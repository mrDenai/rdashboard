use std::{path::Path, time::Duration};

use futures_util::StreamExt as _;
use reqwest::{
    StatusCode, Url,
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER},
};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    notifications::{NotificationEventV1, TelegramGatewayMessageV1},
    store::{NotificationClaimV1, NotificationStore, NotificationStoreError},
    unix_time_ms,
};

pub const TELEGRAM_GATEWAY_ORIGIN: &str = "https://tg.4u.ge";
pub const TELEGRAM_GATEWAY_CREDENTIAL: &str = "telegram-gateway-secret";
const MAX_GATEWAY_BODY_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 4 * 1024;
const CLAIM_LEASE: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct TelegramGatewayClient {
    client: reqwest::Client,
    origin: Url,
    authorization: HeaderValue,
    gateway_project_id: String,
    chat_id: i64,
    message_thread_id: i32,
}

impl std::fmt::Debug for TelegramGatewayClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelegramGatewayClient")
            .field("origin", &self.origin)
            .field("gateway_project_id", &self.gateway_project_id)
            .field("chat_id", &self.chat_id)
            .field("message_thread_id", &self.message_thread_id)
            .finish_non_exhaustive()
    }
}

impl TelegramGatewayClient {
    pub fn from_systemd_credentials(
        credential_directory: &Path,
        gateway_project_id: impl Into<String>,
        chat_id: i64,
        message_thread_id: i32,
        timeout: Duration,
    ) -> Result<Self, TelegramGatewayConfigError> {
        let secret = read_required_credential(credential_directory, TELEGRAM_GATEWAY_CREDENTIAL)?;
        Self::new(
            TELEGRAM_GATEWAY_ORIGIN,
            true,
            gateway_project_id,
            chat_id,
            message_thread_id,
            secret.as_str(),
            timeout,
        )
    }

    fn new(
        origin: &str,
        https_only: bool,
        gateway_project_id: impl Into<String>,
        chat_id: i64,
        message_thread_id: i32,
        secret: &str,
        timeout: Duration,
    ) -> Result<Self, TelegramGatewayConfigError> {
        if timeout.is_zero() || timeout > Duration::from_secs(20) {
            return Err(TelegramGatewayConfigError::InvalidTimeout);
        }
        let origin = Url::parse(origin).map_err(|_| TelegramGatewayConfigError::InvalidOrigin)?;
        let allowed_scheme = origin.scheme() == "https"
            || (!https_only
                && origin.scheme() == "http"
                && origin
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1")));
        if !allowed_scheme
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(TelegramGatewayConfigError::InvalidOrigin);
        }
        let gateway_project_id = gateway_project_id.into();
        let probe_event = NotificationEventV1::new(
            "rimg"
                .parse()
                .map_err(|_| TelegramGatewayConfigError::InvalidRoute)?,
            crate::notifications::NotificationKindV1::ControllerFailed,
            "rdashboard.rimg.config_probe",
            "config-probe",
            "rimg: notification configuration probe",
            0,
        )
        .map_err(|_| TelegramGatewayConfigError::InvalidRoute)?;
        TelegramGatewayMessageV1::from_event(
            &probe_event,
            gateway_project_id.clone(),
            chat_id,
            message_thread_id,
        )
        .map_err(|_| TelegramGatewayConfigError::InvalidRoute)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {secret}"))
            .map_err(|_| TelegramGatewayConfigError::InvalidAuthorizationCredential)?;
        authorization.set_sensitive(true);
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(timeout)
            .user_agent("rdashboard-notify/1")
            .build()
            .map_err(|_| TelegramGatewayConfigError::HttpClient)?;
        Ok(Self {
            client,
            origin,
            authorization,
            gateway_project_id,
            chat_id,
            message_thread_id,
        })
    }

    pub async fn submit(&self, event: &NotificationEventV1) -> Result<Uuid, GatewayRequestError> {
        let body = TelegramGatewayMessageV1::from_event(
            event,
            self.gateway_project_id.clone(),
            self.chat_id,
            self.message_thread_id,
        )
        .map_err(|_| GatewayRequestError::permanent("gateway_request_invalid"))?;
        let endpoint = self
            .origin
            .join("api/v1/messages")
            .map_err(|_| GatewayRequestError::permanent("gateway_endpoint_invalid"))?;
        let body = serde_json::to_vec(&body)
            .map_err(|_| GatewayRequestError::permanent("gateway_request_invalid"))?;
        let response = self
            .client
            .post(endpoint)
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| GatewayRequestError::unknown("gateway_submit_transport"))?;
        let status = response.status();
        let retry_after = retry_after(&response);
        let bytes = bounded_response_body(response)
            .await
            .map_err(|()| GatewayRequestError::for_submit_status(status))?;
        if !status.is_success() {
            return Err(GatewayRequestError::from_http_status(status, retry_after));
        }
        let accepted: GatewaySendResponse = serde_json::from_slice(&bytes)
            .map_err(|_| GatewayRequestError::unknown("gateway_submit_response_invalid"))?;
        if accepted.status != GatewayMessageState::Pending {
            return Err(GatewayRequestError::unknown(
                "gateway_submit_status_invalid",
            ));
        }
        Ok(accepted.message_id)
    }

    pub async fn status(&self, message_id: Uuid) -> Result<GatewayStatus, GatewayRequestError> {
        let mut endpoint = self
            .origin
            .join(&format!("api/v1/messages/{message_id}"))
            .map_err(|_| GatewayRequestError::permanent("gateway_endpoint_invalid"))?;
        endpoint
            .query_pairs_mut()
            .append_pair("project_id", &self.gateway_project_id);
        let response = self
            .client
            .get(endpoint)
            .header(AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| GatewayRequestError::retryable("gateway_status_transport", None))?;
        let status = response.status();
        let retry_after = retry_after(&response);
        let bytes = bounded_response_body(response)
            .await
            .map_err(|()| GatewayRequestError::retryable("gateway_status_body_invalid", None))?;
        if !status.is_success() {
            return Err(GatewayRequestError::from_http_status(status, retry_after));
        }
        let provider: GatewayStatusResponse = serde_json::from_slice(&bytes)
            .map_err(|_| GatewayRequestError::retryable("gateway_status_response_invalid", None))?;
        if provider.message_id != message_id
            || provider.retry_count < 0
            || provider.retry_count > 100
            || (provider.status == GatewayMessageState::Sent
                && provider.tg_message_id.is_none_or(|value| value <= 0))
        {
            return Err(GatewayRequestError::retryable(
                "gateway_status_response_invalid",
                None,
            ));
        }
        match provider.status {
            GatewayMessageState::Pending | GatewayMessageState::Sending => {
                Ok(GatewayStatus::Pending)
            }
            GatewayMessageState::Sent => Ok(GatewayStatus::Sent),
            GatewayMessageState::Failed => Ok(GatewayStatus::PermanentFailure("gateway_failed")),
            GatewayMessageState::PermanentFailure => {
                Ok(GatewayStatus::PermanentFailure("gateway_permanent_failure"))
            }
            GatewayMessageState::Deleted => {
                Ok(GatewayStatus::PermanentFailure("gateway_message_deleted"))
            }
            GatewayMessageState::Dropped => {
                Ok(GatewayStatus::PermanentFailure("gateway_message_dropped"))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct NotificationDeliveryWorker {
    store: NotificationStore,
    gateway: TelegramGatewayClient,
}

impl NotificationDeliveryWorker {
    pub const fn new(store: NotificationStore, gateway: TelegramGatewayClient) -> Self {
        Self { store, gateway }
    }

    pub async fn process_once(&self) -> Result<bool, NotificationDeliveryError> {
        let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
        let store = self.store.clone();
        let claim = tokio::task::spawn_blocking(move || store.claim_next(now_ms, CLAIM_LEASE))
            .await
            .map_err(NotificationDeliveryError::StoreTask)??;
        let Some(claim) = claim else {
            return Ok(false);
        };
        if let Some(message_id) = claim.provider_message_id {
            self.poll_claim(claim, message_id).await?;
        } else {
            self.submit_claim(claim).await?;
        }
        Ok(true)
    }

    async fn submit_claim(
        &self,
        claim: NotificationClaimV1,
    ) -> Result<(), NotificationDeliveryError> {
        match self.gateway.submit(&claim.event).await {
            Ok(message_id) => {
                let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
                let store = self.store.clone();
                tokio::task::spawn_blocking(move || {
                    store.mark_gateway_accepted(&claim, message_id, now_ms, POLL_INTERVAL)
                })
                .await
                .map_err(NotificationDeliveryError::StoreTask)??;
            }
            Err(error) => self.complete_error(claim, error).await?,
        }
        Ok(())
    }

    async fn poll_claim(
        &self,
        claim: NotificationClaimV1,
        message_id: Uuid,
    ) -> Result<(), NotificationDeliveryError> {
        match self.gateway.status(message_id).await {
            Ok(GatewayStatus::Pending) => {
                let delay = retry_delay(claim.attempt_number);
                self.complete_retry(claim, "gateway_pending", delay).await?;
            }
            Ok(GatewayStatus::Sent) => {
                let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
                let store = self.store.clone();
                tokio::task::spawn_blocking(move || store.mark_delivered(&claim, now_ms))
                    .await
                    .map_err(NotificationDeliveryError::StoreTask)??;
            }
            Ok(GatewayStatus::PermanentFailure(code)) => {
                self.complete_permanent(&claim, code).await?;
            }
            Err(error) => self.complete_error(claim, error).await?,
        }
        Ok(())
    }

    async fn complete_error(
        &self,
        claim: NotificationClaimV1,
        error: GatewayRequestError,
    ) -> Result<(), NotificationDeliveryError> {
        match error.disposition {
            GatewayErrorDisposition::Unknown => {
                let delay = error
                    .retry_after
                    .unwrap_or_else(|| retry_delay(claim.attempt_number));
                let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
                let store = self.store.clone();
                let code = error.code;
                tokio::task::spawn_blocking(move || {
                    store.mark_delivery_unknown(&claim, code, now_ms, delay)
                })
                .await
                .map_err(NotificationDeliveryError::StoreTask)??;
            }
            GatewayErrorDisposition::Retryable => {
                let delay = error
                    .retry_after
                    .unwrap_or_else(|| retry_delay(claim.attempt_number));
                self.complete_retry(claim, error.code, delay).await?;
            }
            GatewayErrorDisposition::Permanent => {
                self.complete_permanent(&claim, error.code).await?;
            }
        }
        Ok(())
    }

    async fn complete_retry(
        &self,
        claim: NotificationClaimV1,
        code: &'static str,
        delay: Duration,
    ) -> Result<(), NotificationDeliveryError> {
        let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            store.mark_retry_scheduled(&claim, code, now_ms, delay)
        })
        .await
        .map_err(NotificationDeliveryError::StoreTask)??;
        Ok(())
    }

    async fn complete_permanent(
        &self,
        claim: &NotificationClaimV1,
        code: &'static str,
    ) -> Result<(), NotificationDeliveryError> {
        let now_ms = unix_time_ms().map_err(NotificationDeliveryError::Clock)?;
        let store = self.store.clone();
        let claim = claim.clone();
        tokio::task::spawn_blocking(move || store.mark_permanent_failure(&claim, code, now_ms))
            .await
            .map_err(NotificationDeliveryError::StoreTask)??;
        Ok(())
    }
}

fn retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(8);
    Duration::from_secs(2_u64.saturating_pow(exponent).min(300))
}

async fn bounded_response_body(response: reqwest::Response) -> Result<Vec<u8>, ()> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_GATEWAY_BODY_BYTES)
    {
        return Err(());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if body.len().saturating_add(chunk.len()) > MAX_GATEWAY_BODY_BYTES {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=3_600).contains(seconds))
        .map(Duration::from_secs)
}

fn read_required_credential(
    directory: &Path,
    name: &'static str,
) -> Result<Zeroizing<String>, TelegramGatewayConfigError> {
    if !directory.is_absolute()
        || directory.components().collect::<std::path::PathBuf>() != directory
    {
        return Err(TelegramGatewayConfigError::InvalidCredentialDirectory);
    }
    let path = directory.join(name);
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| TelegramGatewayConfigError::CredentialRead(name, error))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(TelegramGatewayConfigError::InvalidCredential(name));
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| TelegramGatewayConfigError::CredentialRead(name, error))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| TelegramGatewayConfigError::InvalidCredential(name))?
        .trim_end_matches(['\r', '\n']);
    if value.is_empty()
        || value != value.trim()
        || value.chars().any(char::is_control)
        || value.len() > usize::try_from(MAX_CREDENTIAL_BYTES).unwrap_or(usize::MAX)
    {
        return Err(TelegramGatewayConfigError::InvalidCredential(name));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayStatus {
    Pending,
    Sent,
    PermanentFailure(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayErrorDisposition {
    Unknown,
    Retryable,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayRequestError {
    code: &'static str,
    disposition: GatewayErrorDisposition,
    retry_after: Option<Duration>,
}

impl GatewayRequestError {
    const fn unknown(code: &'static str) -> Self {
        Self {
            code,
            disposition: GatewayErrorDisposition::Unknown,
            retry_after: None,
        }
    }

    const fn retryable(code: &'static str, retry_after: Option<Duration>) -> Self {
        Self {
            code,
            disposition: GatewayErrorDisposition::Retryable,
            retry_after,
        }
    }

    const fn permanent(code: &'static str) -> Self {
        Self {
            code,
            disposition: GatewayErrorDisposition::Permanent,
            retry_after: None,
        }
    }

    fn for_submit_status(status: StatusCode) -> Self {
        if status.is_success() {
            Self::unknown("gateway_submit_body_invalid")
        } else {
            Self::from_http_status(status, None)
        }
    }

    fn from_http_status(status: StatusCode, retry_after: Option<Duration>) -> Self {
        match status {
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
                Self::retryable("gateway_retryable_response", retry_after)
            }
            status if status.is_server_error() => {
                Self::retryable("gateway_server_error", retry_after)
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Self::permanent("gateway_authorization_rejected")
            }
            StatusCode::NOT_FOUND => Self::permanent("gateway_route_not_found"),
            status if status.is_redirection() => Self::permanent("gateway_redirect_rejected"),
            _ => Self::permanent("gateway_request_rejected"),
        }
    }
}

impl std::fmt::Display for GatewayRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for GatewayRequestError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewaySendResponse {
    message_id: Uuid,
    status: GatewayMessageState,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayStatusResponse {
    message_id: Uuid,
    tg_message_id: Option<i64>,
    status: GatewayMessageState,
    #[serde(rename = "error_code")]
    _error_code: Option<i64>,
    #[serde(rename = "error_text")]
    _error_text: Option<String>,
    retry_count: i64,
    #[serde(rename = "created_at")]
    _created_at: String,
    #[serde(rename = "scheduled_at")]
    _scheduled_at: Option<String>,
    #[serde(rename = "sent_at")]
    _sent_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum GatewayMessageState {
    Pending,
    Sending,
    Sent,
    Failed,
    PermanentFailure,
    Deleted,
    Dropped,
}

#[derive(Debug, thiserror::Error)]
pub enum TelegramGatewayConfigError {
    #[error("Telegram gateway request timeout is invalid")]
    InvalidTimeout,
    #[error("Telegram gateway origin is invalid")]
    InvalidOrigin,
    #[error("Telegram gateway project/chat route is invalid")]
    InvalidRoute,
    #[error("Telegram gateway credential directory is invalid")]
    InvalidCredentialDirectory,
    #[error("Telegram gateway credential {0} could not be read: {1}")]
    CredentialRead(&'static str, std::io::Error),
    #[error("Telegram gateway credential {0} is invalid")]
    InvalidCredential(&'static str),
    #[error("Telegram gateway authorization credential is invalid")]
    InvalidAuthorizationCredential,
    #[error("Telegram gateway HTTP client could not be created")]
    HttpClient,
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationDeliveryError {
    #[error("notification store failed: {0}")]
    Store(#[from] NotificationStoreError),
    #[error("notification store task failed: {0}")]
    StoreTask(tokio::task::JoinError),
    #[error("notification host clock is invalid: {0}")]
    Clock(std::time::SystemTimeError),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        extract::{Path as AxumPath, State},
        http::StatusCode,
        routing::{get, post},
    };
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{
        domain::ProjectId,
        notifications::{NotificationDeliveryStateV1, NotificationKindV1},
    };

    #[derive(Clone)]
    struct FakeGateway {
        message_id: Uuid,
        statuses: Arc<Mutex<Vec<&'static str>>>,
    }

    async fn send(State(state): State<FakeGateway>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "message_id": state.message_id,
            "status": "pending"
        }))
    }

    async fn status(
        State(state): State<FakeGateway>,
        AxumPath(message_id): AxumPath<Uuid>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        if message_id != state.message_id {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            );
        }
        let status = state.statuses.lock().expect("statuses").remove(0);
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "message_id": state.message_id,
                "tg_message_id": if status == "sent" { Some(42) } else { None },
                "status": status,
                "error_code": null,
                "error_text": null,
                "retry_count": 0,
                "created_at": "2026-07-19T00:00:00Z",
                "scheduled_at": null,
                "sent_at": if status == "sent" {
                    Some("2026-07-19T00:00:01Z")
                } else {
                    None
                }
            })),
        )
    }

    async fn fake_gateway(statuses: Vec<&'static str>) -> (Url, Uuid) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let message_id = Uuid::new_v4();
        let state = FakeGateway {
            message_id,
            statuses: Arc::new(Mutex::new(statuses)),
        };
        let app = Router::new()
            .route("/api/v1/messages", post(send))
            .route("/api/v1/messages/{message_id}", get(status))
            .with_state(state);
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fake gateway");
        });
        (
            Url::parse(&format!("http://{address}/")).expect("origin"),
            message_id,
        )
    }

    fn event_with_occurrence(occurrence: &str) -> NotificationEventV1 {
        NotificationEventV1::new(
            "rimg".parse::<ProjectId>().expect("project"),
            NotificationKindV1::ErrorPriorityChanged,
            "rdashboard.rimg.errors",
            occurrence,
            "rimg: error priority is high",
            0,
        )
        .expect("event")
    }

    fn event() -> NotificationEventV1 {
        event_with_occurrence("priority:high:1")
    }

    #[tokio::test]
    async fn worker_persists_async_gateway_acceptance_then_terminal_delivery() {
        let (origin, expected_message_id) = fake_gateway(vec!["sent"]).await;
        let client = TelegramGatewayClient::new(
            origin.as_str(),
            false,
            "rdashboard",
            -100,
            0,
            "test-secret",
            Duration::from_secs(2),
        )
        .expect("client");
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        store.enqueue(&event(), 0).expect("enqueue");
        let worker = NotificationDeliveryWorker::new(store.clone(), client);
        assert!(worker.process_once().await.expect("submit"));
        let after_submit = store
            .project_records(&"rimg".parse().expect("project"), 10)
            .expect("records")
            .remove(0);
        assert_eq!(after_submit.provider_message_id, Some(expected_message_id));
        assert_eq!(
            after_submit.state,
            NotificationDeliveryStateV1::RetryScheduled
        );

        tokio::time::sleep(POLL_INTERVAL).await;
        assert!(worker.process_once().await.expect("poll"));
        let delivered = store
            .project_records(&"rimg".parse().expect("project"), 10)
            .expect("records")
            .remove(0);
        assert_eq!(delivered.state, NotificationDeliveryStateV1::Delivered);
    }

    #[tokio::test]
    async fn malformed_success_is_delivery_unknown_not_known_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let app = Router::new().route(
            "/api/v1/messages",
            post(|| async { (StatusCode::OK, "not-json") }),
        );
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fake gateway");
        });
        let client = TelegramGatewayClient::new(
            &format!("http://{address}/"),
            false,
            "rdashboard",
            -100,
            0,
            "test-secret",
            Duration::from_secs(2),
        )
        .expect("client");
        let error = client.submit(&event()).await.expect_err("invalid response");
        assert_eq!(error.disposition, GatewayErrorDisposition::Unknown);
    }

    #[tokio::test]
    async fn accepted_submit_with_failed_local_binding_reclaims_as_possible_duplicate() {
        let (origin, provider_message_id) = fake_gateway(Vec::new()).await;
        let client = TelegramGatewayClient::new(
            origin.as_str(),
            false,
            "rdashboard",
            -100,
            0,
            "test-secret",
            Duration::from_secs(2),
        )
        .expect("client");
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        let now_ms = unix_time_ms().expect("clock");

        store
            .enqueue(&event_with_occurrence("priority:high:existing"), now_ms)
            .expect("existing enqueue");
        let existing = store
            .claim_next(now_ms, CLAIM_LEASE)
            .expect("existing claim")
            .expect("existing event");
        store
            .mark_gateway_accepted(
                &existing,
                provider_message_id,
                now_ms,
                Duration::from_mins(5),
            )
            .expect("existing provider binding");
        store
            .enqueue(&event_with_occurrence("priority:high:new"), now_ms)
            .expect("new enqueue");

        let worker = NotificationDeliveryWorker::new(store.clone(), client);
        assert!(matches!(
            worker.process_once().await,
            Err(NotificationDeliveryError::Store(
                NotificationStoreError::Sqlite(_)
            ))
        ));
        let after_expiry = unix_time_ms()
            .expect("clock")
            .checked_add(i64::try_from(CLAIM_LEASE.as_millis()).expect("lease milliseconds") + 1)
            .expect("future time");
        let recovered = store
            .claim_next(after_expiry, CLAIM_LEASE)
            .expect("reclaim")
            .expect("recovered event");
        assert!(recovered.possible_duplicate);
        assert!(recovered.provider_message_id.is_none());
    }
}
