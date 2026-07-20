use std::{fmt::Write as _, future::Future, path::Path, str::FromStr, time::Duration};

use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use url::{Host, Url};

use crate::domain::{
    ObservationStatus, ProjectCondition, ProjectId, ProjectResourceTelemetry, ProjectTelemetry,
};
#[cfg(all(unix, test))]
use crate::observer::ProjectResourceSnapshotV1;
#[cfg(unix)]
use crate::observer::{ObserverClientError, ObserverClientV1, ObserverRejectionCodeV1};

const PROJECT_ID: &str = "rimg";
const DISPLAY_NAME: &str = "rimg";
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_STATUS_BODY_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RimgOperationalModeV1 {
    Normal,
    Maintenance,
    Draining,
    Fenced,
}

impl RimgOperationalModeV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Maintenance => "maintenance",
            Self::Draining => "draining",
            Self::Fenced => "fenced",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RimgOperationalHealthV1 {
    mode: RimgOperationalModeV1,
    last_epoch: u64,
    active_epoch: Option<u64>,
    active_token_present: bool,
    intake_open: bool,
    workers_drained: bool,
    active_write_leases: u64,
    processing_jobs: u64,
    delivering_webhooks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RimgWorkerHealthV1 {
    ready: bool,
    last_success_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RimgQueueHealthV1 {
    fast: RimgWorkerHealthV1,
    background: RimgWorkerHealthV1,
    ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RimgWebhookHealthV1 {
    enabled: bool,
    ready: bool,
    last_success_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
struct RimgHealthFlag(bool);

impl RimgHealthFlag {
    const fn is_true(self) -> bool {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RimgHealthStatusV1 {
    schema_version: u16,
    ready: RimgHealthFlag,
    checked_at: i64,
    operational: Option<RimgOperationalHealthV1>,
    queue: RimgQueueHealthV1,
    webhook: RimgWebhookHealthV1,
    database_writable: RimgHealthFlag,
    uploads_writable: RimgHealthFlag,
    masters_writable: RimgHealthFlag,
}

#[derive(Clone, Debug)]
pub struct RimgHealthCollector {
    project_id: ProjectId,
    target: Option<HttpTarget>,
    timeout: Duration,
    last_response_at_ms: Option<i64>,
}

impl RimgHealthCollector {
    pub fn from_optional_base_url(
        base_url: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, RimgConfigError> {
        if timeout.is_zero() {
            return Err(RimgConfigError::ZeroTimeout);
        }
        let project_id = ProjectId::from_str(PROJECT_ID)
            .map_err(|_| RimgConfigError::InvalidInternalProjectId)?;
        let target = base_url.map(HttpTarget::parse).transpose()?;
        Ok(Self {
            project_id,
            target,
            timeout,
            last_response_at_ms: None,
        })
    }

    pub async fn collect(&mut self, now_ms: i64) -> ProjectTelemetry {
        let Some(target) = self.target.as_ref() else {
            return self.telemetry(
                ProjectCondition::Unknown,
                None,
                "Health endpoint не настроен: задайте RDASHBOARD_RIMG_BASE_URL.",
            );
        };

        let (live, ready, status) = tokio::join!(
            target.probe("/health/live", self.timeout),
            target.probe("/health/ready", self.timeout),
            target.probe_status(self.timeout),
        );
        self.apply_outcomes(now_ms, live, ready, status)
    }

    fn apply_outcomes(
        &mut self,
        now_ms: i64,
        live: ProbeOutcome,
        ready: ProbeOutcome,
        status: StatusProbeOutcome,
    ) -> ProjectTelemetry {
        if live.is_ok() || ready.is_ok() || status.is_ok() {
            self.last_response_at_ms = Some(now_ms);
        }
        let (condition, mut detail) = match status {
            Ok(status) => classify_contract_health(live, ready, &status),
            Err(status_failure) => {
                let (condition, mut detail) = classify_legacy_health(live, ready);
                let _ = write!(
                    detail,
                    " status={}; versioned health contract unavailable.",
                    status_failure.label()
                );
                (condition, detail)
            }
        };
        if condition == ProjectCondition::SignalLost {
            detail.push_str(if self.last_response_at_ms.is_some() {
                " Показано время последнего HTTP-ответа."
            } else {
                " Предыдущих HTTP-ответов ещё не было."
            });
        }
        self.telemetry(condition, self.last_response_at_ms, detail)
    }

    fn telemetry(
        &self,
        condition: ProjectCondition,
        observed_at_ms: Option<i64>,
        detail: impl Into<String>,
    ) -> ProjectTelemetry {
        ProjectTelemetry {
            project_id: self.project_id.clone(),
            display_name: DISPLAY_NAME.to_owned(),
            condition,
            observed_at_ms,
            detail: detail.into(),
            resources: unavailable_resources(
                ObservationStatus::Unknown,
                "Resource collector has not run yet.",
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RimgResourceCollector {
    project_id: ProjectId,
    #[cfg(unix)]
    client: Option<ObserverClientV1>,
    last_success: Option<ProjectResourceTelemetry>,
}

impl RimgResourceCollector {
    pub fn from_optional_socket_path(
        socket_path: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, RimgConfigError> {
        if timeout.is_zero() {
            return Err(RimgConfigError::ZeroTimeout);
        }
        if socket_path.is_some_and(|path| !path.is_absolute()) {
            return Err(RimgConfigError::ResourceSocketNotAbsolute);
        }
        #[cfg(unix)]
        let client = socket_path
            .map(|path| ObserverClientV1::new(path, timeout))
            .transpose()
            .map_err(|_| RimgConfigError::InvalidResourceObserverClient)?;
        Ok(Self {
            project_id: ProjectId::from_str(PROJECT_ID)
                .map_err(|_| RimgConfigError::InvalidInternalProjectId)?,
            #[cfg(unix)]
            client,
            last_success: None,
        })
    }

    pub async fn collect(&mut self, _now_ms: i64) -> ProjectResourceTelemetry {
        #[cfg(not(unix))]
        return unavailable_resources(
            ObservationStatus::Unsupported,
            "Resource observer is supported only on Unix.",
        );
        #[cfg(unix)]
        let Some(client) = self.client.as_ref() else {
            return unavailable_resources(
                ObservationStatus::Unknown,
                "Источник ресурсов контейнера не настроен.",
            );
        };

        #[cfg(unix)]
        match client
            .observe_project_resources(self.project_id.clone())
            .await
        {
            Ok(snapshot) => {
                let telemetry = ProjectResourceTelemetry {
                    status: ObservationStatus::Fresh,
                    observed_at_ms: Some(snapshot.observed_at_ms),
                    cpu_percent: Some(snapshot.cpu_percent),
                    memory_used_bytes: Some(snapshot.memory_used_bytes),
                    memory_limit_bytes: Some(snapshot.memory_limit_bytes),
                    network_rx_bytes: Some(snapshot.network_rx_bytes),
                    network_tx_bytes: Some(snapshot.network_tx_bytes),
                    block_read_bytes: Some(snapshot.block_read_bytes),
                    block_write_bytes: Some(snapshot.block_write_bytes),
                    detail: "Текущая статистика контейнера получена.".to_owned(),
                };
                self.last_success = Some(telemetry.clone());
                telemetry
            }
            Err(failure) => self.last_success.clone().map_or_else(
                || {
                    unavailable_resources(
                        ObservationStatus::SignalLost,
                        format!(
                            "Статистика контейнера недоступна: {}.",
                            observer_failure_label(&failure)
                        ),
                    )
                },
                |mut previous| {
                    previous.status = ObservationStatus::Stale;
                    previous.detail = format!(
                        "Показаны последние данные; обновление не удалось: {}.",
                        observer_failure_label(&failure)
                    );
                    previous
                },
            ),
        }
    }
}

fn unavailable_resources(
    status: ObservationStatus,
    detail: impl Into<String>,
) -> ProjectResourceTelemetry {
    ProjectResourceTelemetry {
        status,
        observed_at_ms: None,
        cpu_percent: None,
        memory_used_bytes: None,
        memory_limit_bytes: None,
        network_rx_bytes: None,
        network_tx_bytes: None,
        block_read_bytes: None,
        block_write_bytes: None,
        detail: detail.into(),
    }
}

#[cfg(unix)]
const fn observer_failure_label(error: &ObserverClientError) -> &'static str {
    match error {
        ObserverClientError::DeadlineExceeded => "timeout",
        ObserverClientError::Io(_) => "connect_failed",
        ObserverClientError::Rejected {
            code: ObserverRejectionCodeV1::ProjectNotConfigured,
            ..
        } => "project_not_configured",
        ObserverClientError::Rejected {
            code: ObserverRejectionCodeV1::CollectionUnavailable,
            ..
        } => "collection_unavailable",
        ObserverClientError::Rejected { .. } => "observer_rejected",
        ObserverClientError::InvalidConfig
        | ObserverClientError::Frame(_)
        | ObserverClientError::TrailingResponse
        | ObserverClientError::RequestBinding
        | ObserverClientError::WrongResponse => "unsupported_contract",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpTarget {
    connect_host: String,
    port: u16,
    host_header: String,
}

impl HttpTarget {
    fn parse(value: &str) -> Result<Self, RimgConfigError> {
        let parsed = Url::parse(value).map_err(|_| RimgConfigError::InvalidBaseUrl)?;
        if parsed.scheme() != "http" {
            return Err(RimgConfigError::UnsupportedScheme);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(RimgConfigError::EmbeddedCredentials);
        }
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(RimgConfigError::BaseUrlHasExtraParts);
        }
        let host = parsed.host().ok_or(RimgConfigError::MissingHost)?;
        let connect_host = parsed
            .host_str()
            .ok_or(RimgConfigError::MissingHost)?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or(RimgConfigError::MissingPort)?;
        let host_header = match host {
            Host::Ipv6(address) => format!("[{address}]:{port}"),
            Host::Ipv4(address) => format!("{address}:{port}"),
            Host::Domain(domain) => format!("{domain}:{port}"),
        };
        Ok(Self {
            connect_host,
            port,
            host_header,
        })
    }

    async fn probe(&self, path: &'static str, timeout: Duration) -> ProbeOutcome {
        bounded_probe(timeout, self.probe_without_timeout(path)).await
    }

    async fn probe_without_timeout(&self, path: &'static str) -> ProbeOutcome {
        let mut stream = TcpStream::connect((self.connect_host.as_str(), self.port))
            .await
            .map_err(|_| ProbeFailure::Connect)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: rdashboard/0.1\r\n\r\n",
            self.host_header
        );
        exchange(&mut stream, request.as_bytes()).await
    }

    async fn probe_status(&self, timeout: Duration) -> StatusProbeOutcome {
        bounded_status_probe(timeout, self.probe_status_without_timeout()).await
    }

    async fn probe_status_without_timeout(&self) -> StatusProbeOutcome {
        let mut stream = TcpStream::connect((self.connect_host.as_str(), self.port))
            .await
            .map_err(|_| ProbeFailure::Connect)?;
        let request = format!(
            "GET /health/status HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\nUser-Agent: rdashboard/0.1\r\n\r\n",
            self.host_header
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| ProbeFailure::Write)?;
        let (status, body) = read_json_response(&mut stream).await?;
        if status != 200 {
            return Err(ProbeFailure::UnexpectedStatus);
        }
        let contract: RimgHealthStatusV1 =
            serde_json::from_slice(&body).map_err(|_| ProbeFailure::MalformedJson)?;
        if contract.schema_version != 1 {
            return Err(ProbeFailure::UnsupportedContract);
        }
        Ok(contract)
    }
}

type ProbeOutcome = Result<u16, ProbeFailure>;
type StatusProbeOutcome = Result<RimgHealthStatusV1, ProbeFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeFailure {
    Timeout,
    Connect,
    Write,
    Read,
    ResponseHeadersTooLarge,
    ResponseBodyTooLarge,
    MalformedResponse,
    MalformedJson,
    UnexpectedStatus,
    UnsupportedContract,
}

impl ProbeFailure {
    const fn label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect_failed",
            Self::Write => "request_failed",
            Self::Read => "response_failed",
            Self::ResponseHeadersTooLarge => "headers_too_large",
            Self::ResponseBodyTooLarge => "body_too_large",
            Self::MalformedResponse => "malformed_response",
            Self::MalformedJson => "malformed_json",
            Self::UnexpectedStatus => "unexpected_status",
            Self::UnsupportedContract => "unsupported_contract",
        }
    }
}

async fn bounded_status_probe<F>(timeout: Duration, future: F) -> StatusProbeOutcome
where
    F: Future<Output = StatusProbeOutcome>,
{
    tokio::time::timeout(timeout, future)
        .await
        .unwrap_or(Err(ProbeFailure::Timeout))
}

async fn bounded_probe<F>(timeout: Duration, future: F) -> ProbeOutcome
where
    F: Future<Output = ProbeOutcome>,
{
    tokio::time::timeout(timeout, future)
        .await
        .unwrap_or(Err(ProbeFailure::Timeout))
}

async fn exchange<S>(stream: &mut S, request: &[u8]) -> ProbeOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|_| ProbeFailure::Write)?;
    read_status(stream).await
}

async fn read_status<R>(reader: &mut R) -> ProbeOutcome
where
    R: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        if response.len() >= MAX_RESPONSE_HEADER_BYTES {
            return Err(ProbeFailure::ResponseHeadersTooLarge);
        }
        let remaining = MAX_RESPONSE_HEADER_BYTES - response.len();
        let read_limit = remaining.min(chunk.len());
        let read = reader
            .read(&mut chunk[..read_limit])
            .await
            .map_err(|_| ProbeFailure::Read)?;
        if read == 0 {
            return Err(ProbeFailure::MalformedResponse);
        }
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return parse_status(&response);
        }
    }
}

async fn read_json_response<R>(reader: &mut R) -> Result<(u16, Vec<u8>), ProbeFailure>
where
    R: AsyncRead + Unpin,
{
    let maximum = MAX_RESPONSE_HEADER_BYTES + MAX_STATUS_BODY_BYTES;
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if response.len() >= maximum {
            return Err(ProbeFailure::ResponseBodyTooLarge);
        }
        let remaining = maximum - response.len();
        let read_limit = remaining.min(chunk.len());
        let read = reader
            .read(&mut chunk[..read_limit])
            .await
            .map_err(|_| ProbeFailure::Read)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ProbeFailure::MalformedResponse)?;
    if header_end > MAX_RESPONSE_HEADER_BYTES {
        return Err(ProbeFailure::ResponseHeadersTooLarge);
    }
    let body_start = header_end
        .checked_add(4)
        .ok_or(ProbeFailure::MalformedResponse)?;
    let body = response
        .get(body_start..)
        .ok_or(ProbeFailure::MalformedResponse)?;
    if body.len() > MAX_STATUS_BODY_BYTES {
        return Err(ProbeFailure::ResponseBodyTooLarge);
    }
    Ok((parse_status(&response[..header_end])?, body.to_vec()))
}

fn parse_status(response: &[u8]) -> ProbeOutcome {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(ProbeFailure::MalformedResponse)?;
    let status_line =
        std::str::from_utf8(&response[..line_end]).map_err(|_| ProbeFailure::MalformedResponse)?;
    let mut fields = status_line.split_ascii_whitespace();
    let version = fields.next().ok_or(ProbeFailure::MalformedResponse)?;
    let status = fields.next().ok_or(ProbeFailure::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProbeFailure::MalformedResponse);
    }
    let status = status
        .parse::<u16>()
        .map_err(|_| ProbeFailure::MalformedResponse)?;
    if !(100..=599).contains(&status) {
        return Err(ProbeFailure::MalformedResponse);
    }
    Ok(status)
}

fn classify_contract_health(
    live: ProbeOutcome,
    ready: ProbeOutcome,
    status: &RimgHealthStatusV1,
) -> (ProjectCondition, String) {
    let queue_consistent = status.queue.ready
        == (status.queue.fast.ready && status.queue.background.ready)
        && (!status.queue.fast.ready || status.queue.fast.last_success_at.is_some())
        && (!status.queue.background.ready || status.queue.background.last_success_at.is_some());
    let operational_consistent = status.operational.as_ref().is_some_and(|operational| {
        let normal = operational.mode == RimgOperationalModeV1::Normal;
        let drained = operational.active_write_leases == 0
            && operational.processing_jobs == 0
            && operational.delivering_webhooks == 0;
        normal == operational.intake_open
            && normal == operational.active_epoch.is_none()
            && normal != operational.active_token_present
            && operational.workers_drained == drained
            && (normal || operational.active_epoch == Some(operational.last_epoch))
    });
    let computed_ready = status.operational.as_ref().is_some_and(|operational| {
        operational.mode == RimgOperationalModeV1::Normal && operational.intake_open
    }) && status.queue.ready
        && status.webhook.ready
        && status.database_writable.is_true()
        && status.uploads_writable.is_true()
        && status.masters_writable.is_true();
    let webhook_consistent = if status.webhook.enabled {
        !status.webhook.ready || status.webhook.last_success_at.is_some()
    } else {
        status.webhook.ready && status.webhook.last_success_at.is_none()
    };
    let ready_endpoint_consistent = match ready {
        Ok(204) => status.ready.is_true(),
        Ok(503) | Err(_) => !status.ready.is_true(),
        Ok(_) => false,
    };
    let contract_consistent = queue_consistent
        && operational_consistent
        && webhook_consistent
        && computed_ready == status.ready.is_true()
        && ready_endpoint_consistent;

    let operational_detail = status.operational.as_ref().map_or_else(
        || "operational=missing".to_owned(),
        |operational| {
            format!(
                "mode={}; epoch={}; active_epoch={:?}; token_present={}; intake={}; drained={}; leases={}; processing={}; delivering={}",
                operational.mode.label(),
                operational.last_epoch,
                operational.active_epoch,
                operational.active_token_present,
                operational.intake_open,
                operational.workers_drained,
                operational.active_write_leases,
                operational.processing_jobs,
                operational.delivering_webhooks
            )
        },
    );
    let detail = format!(
        "contract_v1 checked_at={}; live={}; ready={}; {}; queue_ready={} (fast={:?}, background={:?}); webhook_enabled={}; webhook_ready={}; webhook_last={:?}; writable=db:{}/uploads:{}/masters:{}.",
        status.checked_at,
        outcome_label(live),
        outcome_label(ready),
        operational_detail,
        status.queue.ready,
        status.queue.fast.last_success_at,
        status.queue.background.last_success_at,
        status.webhook.enabled,
        status.webhook.ready,
        status.webhook.last_success_at,
        status.database_writable.is_true(),
        status.uploads_writable.is_true(),
        status.masters_writable.is_true()
    );

    if !contract_consistent {
        return (
            ProjectCondition::Down,
            format!("{detail} Versioned health fields contradict each other."),
        );
    }
    if matches!(live, Ok(status) if status != 204) {
        return (
            ProjectCondition::Down,
            format!("{detail} Liveness returned an invalid HTTP status."),
        );
    }
    if live.is_err() {
        return (
            ProjectCondition::Degraded,
            format!("{detail} Status responds, but liveness is not confirmed."),
        );
    }
    match status.operational.as_ref().map(|value| value.mode) {
        Some(
            RimgOperationalModeV1::Maintenance
            | RimgOperationalModeV1::Draining
            | RimgOperationalModeV1::Fenced,
        ) => (ProjectCondition::Maintenance, detail),
        Some(RimgOperationalModeV1::Normal) if status.ready.is_true() => {
            (ProjectCondition::Healthy, detail)
        }
        Some(RimgOperationalModeV1::Normal) | None => (ProjectCondition::Degraded, detail),
    }
}

fn classify_legacy_health(live: ProbeOutcome, ready: ProbeOutcome) -> (ProjectCondition, String) {
    match (live, ready) {
        (Ok(204), Ok(204)) => (
            ProjectCondition::Degraded,
            "live=204; ready=204. Legacy-контракт пока не проверяет запись, webhook-loop и первый успешный цикл workers."
                .to_owned(),
        ),
        (Ok(204), _) => (
            ProjectCondition::Degraded,
            format!(
                "live=204; ready={}. Процесс отвечает, но readiness не подтверждён.",
                outcome_label(ready)
            ),
        ),
        (Err(_), Ok(204)) => (
            ProjectCondition::Degraded,
            format!(
                "live={}; ready=204. Health-сигналы противоречат друг другу.",
                outcome_label(live)
            ),
        ),
        (Err(_), Err(_)) => (
            ProjectCondition::SignalLost,
            format!(
                "live={}; ready={}. Нет HTTP-сигнала.",
                outcome_label(live),
                outcome_label(ready)
            ),
        ),
        _ => (
            ProjectCondition::Down,
            format!(
                "live={}; ready={}. rimg объявляет себя неработоспособным.",
                outcome_label(live),
                outcome_label(ready)
            ),
        ),
    }
}

fn outcome_label(outcome: ProbeOutcome) -> String {
    match outcome {
        Ok(status) => status.to_string(),
        Err(failure) => failure.label().to_owned(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RimgConfigError {
    #[error("must be an absolute HTTP base URL")]
    InvalidBaseUrl,
    #[error("only plaintext HTTP is supported for the local internal health endpoint")]
    UnsupportedScheme,
    #[error("embedded URL credentials are forbidden")]
    EmbeddedCredentials,
    #[error("base URL must not contain a path, query, or fragment")]
    BaseUrlHasExtraParts,
    #[error("base URL must contain a host")]
    MissingHost,
    #[error("base URL must contain a known or explicit port")]
    MissingPort,
    #[error("health timeout must be greater than zero")]
    ZeroTimeout,
    #[error("resource socket path must be absolute")]
    ResourceSocketNotAbsolute,
    #[error("resource observer client configuration is invalid")]
    InvalidResourceObserverClient,
    #[error("internal rimg project identifier is invalid")]
    InvalidInternalProjectId,
}

#[cfg(test)]
mod tests {
    use std::{future, time::Duration};

    use super::*;

    fn healthy_status() -> RimgHealthStatusV1 {
        RimgHealthStatusV1 {
            schema_version: 1,
            ready: RimgHealthFlag(true),
            checked_at: 100,
            operational: Some(RimgOperationalHealthV1 {
                mode: RimgOperationalModeV1::Normal,
                last_epoch: 0,
                active_epoch: None,
                active_token_present: false,
                intake_open: true,
                workers_drained: true,
                active_write_leases: 0,
                processing_jobs: 0,
                delivering_webhooks: 0,
            }),
            queue: RimgQueueHealthV1 {
                fast: RimgWorkerHealthV1 {
                    ready: true,
                    last_success_at: Some(99),
                },
                background: RimgWorkerHealthV1 {
                    ready: true,
                    last_success_at: Some(98),
                },
                ready: true,
            },
            webhook: RimgWebhookHealthV1 {
                enabled: false,
                ready: true,
                last_success_at: None,
            },
            database_writable: RimgHealthFlag(true),
            uploads_writable: RimgHealthFlag(true),
            masters_writable: RimgHealthFlag(true),
        }
    }

    #[test]
    fn base_url_rejects_ambiguous_or_sensitive_forms() {
        assert!(HttpTarget::parse("http://127.0.0.1:8080").is_ok());
        assert!(HttpTarget::parse("http://[::1]:8080/").is_ok());
        assert_eq!(
            HttpTarget::parse("https://127.0.0.1:8080"),
            Err(RimgConfigError::UnsupportedScheme)
        );
        assert_eq!(
            HttpTarget::parse("http://user:secret@127.0.0.1:8080"),
            Err(RimgConfigError::EmbeddedCredentials)
        );
        assert_eq!(
            HttpTarget::parse("http://127.0.0.1:8080/api"),
            Err(RimgConfigError::BaseUrlHasExtraParts)
        );
        assert_eq!(
            HttpTarget::parse("http://127.0.0.1:8080/?token=secret"),
            Err(RimgConfigError::BaseUrlHasExtraParts)
        );
    }

    #[tokio::test]
    async fn bounded_probe_turns_elapsed_deadline_into_typed_failure() {
        let outcome = bounded_probe(Duration::from_millis(1), future::pending()).await;
        assert_eq!(outcome, Err(ProbeFailure::Timeout));
    }

    #[tokio::test]
    async fn unconfigured_collector_reports_unknown_without_inventing_an_observation() {
        let mut collector =
            RimgHealthCollector::from_optional_base_url(None, Duration::from_secs(2))
                .unwrap_or_else(|error| panic!("collector fixture: {error}"));

        let telemetry = collector.collect(100).await;
        assert_eq!(telemetry.condition, ProjectCondition::Unknown);
        assert_eq!(telemetry.observed_at_ms, None);
        assert!(telemetry.detail.contains("RDASHBOARD_RIMG_BASE_URL"));
    }

    #[test]
    fn resource_collector_rejects_relative_socket_paths() {
        assert!(matches!(
            RimgResourceCollector::from_optional_socket_path(
                Some(Path::new("relative.sock")),
                Duration::from_secs(2),
            ),
            Err(RimgConfigError::ResourceSocketNotAbsolute)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resource_collector_keeps_last_success_as_stale_after_signal_loss() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let socket_path = directory.path().join("resources.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .unwrap_or_else(|error| panic!("bind resource fixture: {error}"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept resource fixture: {error}"));
            let request: crate::observer::ObserverRequestV1 =
                crate::protocol::read_frame(&mut stream, crate::protocol::NORMAL_FRAME_MAX_BYTES)
                    .await
                    .unwrap_or_else(|error| panic!("read resource fixture: {error}"));
            let crate::observer::ObserverQueryV1::ProjectResources { project_id } = request.query;
            assert_eq!(project_id.as_str(), PROJECT_ID);
            let response = crate::observer::ObserverResponseV1::ProjectResources {
                schema_version: crate::observer::OBSERVER_PROTOCOL_VERSION,
                request_id: request.request_id,
                project_id,
                snapshot: ProjectResourceSnapshotV1 {
                    schema_version: crate::observer::PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION,
                    observed_at_ms: 100,
                    cpu_percent: 1.5,
                    memory_used_bytes: 20,
                    memory_limit_bytes: 100,
                    network_rx_bytes: 1_000,
                    network_tx_bytes: 2_000,
                    block_read_bytes: 3_000,
                    block_write_bytes: 4_000,
                },
            };
            crate::protocol::write_frame(
                &mut stream,
                &response,
                crate::protocol::NORMAL_FRAME_MAX_BYTES,
            )
            .await
            .unwrap_or_else(|error| panic!("write resource fixture: {error}"));
            stream
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("close resource fixture: {error}"));
        });
        let mut collector = RimgResourceCollector::from_optional_socket_path(
            Some(&socket_path),
            Duration::from_secs(2),
        )
        .unwrap_or_else(|error| panic!("resource collector: {error}"));

        let fresh = collector.collect(100).await;
        assert_eq!(fresh.status, ObservationStatus::Fresh);
        assert_eq!(fresh.observed_at_ms, Some(100));
        assert_eq!(fresh.memory_used_bytes, Some(20));
        server
            .await
            .unwrap_or_else(|error| panic!("resource fixture task: {error}"));
        std::fs::remove_file(&socket_path)
            .unwrap_or_else(|error| panic!("remove resource fixture: {error}"));

        let stale = collector.collect(200).await;
        assert_eq!(stale.status, ObservationStatus::Stale);
        assert_eq!(stale.observed_at_ms, Some(100));
        assert_eq!(stale.network_tx_bytes, Some(2_000));
    }

    #[tokio::test]
    async fn response_reader_accepts_valid_http_and_rejects_bad_or_unbounded_headers() {
        let mut valid = &b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"[..];
        assert_eq!(read_status(&mut valid).await, Ok(204));

        let mut malformed = &b"NOT-HTTP 204\r\n\r\n"[..];
        assert_eq!(
            read_status(&mut malformed).await,
            Err(ProbeFailure::MalformedResponse)
        );

        let oversized = vec![b'x'; MAX_RESPONSE_HEADER_BYTES];
        let mut oversized = oversized.as_slice();
        assert_eq!(
            read_status(&mut oversized).await,
            Err(ProbeFailure::ResponseHeadersTooLarge)
        );
    }

    #[tokio::test]
    async fn versioned_status_reader_is_bounded_and_requires_exact_json() {
        let body = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "ready": true,
            "checked_at": 100,
            "operational": {
                "mode": "normal",
                "last_epoch": 0,
                "active_epoch": null,
                "active_token_present": false,
                "intake_open": true,
                "workers_drained": true,
                "active_write_leases": 0,
                "processing_jobs": 0,
                "delivering_webhooks": 0
            },
            "queue": {
                "fast": {"ready": true, "last_success_at": 99},
                "background": {"ready": true, "last_success_at": 98},
                "ready": true
            },
            "webhook": {"enabled": false, "ready": true, "last_success_at": null},
            "database_writable": true,
            "uploads_writable": true,
            "masters_writable": true
        }))
        .unwrap_or_else(|error| panic!("serialize status fixture: {error}"));
        let response = [
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
            body.as_slice(),
        ]
        .concat();
        let mut response = response.as_slice();
        let (status, parsed_body) = read_json_response(&mut response)
            .await
            .unwrap_or_else(|error| panic!("read status fixture: {error:?}"));
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_slice::<RimgHealthStatusV1>(&parsed_body)
                .unwrap_or_else(|error| panic!("parse status fixture: {error}")),
            healthy_status()
        );

        let oversized = vec![b'x'; MAX_RESPONSE_HEADER_BYTES + MAX_STATUS_BODY_BYTES + 1];
        let mut oversized = oversized.as_slice();
        assert_eq!(
            read_json_response(&mut oversized).await,
            Err(ProbeFailure::ResponseBodyTooLarge)
        );
    }

    #[test]
    fn versioned_contract_claims_healthy_only_when_all_evidence_agrees() {
        let status = healthy_status();
        let (condition, _) = classify_contract_health(Ok(204), Ok(204), &status);
        assert_eq!(condition, ProjectCondition::Healthy);

        let mut failed_worker = status.clone();
        failed_worker.ready = RimgHealthFlag(false);
        failed_worker.queue.ready = false;
        failed_worker.queue.fast.ready = false;
        let (condition, detail) = classify_contract_health(Ok(204), Ok(503), &failed_worker);
        assert_eq!(condition, ProjectCondition::Degraded);
        assert!(detail.contains("fast=Some(99)"));

        let mut maintenance = status.clone();
        maintenance.ready = RimgHealthFlag(false);
        maintenance.operational = Some(RimgOperationalHealthV1 {
            mode: RimgOperationalModeV1::Fenced,
            last_epoch: 7,
            active_epoch: Some(7),
            active_token_present: true,
            intake_open: false,
            workers_drained: true,
            active_write_leases: 0,
            processing_jobs: 0,
            delivering_webhooks: 0,
        });
        let (condition, _) = classify_contract_health(Ok(204), Ok(503), &maintenance);
        assert_eq!(condition, ProjectCondition::Maintenance);

        let mut contradictory = status;
        contradictory.database_writable = RimgHealthFlag(false);
        let (condition, detail) = classify_contract_health(Ok(204), Ok(204), &contradictory);
        assert_eq!(condition, ProjectCondition::Down);
        assert!(detail.contains("contradict"));

        let status = healthy_status();
        let (condition, _) = classify_contract_health(Ok(500), Ok(204), &status);
        assert_eq!(condition, ProjectCondition::Down);

        let mut impossible_webhook = status;
        impossible_webhook.webhook.enabled = true;
        let (condition, _) = classify_contract_health(Ok(204), Ok(204), &impossible_webhook);
        assert_eq!(condition, ProjectCondition::Down);
    }

    #[tokio::test]
    async fn exchange_handles_a_fragmented_header_without_waiting_for_a_body() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 16];
            let read = server
                .read(&mut request)
                .await
                .unwrap_or_else(|error| panic!("read request fixture: {error}"));
            assert_eq!(&request[..read], b"probe");
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n")
                .await
                .unwrap_or_else(|error| panic!("write first response fragment: {error}"));
            tokio::task::yield_now().await;
            server
                .write_all(b"\r\n")
                .await
                .unwrap_or_else(|error| panic!("write final response fragment: {error}"));
        });

        assert_eq!(exchange(&mut client, b"probe").await, Ok(204));
        server_task
            .await
            .unwrap_or_else(|error| panic!("server fixture task: {error}"));
    }

    #[test]
    fn legacy_contract_never_claims_healthy_and_distinguishes_signal_loss() {
        let (condition, detail) = classify_legacy_health(Ok(204), Ok(204));
        assert_eq!(condition, ProjectCondition::Degraded);
        assert!(detail.contains("Legacy-контракт"));

        let (condition, _) = classify_legacy_health(Ok(204), Err(ProbeFailure::Timeout));
        assert_eq!(condition, ProjectCondition::Degraded);

        let (condition, _) =
            classify_legacy_health(Err(ProbeFailure::Connect), Err(ProbeFailure::Timeout));
        assert_eq!(condition, ProjectCondition::SignalLost);

        let (condition, _) = classify_legacy_health(Ok(500), Ok(503));
        assert_eq!(condition, ProjectCondition::Down);

        let (condition, _) = classify_legacy_health(Ok(503), Ok(204));
        assert_eq!(condition, ProjectCondition::Down);

        let (condition, _) = classify_legacy_health(Ok(200), Ok(204));
        assert_eq!(condition, ProjectCondition::Down);

        let (condition, detail) = classify_legacy_health(Err(ProbeFailure::Connect), Ok(204));
        assert_eq!(condition, ProjectCondition::Degraded);
        assert!(detail.contains("противоречат"));
    }

    #[test]
    fn signal_loss_preserves_last_real_http_observation_time() {
        let mut collector = RimgHealthCollector::from_optional_base_url(
            Some("http://127.0.0.1:8080"),
            Duration::from_secs(2),
        )
        .unwrap_or_else(|error| panic!("collector fixture: {error}"));
        let initial_loss = collector.apply_outcomes(
            50,
            Err(ProbeFailure::Connect),
            Err(ProbeFailure::Timeout),
            Err(ProbeFailure::Timeout),
        );
        assert_eq!(initial_loss.observed_at_ms, None);
        assert!(initial_loss.detail.contains("ещё не было"));

        let observed = collector.apply_outcomes(
            100,
            Ok(204),
            Ok(204),
            Err(ProbeFailure::UnsupportedContract),
        );
        assert_eq!(observed.observed_at_ms, Some(100));

        let lost = collector.apply_outcomes(
            200,
            Err(ProbeFailure::Connect),
            Err(ProbeFailure::Timeout),
            Err(ProbeFailure::Connect),
        );
        assert_eq!(lost.condition, ProjectCondition::SignalLost);
        assert_eq!(lost.observed_at_ms, Some(100));
        assert!(lost.detail.contains("Показано время"));
    }
}
