use std::time::Duration;

use reqwest::{Client, StatusCode, redirect::Policy};
use url::Url;

use crate::domain::{
    ObservationStatus, ProjectCondition, ProjectId, ProjectResourceTelemetry, ProjectTelemetry,
};

#[derive(Clone, Debug)]
pub struct HttpHealthCollector {
    project_id: ProjectId,
    display_name: String,
    endpoint: Option<Url>,
    client: Client,
    last_response_at_ms: Option<i64>,
}

impl HttpHealthCollector {
    pub fn from_optional_base_url(
        project_id: ProjectId,
        display_name: impl Into<String>,
        base_url: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, HttpHealthConfigError> {
        if timeout.is_zero() {
            return Err(HttpHealthConfigError::ZeroTimeout);
        }
        let display_name = display_name.into();
        if display_name.trim().is_empty() || display_name.len() > 96 {
            return Err(HttpHealthConfigError::InvalidDisplayName);
        }
        let endpoint = base_url.map(parse_health_endpoint).transpose()?;
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .user_agent("rdashboard/0.1")
            .build()
            .map_err(|_| HttpHealthConfigError::Client)?;
        Ok(Self {
            project_id,
            display_name,
            endpoint,
            client,
            last_response_at_ms: None,
        })
    }

    pub async fn collect(&mut self, now_ms: i64) -> ProjectTelemetry {
        let Some(endpoint) = self.endpoint.as_ref() else {
            return self.telemetry(
                ProjectCondition::Unknown,
                None,
                "Health endpoint не настроен.",
            );
        };
        match self
            .client
            .get(endpoint.clone())
            .header(reqwest::header::ACCEPT, "text/plain, application/json")
            .send()
            .await
        {
            Ok(response) => {
                self.last_response_at_ms = Some(now_ms);
                if response.status() == StatusCode::OK {
                    self.telemetry(
                        ProjectCondition::Healthy,
                        Some(now_ms),
                        "Стабильный health route вернул HTTP 200.",
                    )
                } else {
                    self.telemetry(
                        ProjectCondition::Down,
                        Some(now_ms),
                        format!("Стабильный health route вернул HTTP {}.", response.status()),
                    )
                }
            }
            Err(_) => self.telemetry(
                ProjectCondition::SignalLost,
                self.last_response_at_ms,
                if self.last_response_at_ms.is_some() {
                    "Health route недоступен; показано время последнего HTTP-ответа."
                } else {
                    "Health route недоступен; предыдущих HTTP-ответов ещё не было."
                },
            ),
        }
    }

    fn telemetry(
        &self,
        condition: ProjectCondition,
        observed_at_ms: Option<i64>,
        detail: impl Into<String>,
    ) -> ProjectTelemetry {
        ProjectTelemetry {
            project_id: self.project_id.clone(),
            display_name: self.display_name.clone(),
            condition,
            observed_at_ms,
            detail: detail.into(),
            resources: ProjectResourceTelemetry {
                status: ObservationStatus::Unknown,
                observed_at_ms: None,
                cpu_percent: None,
                memory_used_bytes: None,
                memory_limit_bytes: None,
                network_rx_bytes: None,
                network_tx_bytes: None,
                block_read_bytes: None,
                block_write_bytes: None,
                detail: "Resource collector has not run yet.".to_owned(),
            },
        }
    }
}

fn parse_health_endpoint(value: &str) -> Result<Url, HttpHealthConfigError> {
    let mut parsed = Url::parse(value).map_err(|_| HttpHealthConfigError::InvalidBaseUrl)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(HttpHealthConfigError::UnsupportedScheme);
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(HttpHealthConfigError::InvalidBaseUrl);
    }
    parsed.set_path("/health");
    Ok(parsed)
}

#[derive(Debug, thiserror::Error)]
pub enum HttpHealthConfigError {
    #[error("health timeout must be positive")]
    ZeroTimeout,
    #[error("health display name is invalid")]
    InvalidDisplayName,
    #[error("health base URL is invalid")]
    InvalidBaseUrl,
    #[error("health base URL must use HTTP or HTTPS")]
    UnsupportedScheme,
    #[error("health HTTP client could not be created")]
    Client,
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use axum::{Router, http::StatusCode, routing::get};
    use tokio::net::TcpListener;

    use super::{HttpHealthCollector, HttpHealthConfigError};
    use crate::domain::{ProjectCondition, ProjectId};

    async fn health_server(status: StatusCode) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("bind health fixture: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("fixture address: {error}"));
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/health", get(move || async move { status })),
            )
            .await
            .unwrap_or_else(|error| panic!("serve health fixture: {error}"));
        });
        format!("http://{address}/")
    }

    fn project_id() -> ProjectId {
        ProjectId::from_str("telegram-gateway").unwrap_or_else(|error| panic!("project: {error}"))
    }

    #[tokio::test]
    async fn stable_health_route_controls_project_condition() {
        let healthy = health_server(StatusCode::OK).await;
        let mut collector = HttpHealthCollector::from_optional_base_url(
            project_id(),
            "Telegram gateway",
            Some(&healthy),
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("collector: {error}"));
        let snapshot = collector.collect(10).await;
        assert_eq!(snapshot.condition, ProjectCondition::Healthy);
        assert_eq!(snapshot.observed_at_ms, Some(10));

        let failing = health_server(StatusCode::SERVICE_UNAVAILABLE).await;
        let mut collector = HttpHealthCollector::from_optional_base_url(
            project_id(),
            "Telegram gateway",
            Some(&failing),
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("collector: {error}"));
        assert_eq!(
            collector.collect(11).await.condition,
            ProjectCondition::Down
        );
    }

    #[test]
    fn health_origin_is_bare_bounded_http_or_https() {
        for invalid in [
            "ftp://example.test/",
            "https://user@example.test/",
            "https://example.test/path",
            "https://example.test/?query=1",
        ] {
            assert!(
                HttpHealthCollector::from_optional_base_url(
                    project_id(),
                    "Telegram gateway",
                    Some(invalid),
                    Duration::from_secs(1),
                )
                .is_err(),
                "accepted {invalid}"
            );
        }
        assert!(matches!(
            HttpHealthCollector::from_optional_base_url(
                project_id(),
                "Telegram gateway",
                None,
                Duration::ZERO,
            ),
            Err(HttpHealthConfigError::ZeroTimeout)
        ));
    }
}
