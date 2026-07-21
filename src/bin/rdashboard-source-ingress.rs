use std::{collections::BTreeSet, io, str::FromStr as _, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path as AxumPath, Request, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rdashboard::{
    domain::ProjectId,
    installed_source::load_installed_source_config,
    source::GithubWebhookAdmissionV1,
    source_ingress_socket::{
        SOURCE_INGRESS_BODY_MAX_BYTES, SourceIngressClientError, SourceIngressClientV1,
        SourceIngressRejectionCodeV1,
    },
};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const LISTEN_ADDRESS: &str = "127.0.0.1:3201";
const GITHUB_EVENT_HEADER: &str = "x-github-event";
const GITHUB_DELIVERY_HEADER: &str = "x-github-delivery";
const GITHUB_SIGNATURE_HEADER: &str = "x-hub-signature-256";
const MAX_HEADER_COUNT: usize = 32;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_WEBHOOK_REQUESTS: usize = 8;
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
struct AppState {
    projects: BTreeSet<ProjectId>,
    client: SourceIngressClientV1,
    request_slots: Arc<Semaphore>,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(invalid_data("rdashboard-source-ingress accepts no arguments").into());
    }
    init_tracing()?;
    let config = load_installed_source_config()?;
    let projects = config.project_ids().into_iter().collect::<BTreeSet<_>>();
    let client = SourceIngressClientV1::installed(
        config.source_uid,
        Duration::from_millis(config.request_timeout_ms),
    )?;
    let state = Arc::new(AppState {
        projects,
        client,
        request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_WEBHOOK_REQUESTS)),
    });
    let listener = tokio::net::TcpListener::bind(LISTEN_ADDRESS).await?;
    info!(listen = LISTEN_ADDRESS, "source HTTP ingress listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: Arc<AppState>) -> Router {
    let webhook = Router::new()
        .route("/github/{project_id}", post(github_push))
        .layer(DefaultBodyLimit::max(SOURCE_INGRESS_BODY_MAX_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            limit_webhook_concurrency,
        ));
    Router::new()
        .route("/health", get(health))
        .merge(webhook)
        .with_state(state)
}

async fn limit_webhook_concurrency(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = Arc::clone(&state.request_slots).try_acquire_owned() else {
        return ingress_response(StatusCode::SERVICE_UNAVAILABLE, "overloaded", Some(1));
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn github_push(
    State(state): State<Arc<AppState>>,
    AxumPath(raw_project_id): AxumPath<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if uri.query().is_some() {
        return ingress_response(StatusCode::NOT_FOUND, "not_found", None);
    }
    let Ok(project_id) = ProjectId::from_str(&raw_project_id) else {
        return ingress_response(StatusCode::NOT_FOUND, "not_found", None);
    };
    if !state.projects.contains(&project_id) {
        return ingress_response(StatusCode::NOT_FOUND, "not_found", None);
    }
    let request = match github_headers(&headers) {
        Ok(request) => request,
        Err(rejection) => return rejection.response(),
    };
    let raw_body = body.to_vec();
    drop(body);
    match state
        .client
        .github_push(
            project_id.clone(),
            request.delivery_id,
            request.signature,
            raw_body,
        )
        .await
    {
        Ok(GithubWebhookAdmissionV1::Queued { wakeup_sequence }) => {
            info!(project_id = %project_id, wakeup_sequence, "GitHub push wake-up durably queued");
            ingress_response(StatusCode::ACCEPTED, "queued", None)
        }
        Ok(GithubWebhookAdmissionV1::Duplicate {
            wakeup_sequence,
            completed,
        }) => {
            info!(
                project_id = %project_id,
                wakeup_sequence,
                completed,
                "duplicate GitHub push delivery acknowledged"
            );
            let status = if completed {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            ingress_response(status, "duplicate", None)
        }
        Ok(GithubWebhookAdmissionV1::IgnoredRef) => {
            ingress_response(StatusCode::OK, "ignored_ref", None)
        }
        Err(error) => {
            let (status, code, retry_after) = map_client_error(&error);
            warn!(project_id = %project_id, error = %error, "GitHub push ingress rejected");
            ingress_response(status, code, retry_after)
        }
    }
}

struct GithubHeaders {
    delivery_id: String,
    signature: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IngressHttpRejection {
    status: StatusCode,
    code: &'static str,
    retry_after: Option<u64>,
}

impl IngressHttpRejection {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after: None,
        }
    }

    fn response(self) -> Response {
        ingress_response(self.status, self.code, self.retry_after)
    }
}

fn github_headers(headers: &HeaderMap) -> Result<GithubHeaders, IngressHttpRejection> {
    let header_bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())
    });
    if headers.len() > MAX_HEADER_COUNT || header_bytes.is_none_or(|bytes| bytes > MAX_HEADER_BYTES)
    {
        return Err(IngressHttpRejection::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
        ));
    }
    if headers
        .get(GITHUB_EVENT_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some("push")
    {
        return Err(IngressHttpRejection::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_event",
        ));
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type != "application/json" {
        return Err(IngressHttpRejection::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let delivery_id = required_header(headers, GITHUB_DELIVERY_HEADER, 128)?;
    let signature = required_header(headers, GITHUB_SIGNATURE_HEADER, 71)?;
    Ok(GithubHeaders {
        delivery_id,
        signature,
    })
}

fn required_header(
    headers: &HeaderMap,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<String, IngressHttpRejection> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= maximum_bytes)
        .ok_or_else(|| IngressHttpRejection::new(StatusCode::BAD_REQUEST, "invalid_headers"))?;
    Ok(value.to_owned())
}

fn map_client_error(error: &SourceIngressClientError) -> (StatusCode, &'static str, Option<u64>) {
    match error {
        SourceIngressClientError::Rejected {
            code: SourceIngressRejectionCodeV1::AuthenticationFailed,
            ..
        } => (StatusCode::UNAUTHORIZED, "authentication_failed", None),
        SourceIngressClientError::Rejected {
            code: SourceIngressRejectionCodeV1::UnknownProject,
            ..
        } => (StatusCode::NOT_FOUND, "not_found", None),
        SourceIngressClientError::Rejected {
            code:
                SourceIngressRejectionCodeV1::RepositoryMismatch
                | SourceIngressRejectionCodeV1::DeliveryConflict,
            ..
        } => (StatusCode::CONFLICT, "delivery_conflict", None),
        SourceIngressClientError::Rejected {
            code: SourceIngressRejectionCodeV1::InvalidRequest,
            ..
        }
        | SourceIngressClientError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "invalid_request", None)
        }
        SourceIngressClientError::Rejected {
            retryable: false, ..
        } => (StatusCode::BAD_REQUEST, "rejected", None),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", Some(1)),
    }
}

fn ingress_response(status: StatusCode, code: &'static str, retry_after: Option<u64>) -> Response {
    let mut response = (status, code).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if let Some(seconds) = retry_after {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_str(&seconds.to_string())
                .expect("small retry-after value is valid"),
        );
    }
    response
}

fn init_tracing() -> Result<(), DynError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()?;
    Ok(())
}

fn invalid_data(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
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

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderValue, Request as HttpRequest, header},
    };
    use tower::ServiceExt as _;

    #[test]
    fn github_headers_require_exact_push_json_and_bounded_identifiers() {
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, HeaderValue::from_static("push"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            GITHUB_DELIVERY_HEADER,
            HeaderValue::from_static("delivery-1"),
        );
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            HeaderValue::from_static(
                "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let parsed = github_headers(&headers).expect("valid headers");
        assert_eq!(parsed.delivery_id, "delivery-1");

        headers.insert(GITHUB_EVENT_HEADER, HeaderValue::from_static("ping"));
        assert!(github_headers(&headers).is_err());
        headers.insert(GITHUB_EVENT_HEADER, HeaderValue::from_static("push"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(github_headers(&headers).is_err());
    }

    #[tokio::test]
    async fn webhook_concurrency_is_bounded_without_hiding_health() {
        let request_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_WEBHOOK_REQUESTS));
        let held = Arc::clone(&request_slots)
            .acquire_many_owned(
                u32::try_from(MAX_CONCURRENT_WEBHOOK_REQUESTS).expect("small request limit"),
            )
            .await
            .expect("hold ingress permits");
        let state = Arc::new(AppState {
            projects: BTreeSet::from([ProjectId::from_str("ralert").expect("project")]),
            client: SourceIngressClientV1::new(
                "/tmp/rdashboard-source-ingress-test.sock",
                991,
                Duration::from_secs(1),
            )
            .expect("test client"),
            request_slots,
        });
        let app = router(state);
        let overloaded = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/github/ralert")
                    .body(Body::empty())
                    .expect("webhook request"),
            )
            .await
            .expect("overload response");
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            overloaded.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("1"))
        );

        let health = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
        drop(held);
    }
}
