use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Response, Sse},
    routing::{get, post},
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{
    authorization::inspect_unverified_action_grant,
    controller::{DurableController, TabLeaseClaim},
    domain::{DashboardSnapshot, GitCommitId, OperationKind, ProjectId, ReleaseClass},
    executor_intent::{
        ExecutorIntentConsequenceV1, ExecutorIntentRequiredRoleV1,
        inspect_unverified_executor_intent,
    },
    executor_socket::{ExecutorClientError, RootExecutorClient},
    mutation_admission::{
        ExecuteMutationGrantV1, ObserveMutationStatusV1, PrepareMutationIntentV1,
    },
    store::StoreError,
    unix_time_ms,
};

use super::{
    CloudflareAccessIdentity, CloudflareAccessVerifier, EventHub, EventStream, HubError,
    RequestedAfter, require_cloudflare_access,
};

const INDEX_HTML: &str = include_str!("../../web/index.html");
const APP_CSS: &str = include_str!("../../web/app.css");
const APP_JS: &str = include_str!("../../web/app.js");
const STATUS_JS: &str = include_str!("../../web/status.js");
const TAB_LEASE_TTL_MS: i64 = 5 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct DashboardMutationApiV1 {
    controller: DurableController,
    executor: Arc<RootExecutorClient>,
}

impl DashboardMutationApiV1 {
    pub const fn new(controller: DurableController, executor: Arc<RootExecutorClient>) -> Self {
        Self {
            controller,
            executor,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DashboardState {
    pub hub: EventHub,
    pub latest_snapshot: Arc<RwLock<Option<DashboardSnapshot>>>,
    pub collection_error: Arc<RwLock<Option<String>>>,
    pub retention_error: Arc<RwLock<Option<String>>>,
    pub sample_interval: Duration,
    pub mutation_api: Option<Arc<DashboardMutationApiV1>>,
}

impl DashboardState {
    pub fn new(hub: EventHub, sample_interval: Duration) -> Self {
        Self {
            hub,
            latest_snapshot: Arc::new(RwLock::new(None)),
            collection_error: Arc::new(RwLock::new(None)),
            retention_error: Arc::new(RwLock::new(None)),
            sample_interval,
            mutation_api: None,
        }
    }

    #[must_use]
    pub fn with_mutation_api(mut self, mutation_api: DashboardMutationApiV1) -> Self {
        self.mutation_api = Some(Arc::new(mutation_api));
        self
    }
}

pub fn router(state: DashboardState) -> Router {
    router_with_access(state, None)
}

pub fn router_with_access(
    state: DashboardState,
    access: Option<Arc<CloudflareAccessVerifier>>,
) -> Router {
    let protected = Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(stylesheet))
        .route("/assets/app.js", get(script))
        .route("/assets/status.js", get(status_script))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/events", get(events))
        .route("/api/v1/mutations/capabilities", get(mutation_capabilities))
        .route("/api/v1/mutations/lease", post(takeover_mutation_lease))
        .route("/api/v1/mutations/prepare", post(prepare_mutation))
        .route("/api/v1/mutations/execute", post(execute_mutation))
        .route("/api/v1/mutations/status", get(mutation_status))
        .fallback(not_found);
    let protected = access.map_or(protected.clone(), |verifier| {
        protected.layer(middleware::from_fn_with_state(
            verifier,
            require_cloudflare_access,
        ))
    });
    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=300"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin-allow-popups"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ),
        ))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], Html(INDEX_HTML))
}

async fn stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        APP_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        APP_JS,
    )
}

async fn status_script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        STATUS_JS,
    )
}

async fn snapshot(State(state): State<DashboardState>) -> Response {
    let snapshot = state.latest_snapshot.read().await.clone();
    match snapshot {
        Some(snapshot) => {
            let served_at_ms = match unix_time_ms() {
                Ok(value) => value,
                Err(error) => {
                    return ApiProblem::response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "clock_invalid",
                        &error.to_string(),
                    )
                    .into_response();
                }
            };
            let Ok(server_time) = HeaderValue::try_from(served_at_ms.to_string()) else {
                return ApiProblem::response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "clock_invalid",
                    "Server time cannot be represented as an HTTP header.",
                )
                .into_response();
            };
            let mut response = Json(snapshot).into_response();
            response
                .headers_mut()
                .insert("x-rdashboard-server-time-ms", server_time);
            response
        }
        None => ApiProblem::response(
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot_unavailable",
            "No complete host snapshot has been collected yet.",
        )
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventQuery {
    after: Option<String>,
}

async fn events(
    State(state): State<DashboardState>,
    identity: Option<Extension<CloudflareAccessIdentity>>,
    Query(query): Query<EventQuery>,
) -> Response {
    let requested = RequestedAfter::parse(query.after.as_deref());
    match state.hub.subscribe(requested) {
        Ok(stream) => Sse::new(bound_event_stream(stream, identity.as_ref()))
            .keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(Duration::from_secs(15))
                    .text("keepalive"),
            )
            .into_response(),
        Err(HubError::Capacity) => ApiProblem::response(
            StatusCode::SERVICE_UNAVAILABLE,
            "stream_capacity",
            "The pilot SSE connection limit is currently exhausted.",
        )
        .into_response(),
        Err(error) => ApiProblem::response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stream_initialization_failed",
            &error.to_string(),
        )
        .into_response(),
    }
}

fn bound_event_stream(
    stream: EventStream,
    identity: Option<&Extension<CloudflareAccessIdentity>>,
) -> EventStream {
    let Some(identity) = identity else {
        return stream;
    };
    let now = unix_time_ms()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .map_or(identity.expires_at, |value| value / 1_000);
    let lifetime = identity.expires_at.saturating_sub(now).min(5 * 60);
    Box::pin(stream.take_until(tokio::time::sleep(Duration::from_secs(lifetime))))
}

async fn health(State(state): State<DashboardState>) -> Response {
    let Ok(now) = unix_time_ms() else {
        return ApiProblem::response(
            StatusCode::SERVICE_UNAVAILABLE,
            "clock_invalid",
            "The host clock is unavailable.",
        )
        .into_response();
    };
    let collection_error = state.collection_error.read().await.clone();
    let retention_error = state.retention_error.read().await.clone();
    let snapshot = state.latest_snapshot.read().await.clone();
    let Some(snapshot) = snapshot else {
        return ApiProblem::response(
            StatusCode::SERVICE_UNAVAILABLE,
            "collection_not_started",
            "No host sample is available.",
        )
        .into_response();
    };
    let Some(age_ms) = now
        .checked_sub(snapshot.generated_at_ms)
        .filter(|age| *age >= 0)
    else {
        return ApiProblem::response(
            StatusCode::SERVICE_UNAVAILABLE,
            "sample_timestamp_in_future",
            "The latest host sample timestamp is ahead of the host clock.",
        )
        .into_response();
    };
    let dead_after_ms = i64::try_from(state.sample_interval.as_millis())
        .unwrap_or(i64::MAX)
        .saturating_mul(3);
    let critical_error = collection_error
        .map(|_| "critical collection failed")
        .or_else(|| retention_error.map(|_| "critical retention failed"));
    if let Some(detail) = critical_error {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "degraded",
                sample_age_ms: age_ms,
                detail: Some(detail.to_owned()),
            }),
        )
            .into_response();
    }
    if age_ms > dead_after_ms {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "stale",
                sample_age_ms: age_ms,
                detail: Some("critical collection is stale".to_owned()),
            }),
        )
            .into_response();
    }
    Json(HealthResponse {
        status: "ok",
        sample_age_ms: age_ms,
        detail: None,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeoverLeaseRequest {
    actor_id: uuid::Uuid,
    lease_id: uuid::Uuid,
}

#[derive(Debug, Serialize)]
struct TakeoverLeaseResponse {
    actor_id: uuid::Uuid,
    lease_id: uuid::Uuid,
    generation: u64,
    expires_at_ms: i64,
}

async fn takeover_mutation_lease(
    State(state): State<DashboardState>,
    Json(request): Json<TakeoverLeaseRequest>,
) -> Response {
    let Some(api) = state.mutation_api.as_ref() else {
        return mutation_unavailable();
    };
    let now_ms = match unix_time_ms() {
        Ok(now_ms) => now_ms,
        Err(error) => return clock_problem(&error),
    };
    let expires_at_ms = now_ms.saturating_add(TAB_LEASE_TTL_MS);
    match api
        .controller
        .takeover_lease(request.actor_id, request.lease_id, now_ms, expires_at_ms)
    {
        Ok(lease) => Json(TakeoverLeaseResponse {
            actor_id: lease.user_id,
            lease_id: lease.lease_id,
            generation: lease.generation,
            expires_at_ms: lease.expires_at_ms,
        })
        .into_response(),
        Err(error) => store_problem(&error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareMutationRequest {
    project_id: ProjectId,
    operation_kind: OperationKind,
    target_commit: Option<GitCommitId>,
    proposed_release_class: Option<ReleaseClass>,
    idempotency_key: uuid::Uuid,
}

#[derive(Debug, Serialize)]
struct PrepareMutationResponse {
    signed_intent: String,
    intent_id: uuid::Uuid,
    expires_at_ms: i64,
    effective_release_class: Option<ReleaseClass>,
    consequences: Vec<ExecutorIntentConsequenceV1>,
    minimum_role: ExecutorIntentRequiredRoleV1,
}

async fn prepare_mutation(
    State(state): State<DashboardState>,
    Json(request): Json<PrepareMutationRequest>,
) -> Response {
    let Some(api) = state.mutation_api.as_ref() else {
        return mutation_unavailable();
    };
    match api
        .executor
        .prepare_operation_intent(PrepareMutationIntentV1 {
            project_id: request.project_id,
            operation_kind: request.operation_kind,
            target_commit: request.target_commit,
            proposed_release_class: request.proposed_release_class,
            idempotency_key: request.idempotency_key,
        })
        .await
    {
        Ok(signed_intent) => match inspect_unverified_executor_intent(&signed_intent) {
            Ok(claims) => Json(PrepareMutationResponse {
                signed_intent,
                intent_id: claims.intent_id,
                expires_at_ms: claims.expires_at_ms,
                effective_release_class: claims.effective_release_class,
                consequences: claims.consequences,
                minimum_role: claims.minimum_role,
            })
            .into_response(),
            Err(_) => executor_problem(&ExecutorClientError::ResponseBindingMismatch),
        },
        Err(error) => executor_problem(&error),
    }
}

#[derive(Debug, Serialize)]
struct MutationCapabilitiesResponse {
    schema_version: u16,
    executor_socket_configured: bool,
    authorization_handoff_available: bool,
    authorizer_url: Option<String>,
}

async fn mutation_capabilities(
    State(state): State<DashboardState>,
) -> Json<MutationCapabilitiesResponse> {
    let mutation_api = state.mutation_api.as_ref();
    Json(MutationCapabilitiesResponse {
        schema_version: 1,
        executor_socket_configured: mutation_api.is_some(),
        authorization_handoff_available: false,
        authorizer_url: None,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteMutationRequest {
    intent_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    action_grant: String,
}

async fn execute_mutation(
    State(state): State<DashboardState>,
    Json(request): Json<ExecuteMutationRequest>,
) -> Response {
    let Some(api) = state.mutation_api.as_ref() else {
        return mutation_unavailable();
    };
    let now_ms = match unix_time_ms() {
        Ok(now_ms) => now_ms,
        Err(error) => return clock_problem(&error),
    };
    let claims = match inspect_unverified_action_grant(&request.action_grant) {
        Ok(claims) if claims.intent_id == request.intent_id => claims,
        Ok(_) => {
            return ApiProblem::response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "grant_binding",
                "The action grant does not name the requested intent.",
            )
            .into_response();
        }
        Err(_) => {
            return ApiProblem::response(
                StatusCode::BAD_REQUEST,
                "invalid_action_grant",
                "The action grant is malformed or noncanonical.",
            )
            .into_response();
        }
    };
    if let Err(error) = api.controller.validate_tab_lease(
        &TabLeaseClaim {
            user_id: claims.actor_id,
            lease_id: claims.lease_id,
            generation: claims.lease_generation,
        },
        now_ms,
    ) {
        return lease_problem(&error);
    }
    match api
        .executor
        .execute_granted_operation(ExecuteMutationGrantV1 {
            intent_id: request.intent_id,
            attempt_id: request.attempt_id,
            action_grant: request.action_grant,
        })
        .await
    {
        Ok(acceptance) => Json(acceptance_response(acceptance)).into_response(),
        Err(error) => executor_problem(&error),
    }
}

#[derive(Debug, Serialize)]
struct MutationAcceptanceResponse {
    intent_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    replayed: bool,
}

fn acceptance_response(
    acceptance: crate::mutation_admission::MutationAcceptanceV1,
) -> MutationAcceptanceResponse {
    MutationAcceptanceResponse {
        intent_id: acceptance.intent_id,
        attempt_id: acceptance.attempt_id,
        replayed: acceptance.replayed,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationStatusQuery {
    intent_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
}

async fn mutation_status(
    State(state): State<DashboardState>,
    Query(query): Query<MutationStatusQuery>,
) -> Response {
    let Some(api) = state.mutation_api.as_ref() else {
        return mutation_unavailable();
    };
    match api
        .executor
        .mutation_status(ObserveMutationStatusV1 {
            intent_id: query.intent_id,
            attempt_id: query.attempt_id,
        })
        .await
    {
        Ok(status) => Json(status).into_response(),
        Err(error) => executor_problem(&error),
    }
}

fn mutation_unavailable() -> Response {
    ApiProblem::response(
        StatusCode::SERVICE_UNAVAILABLE,
        "mutation_unavailable",
        "The dashboard mutation path is not configured.",
    )
    .into_response()
}

fn clock_problem(error: &impl std::fmt::Display) -> Response {
    ApiProblem::response(
        StatusCode::SERVICE_UNAVAILABLE,
        "clock_invalid",
        &error.to_string(),
    )
    .into_response()
}

fn lease_problem(error: &StoreError) -> Response {
    let (status, code) = match error {
        StoreError::LeaseRevoked => (StatusCode::CONFLICT, "lease_revoked"),
        StoreError::LeaseExpired => (StatusCode::CONFLICT, "lease_expired"),
        _ => (StatusCode::BAD_REQUEST, "invalid_lease"),
    };
    ApiProblem::response(status, code, &error.to_string()).into_response()
}

fn store_problem(error: &StoreError) -> Response {
    ApiProblem::response(
        StatusCode::BAD_REQUEST,
        "invalid_mutation_request",
        &error.to_string(),
    )
    .into_response()
}

fn executor_problem(error: &ExecutorClientError) -> Response {
    let (status, code) = match error {
        ExecutorClientError::Rejected {
            retryable: false, ..
        } => (StatusCode::UNPROCESSABLE_ENTITY, "mutation_rejected"),
        ExecutorClientError::Rejected {
            retryable: true, ..
        } => (StatusCode::SERVICE_UNAVAILABLE, "mutation_retryable"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "executor_unavailable"),
    };
    ApiProblem::response(status, code, &error.to_string()).into_response()
}

async fn not_found() -> Response {
    ApiProblem::response(StatusCode::NOT_FOUND, "not_found", "Route not found.").into_response()
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    sample_age_ms: i64,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiProblem<'a> {
    code: &'a str,
    detail: &'a str,
}

impl<'a> ApiProblem<'a> {
    const fn response(status: StatusCode, code: &'a str, detail: &'a str) -> ProblemResponse<'a> {
        ProblemResponse {
            status,
            problem: Self { code, detail },
        }
    }
}

struct ProblemResponse<'a> {
    status: StatusCode,
    problem: ApiProblem<'a>,
}

impl IntoResponse for ProblemResponse<'_> {
    fn into_response(self) -> Response {
        (self.status, Json(self.problem)).into_response()
    }
}
