use std::{
    fs,
    path::{Component, Path},
    str::FromStr,
    time::Duration,
};

use futures_util::StreamExt as _;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, LINK,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    domain::{EvidenceDigest, GitCommitId, ProjectId},
    integrations::{
        DependencyCheckStateV1, DependencyUpdateV1, ErrorGroupV1, ErrorInsightV1, ErrorLevelV1,
        InsightPriorityV1, InsightSourceV1, IntegrationFailureV1, MAX_DEPENDENCY_UPDATES,
        MAX_ERROR_GROUPS, PROJECT_INTEGRATION_SCHEMA_VERSION, ProjectErrorsDataV1,
        ProjectUpdatesDataV1,
    },
};

const PROJECT_ID: &str = "rimg";
const GLITCHTIP_ISSUES_URL: &str = "https://glitchtip.4u.ge/api/0/organizations/4u/issues/?project=4&query=is%3Aunresolved&limit=20";
const OPENCODE_CHAT_URL: &str = "https://opencode.ai/zen/v1/chat/completions";
const GITHUB_PULLS_URL: &str =
    "https://api.github.com/repos/mrDenai/rimg/pulls?state=open&base=main&per_page=50";
const GITHUB_COMMIT_URL_PREFIX: &str = "https://api.github.com/repos/mrDenai/rimg/commits/";
const GLITCHTIP_CREDENTIAL: &str = "glitchtip-read-token";
const OPENCODE_CREDENTIAL: &str = "opencode-api-key";
const GITHUB_CREDENTIAL: &str = "github-metadata-token";
const MAX_CREDENTIAL_BYTES: u64 = 8 * 1024;
const MAX_GLITCHTIP_BODY_BYTES: usize = 256 * 1024;
const MAX_OPENCODE_BODY_BYTES: usize = 64 * 1024;
const MAX_GITHUB_BODY_BYTES: usize = 512 * 1024;
const OPENCODE_MODEL: &str = "deepseek-v4-flash-free";

/// Fixed-provider collectors used by the non-root dashboard process.
#[derive(Clone)]
pub struct ProjectIntegrationCollectors {
    project_id: ProjectId,
    client: reqwest::Client,
    collection_deadline: Duration,
    glitchtip_authorization: Option<HeaderValue>,
    opencode_authorization: Option<HeaderValue>,
    github_authorization: Option<HeaderValue>,
}

impl std::fmt::Debug for ProjectIntegrationCollectors {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectIntegrationCollectors")
            .field("project_id", &self.project_id)
            .field("collection_deadline", &self.collection_deadline)
            .field(
                "glitchtip_configured",
                &self.glitchtip_authorization.is_some(),
            )
            .field(
                "opencode_configured",
                &self.opencode_authorization.is_some(),
            )
            .field("github_configured", &self.github_authorization.is_some())
            .finish_non_exhaustive()
    }
}

impl ProjectIntegrationCollectors {
    /// Loads optional provider credentials from a systemd credential directory.
    ///
    /// Missing credentials keep the corresponding integration explicitly unconfigured. A present
    /// but malformed credential is a startup error so a broken secret is not mistaken for absence.
    pub fn from_credential_directory(
        credential_directory: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, IntegrationCollectorConfigError> {
        if timeout.is_zero() {
            return Err(IntegrationCollectorConfigError::ZeroTimeout);
        }
        if credential_directory.is_some_and(|path| !valid_credential_directory(path)) {
            return Err(IntegrationCollectorConfigError::InvalidCredentialDirectory);
        }
        let glitchtip = read_optional_credential(credential_directory, GLITCHTIP_CREDENTIAL)?
            .map(|token| authorization_header("Bearer", &token))
            .transpose()?;
        let opencode = read_optional_credential(credential_directory, OPENCODE_CREDENTIAL)?
            .map(|token| authorization_header("Bearer", &token))
            .transpose()?;
        let github = read_optional_credential(credential_directory, GITHUB_CREDENTIAL)?
            .map(|token| authorization_header("Bearer", &token))
            .transpose()?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(timeout)
            .user_agent("rdashboard-integrations/1")
            .build()
            .map_err(|_| IntegrationCollectorConfigError::HttpClient)?;
        Ok(Self {
            project_id: ProjectId::from_str(PROJECT_ID)
                .map_err(|_| IntegrationCollectorConfigError::InternalProjectId)?,
            client,
            collection_deadline: timeout,
            glitchtip_authorization: glitchtip,
            opencode_authorization: opencode,
            github_authorization: github,
        })
    }

    pub async fn collect_errors(
        &self,
        now_ms: i64,
    ) -> Result<ProjectErrorsDataV1, IntegrationCollectionError> {
        tokio::time::timeout(self.collection_deadline, self.collect_errors_inner(now_ms))
            .await
            .map_err(|_| {
                IntegrationCollectionError::new(
                    "errors_deadline",
                    "Сбор ошибок превысил общий лимит времени.",
                )
            })?
    }

    async fn collect_errors_inner(
        &self,
        now_ms: i64,
    ) -> Result<ProjectErrorsDataV1, IntegrationCollectionError> {
        let authorization = self.glitchtip_authorization.as_ref().ok_or_else(|| {
            IntegrationCollectionError::new(
                "glitchtip_not_configured",
                "Не установлен отдельный read-only credential GlitchTip.",
            )
        })?;
        let endpoint = fixed_url(GLITCHTIP_ISSUES_URL)?;
        let request = self
            .client
            .get(endpoint)
            .header(AUTHORIZATION, authorization.clone())
            .header(ACCEPT, "application/json");
        let (headers, body) =
            bounded_response(request, MAX_GLITCHTIP_BODY_BYTES, "glitchtip").await?;
        let issues: Vec<GlitchTipIssue> = serde_json::from_slice(&body).map_err(|_| {
            IntegrationCollectionError::new(
                "glitchtip_invalid_response",
                "GlitchTip вернул неподдерживаемый JSON.",
            )
        })?;
        if issues.len() > MAX_ERROR_GROUPS {
            return Err(IntegrationCollectionError::new(
                "glitchtip_response_too_large",
                "GlitchTip вернул слишком много групп ошибок.",
            ));
        }
        let page = ErrorPage::from_issues(issues, has_next_page(&headers))?;
        assemble_errors(
            self.project_id.clone(),
            page,
            self.opencode_authorization
                .as_ref()
                .map(|authorization| OpenCodeAnalyzer {
                    client: self.client.clone(),
                    authorization: authorization.clone(),
                }),
            now_ms,
        )
        .await
    }

    pub async fn collect_updates(
        &self,
        now_ms: i64,
    ) -> Result<ProjectUpdatesDataV1, IntegrationCollectionError> {
        tokio::time::timeout(self.collection_deadline, self.collect_updates_inner(now_ms))
            .await
            .map_err(|_| {
                IntegrationCollectionError::new(
                    "updates_deadline",
                    "Сбор обновлений превысил общий лимит времени.",
                )
            })?
    }

    async fn collect_updates_inner(
        &self,
        now_ms: i64,
    ) -> Result<ProjectUpdatesDataV1, IntegrationCollectionError> {
        let _ = now_ms;
        let authorization = self.github_authorization.as_ref().ok_or_else(|| {
            IntegrationCollectionError::new(
                "github_not_configured",
                "Не установлен credential только для метаданных GitHub.",
            )
        })?;
        let endpoint = fixed_url(GITHUB_PULLS_URL)?;
        let request = github_request(&self.client, endpoint, authorization);
        let (headers, body) = bounded_response(request, MAX_GITHUB_BODY_BYTES, "github").await?;
        let pulls: Vec<GitHubPull> = serde_json::from_slice(&body).map_err(|_| {
            IntegrationCollectionError::new(
                "github_invalid_response",
                "GitHub вернул неподдерживаемый список pull request.",
            )
        })?;
        if pulls.len() > MAX_DEPENDENCY_UPDATES {
            return Err(IntegrationCollectionError::new(
                "github_response_too_large",
                "GitHub вернул слишком много pull request.",
            ));
        }
        let mut updates = Vec::new();
        for pull in pulls.into_iter().filter(GitHubPull::is_dependency_update) {
            let head = GitCommitId::from_str(&pull.head.sha).map_err(|_| {
                IntegrationCollectionError::new(
                    "github_invalid_response",
                    "GitHub вернул некорректный commit dependency update.",
                )
            })?;
            let checks_endpoint = fixed_url(&format!(
                "{GITHUB_COMMIT_URL_PREFIX}{}/check-runs?per_page=100",
                head.as_str()
            ))?;
            let request = github_request(&self.client, checks_endpoint, authorization);
            let (check_headers, checks_body) =
                bounded_response(request, MAX_GITHUB_BODY_BYTES, "github").await?;
            let checks: GitHubCheckRuns = serde_json::from_slice(&checks_body).map_err(|_| {
                IntegrationCollectionError::new(
                    "github_invalid_response",
                    "GitHub вернул неподдерживаемое состояние проверок.",
                )
            })?;
            let update = DependencyUpdateV1 {
                number: pull.number,
                title: pull.title,
                head_ref: pull.head.reference,
                head,
                updated_at: pull.updated_at,
                deep_link: pull.html_url,
                check_state: classify_check_runs(&checks.check_runs, has_next_page(&check_headers)),
            };
            update.validate().map_err(|_| {
                IntegrationCollectionError::new(
                    "github_invalid_response",
                    "GitHub вернул небезопасные метаданные dependency update.",
                )
            })?;
            updates.push(update);
        }
        let data = ProjectUpdatesDataV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: self.project_id.clone(),
            truncated: has_next_page(&headers),
            updates,
        };
        data.validate().map_err(|_| {
            IntegrationCollectionError::new(
                "github_invalid_response",
                "Сводка dependency updates не прошла проверку.",
            )
        })?;
        Ok(data)
    }
}

fn github_request(
    client: &reqwest::Client,
    endpoint: Url,
    authorization: &HeaderValue,
) -> reqwest::RequestBuilder {
    client
        .get(endpoint)
        .header(AUTHORIZATION, authorization.clone())
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
}

#[derive(Clone, Debug)]
struct ErrorPage {
    groups: Vec<ErrorGroupV1>,
    truncated: bool,
}

impl ErrorPage {
    fn from_issues(
        issues: Vec<GlitchTipIssue>,
        truncated: bool,
    ) -> Result<Self, IntegrationCollectionError> {
        let mut groups = Vec::with_capacity(issues.len());
        for issue in issues {
            let event_count = issue.count.value().ok_or_else(|| {
                IntegrationCollectionError::new(
                    "glitchtip_invalid_response",
                    "GlitchTip вернул некорректное число событий.",
                )
            })?;
            let affected_users = issue.user_count.value().ok_or_else(|| {
                IntegrationCollectionError::new(
                    "glitchtip_invalid_response",
                    "GlitchTip вернул некорректное число затронутых пользователей.",
                )
            })?;
            let safe_label = issue
                .metadata
                .and_then(|metadata| metadata.kind)
                .filter(|value| valid_safe_label(value))
                .unwrap_or_else(|| "ApplicationError".to_owned());
            let group = ErrorGroupV1 {
                safe_label,
                level: parse_error_level(&issue.level),
                event_count,
                affected_users,
                first_seen: issue.first_seen,
                last_seen: issue.last_seen,
                deep_link: issue.permalink,
            };
            group.validate().map_err(|_| {
                IntegrationCollectionError::new(
                    "glitchtip_invalid_response",
                    "GlitchTip вернул небезопасные агрегаты группы ошибок.",
                )
            })?;
            groups.push(group);
        }
        Ok(Self { groups, truncated })
    }
}

async fn assemble_errors(
    project_id: ProjectId,
    page: ErrorPage,
    analyzer: Option<OpenCodeAnalyzer>,
    now_ms: i64,
) -> Result<ProjectErrorsDataV1, IntegrationCollectionError> {
    if now_ms < 0 {
        return Err(IntegrationCollectionError::new(
            "clock_invalid",
            "Часы сервера недоступны.",
        ));
    }
    let facts = ModelErrorFacts::from_groups(&page.groups, page.truncated)?;
    let encoded_facts = serde_jcs::to_vec(&facts).map_err(|_| {
        IntegrationCollectionError::new(
            "analysis_input_invalid",
            "Агрегаты ошибок не удалось канонизировать.",
        )
    })?;
    let digest = EvidenceDigest::sha256(&encoded_facts);
    let (unresolved_groups, total_events, affected_users, highest_level) =
        summarize_error_groups(&page.groups)?;

    let (insight, analysis_error) = if page.groups.is_empty() {
        (
            ErrorInsightV1 {
                source: InsightSourceV1::Deterministic,
                priority: InsightPriorityV1::None,
                summary: "Открытых ошибок нет.".to_owned(),
                actions: Vec::new(),
                generated_at_ms: now_ms,
                input_digest: digest,
            },
            None,
        )
    } else if let Some(analyzer) = analyzer {
        match analyzer
            .analyze(&encoded_facts, digest.clone(), now_ms)
            .await
        {
            Ok(insight) => (insight, None),
            Err(error) => (
                deterministic_insight(
                    unresolved_groups,
                    total_events,
                    highest_level,
                    digest,
                    now_ms,
                ),
                Some(error.into_failure()),
            ),
        }
    } else {
        (
            deterministic_insight(
                unresolved_groups,
                total_events,
                highest_level,
                digest,
                now_ms,
            ),
            Some(
                IntegrationFailureV1::new(
                    "opencode_not_configured",
                    "Не установлен credential OpenCode для DeepSeek Free.",
                )
                .map_err(|_| {
                    IntegrationCollectionError::new(
                        "analysis_failure_invalid",
                        "Состояние анализа не прошло проверку.",
                    )
                })?,
            ),
        )
    };
    let data = ProjectErrorsDataV1 {
        schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
        project_id,
        unresolved_groups,
        truncated: page.truncated,
        total_events,
        affected_users,
        highest_level,
        groups: page.groups,
        insight,
        analysis_error,
    };
    data.validate().map_err(|_| {
        IntegrationCollectionError::new(
            "glitchtip_invalid_response",
            "Сводка ошибок не прошла проверку.",
        )
    })?;
    Ok(data)
}

fn summarize_error_groups(
    groups: &[ErrorGroupV1],
) -> Result<(u64, u64, u64, ErrorLevelV1), IntegrationCollectionError> {
    let unresolved_groups = u64::try_from(groups.len()).map_err(|_| {
        IntegrationCollectionError::new(
            "glitchtip_response_too_large",
            "Число групп ошибок не помещается в контракт.",
        )
    })?;
    let total_events = checked_group_sum(groups, |group| group.event_count)?;
    let affected_users = checked_group_sum(groups, |group| group.affected_users)?;
    let highest_level = groups
        .iter()
        .map(|group| group.level)
        .max_by_key(|level| error_level_rank(*level))
        .unwrap_or(ErrorLevelV1::Unknown);
    Ok((
        unresolved_groups,
        total_events,
        affected_users,
        highest_level,
    ))
}

fn deterministic_insight(
    groups: u64,
    events: u64,
    highest_level: ErrorLevelV1,
    input_digest: EvidenceDigest,
    generated_at_ms: i64,
) -> ErrorInsightV1 {
    ErrorInsightV1 {
        source: InsightSourceV1::Deterministic,
        priority: priority_for_level(highest_level),
        summary: format!(
            "Обнаружено {groups} открытых групп и {events} событий; анализ DeepSeek недоступен."
        ),
        actions: vec!["Проверьте наиболее частые группы в GlitchTip.".to_owned()],
        generated_at_ms,
        input_digest,
    }
}

fn checked_group_sum(
    groups: &[ErrorGroupV1],
    value: impl Fn(&ErrorGroupV1) -> u64,
) -> Result<u64, IntegrationCollectionError> {
    groups.iter().try_fold(0_u64, |total, group| {
        total.checked_add(value(group)).ok_or_else(|| {
            IntegrationCollectionError::new(
                "glitchtip_invalid_response",
                "Числовые агрегаты GlitchTip переполнены.",
            )
        })
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelErrorFacts {
    schema_version: u16,
    observed_groups: u64,
    truncated: bool,
    total_events: u64,
    reported_users: u64,
    groups: Vec<ModelErrorGroupFact>,
}

impl ModelErrorFacts {
    fn from_groups(
        groups: &[ErrorGroupV1],
        truncated: bool,
    ) -> Result<Self, IntegrationCollectionError> {
        Ok(Self {
            schema_version: 1,
            observed_groups: u64::try_from(groups.len()).map_err(|_| {
                IntegrationCollectionError::new(
                    "analysis_input_invalid",
                    "Число агрегатов не помещается в запрос анализа.",
                )
            })?,
            truncated,
            total_events: checked_group_sum(groups, |group| group.event_count)?,
            reported_users: checked_group_sum(groups, |group| group.affected_users)?,
            groups: groups
                .iter()
                .enumerate()
                .map(|(index, group)| ModelErrorGroupFact {
                    rank: u16::try_from(index.saturating_add(1)).unwrap_or(u16::MAX),
                    level: group.level,
                    event_count: group.event_count,
                    reported_users: group.affected_users,
                })
                .collect(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelErrorGroupFact {
    rank: u16,
    level: ErrorLevelV1,
    event_count: u64,
    reported_users: u64,
}

#[derive(Clone)]
struct OpenCodeAnalyzer {
    client: reqwest::Client,
    authorization: HeaderValue,
}

impl OpenCodeAnalyzer {
    async fn analyze(
        &self,
        facts: &[u8],
        input_digest: EvidenceDigest,
        now_ms: i64,
    ) -> Result<ErrorInsightV1, IntegrationCollectionError> {
        let facts = std::str::from_utf8(facts).map_err(|_| {
            IntegrationCollectionError::new(
                "analysis_input_invalid",
                "Агрегаты анализа имеют некорректную кодировку.",
            )
        })?;
        let request = OpenCodeRequest {
            model: OPENCODE_MODEL,
            reasoning_effort: "low",
            max_tokens: 1_024,
            temperature: 0.0,
            response_format: OpenCodeResponseFormat {
                kind: "json_object",
            },
            messages: vec![
                OpenCodeMessage {
                    role: "system",
                    content: "Return one compact JSON object only. Analyze anonymous aggregate error counts. Never infer identities, code, paths, causes, deployment actions, or customer impact. Schema: {\"priority\":\"low|medium|high|critical\",\"summary\":\"one Russian line <= 512 bytes\",\"actions\":[\"0-3 Russian lines, each <= 240 bytes\"]}.",
                },
                OpenCodeMessage {
                    role: "user",
                    content: facts,
                },
            ],
        };
        let body = serde_json::to_vec(&request).map_err(|_| {
            IntegrationCollectionError::new(
                "analysis_request_invalid",
                "Запрос DeepSeek не удалось сформировать.",
            )
        })?;
        let endpoint = fixed_url(OPENCODE_CHAT_URL)?;
        let request = self
            .client
            .post(endpoint)
            .header(AUTHORIZATION, self.authorization.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let (_, response_body) =
            bounded_response(request, MAX_OPENCODE_BODY_BYTES, "opencode").await?;
        let response: OpenCodeResponse = serde_json::from_slice(&response_body).map_err(|_| {
            IntegrationCollectionError::new(
                "opencode_invalid_response",
                "OpenCode вернул неподдерживаемый JSON.",
            )
        })?;
        let content = response
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content)
            .filter(|content| !content.is_empty())
            .ok_or_else(|| {
                IntegrationCollectionError::new(
                    "opencode_invalid_response",
                    "OpenCode не вернул результат анализа.",
                )
            })?;
        let model: ModelInsight = serde_json::from_str(&content).map_err(|_| {
            IntegrationCollectionError::new(
                "opencode_invalid_response",
                "DeepSeek вернул результат вне строгого JSON-контракта.",
            )
        })?;
        let insight = ErrorInsightV1 {
            source: InsightSourceV1::DeepseekV4FlashFree,
            priority: model.priority,
            summary: model.summary,
            actions: model.actions,
            generated_at_ms: now_ms,
            input_digest,
        };
        insight.validate().map_err(|_| {
            IntegrationCollectionError::new(
                "opencode_invalid_response",
                "DeepSeek вернул небезопасный или слишком длинный результат.",
            )
        })?;
        Ok(insight)
    }
}

#[derive(Serialize)]
struct OpenCodeRequest<'a> {
    model: &'static str,
    reasoning_effort: &'static str,
    max_tokens: u16,
    temperature: f32,
    response_format: OpenCodeResponseFormat,
    messages: Vec<OpenCodeMessage<'a>>,
}

#[derive(Serialize)]
struct OpenCodeResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct OpenCodeMessage<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Deserialize)]
struct OpenCodeResponse {
    choices: Vec<OpenCodeChoice>,
}

#[derive(Deserialize)]
struct OpenCodeChoice {
    message: OpenCodeResponseMessage,
}

#[derive(Deserialize)]
struct OpenCodeResponseMessage {
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelInsight {
    priority: InsightPriorityV1,
    summary: String,
    actions: Vec<String>,
}

#[derive(Deserialize)]
struct GlitchTipIssue {
    count: FlexibleU64,
    level: String,
    #[serde(rename = "userCount")]
    user_count: FlexibleU64,
    #[serde(rename = "firstSeen")]
    first_seen: String,
    #[serde(rename = "lastSeen")]
    last_seen: String,
    permalink: String,
    metadata: Option<GlitchTipMetadata>,
}

#[derive(Deserialize)]
struct GlitchTipMetadata {
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FlexibleU64 {
    Number(u64),
    Text(String),
}

impl FlexibleU64 {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(value) => value.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
struct GitHubPull {
    number: u64,
    title: String,
    html_url: String,
    head: GitHubHead,
    base: GitHubBase,
    updated_at: String,
    user: GitHubUser,
    labels: Vec<GitHubLabel>,
}

impl GitHubPull {
    fn is_dependency_update(&self) -> bool {
        self.base.reference == "main"
            && (self.head.reference.starts_with("renovate/")
                || self.user.login.eq_ignore_ascii_case("renovate[bot]")
                || self
                    .labels
                    .iter()
                    .any(|label| label.name.eq_ignore_ascii_case("dependencies")))
    }
}

#[derive(Deserialize)]
struct GitHubHead {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
}

#[derive(Deserialize)]
struct GitHubBase {
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    login: String,
}

#[derive(Deserialize)]
struct GitHubLabel {
    name: String,
}

#[derive(Deserialize)]
struct GitHubCheckRuns {
    check_runs: Vec<GitHubCheckRun>,
}

#[derive(Deserialize)]
struct GitHubCheckRun {
    status: String,
    conclusion: Option<String>,
}

fn classify_check_runs(
    checks: &[GitHubCheckRun],
    response_truncated: bool,
) -> DependencyCheckStateV1 {
    if checks.is_empty() {
        return DependencyCheckStateV1::Unknown;
    }
    let mut pending = false;
    for check in checks {
        if check.status != "completed" || check.conclusion.is_none() {
            pending = true;
            continue;
        }
        match check.conclusion.as_deref() {
            Some("success" | "neutral" | "skipped") => {}
            Some(
                "failure" | "cancelled" | "timed_out" | "action_required" | "startup_failure"
                | "stale",
            ) => return DependencyCheckStateV1::Failing,
            Some(_) | None => pending = true,
        }
    }
    if response_truncated {
        DependencyCheckStateV1::Unknown
    } else if pending {
        DependencyCheckStateV1::Pending
    } else {
        DependencyCheckStateV1::Passing
    }
}

fn parse_error_level(value: &str) -> ErrorLevelV1 {
    match value {
        "debug" => ErrorLevelV1::Debug,
        "info" => ErrorLevelV1::Info,
        "warning" | "warn" => ErrorLevelV1::Warning,
        "error" => ErrorLevelV1::Error,
        "fatal" => ErrorLevelV1::Fatal,
        _ => ErrorLevelV1::Unknown,
    }
}

const fn error_level_rank(level: ErrorLevelV1) -> u8 {
    match level {
        ErrorLevelV1::Unknown => 0,
        ErrorLevelV1::Debug => 1,
        ErrorLevelV1::Info => 2,
        ErrorLevelV1::Warning => 3,
        ErrorLevelV1::Error => 4,
        ErrorLevelV1::Fatal => 5,
    }
}

const fn priority_for_level(level: ErrorLevelV1) -> InsightPriorityV1 {
    match level {
        ErrorLevelV1::Fatal => InsightPriorityV1::Critical,
        ErrorLevelV1::Error => InsightPriorityV1::High,
        ErrorLevelV1::Warning | ErrorLevelV1::Unknown => InsightPriorityV1::Medium,
        ErrorLevelV1::Info | ErrorLevelV1::Debug => InsightPriorityV1::Low,
    }
}

fn valid_safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '.' | '$' | '#')
        })
}

async fn bounded_response(
    request: reqwest::RequestBuilder,
    maximum_bytes: usize,
    provider: &'static str,
) -> Result<(HeaderMap, Vec<u8>), IntegrationCollectionError> {
    let response = request.send().await.map_err(|_| {
        IntegrationCollectionError::new(
            provider_code(provider, "unavailable"),
            provider_detail(provider, "не ответил в установленный срок."),
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(IntegrationCollectionError::new(
            provider_code(provider, "http"),
            provider_detail(provider, &format!("вернул HTTP {}.", status.as_u16())),
        ));
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum_bytes)
    {
        return Err(IntegrationCollectionError::new(
            provider_code(provider, "response_too_large"),
            provider_detail(provider, "вернул слишком большой ответ."),
        ));
    }
    let headers = response.headers().clone();
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            IntegrationCollectionError::new(
                provider_code(provider, "unavailable"),
                provider_detail(provider, "оборвал ответ."),
            )
        })?;
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(IntegrationCollectionError::new(
                provider_code(provider, "response_too_large"),
                provider_detail(provider, "вернул слишком большой ответ."),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((headers, body))
}

fn provider_code(provider: &'static str, reason: &'static str) -> &'static str {
    match (provider, reason) {
        ("glitchtip", "unavailable") => "glitchtip_unavailable",
        ("glitchtip", "http") => "glitchtip_http",
        ("glitchtip", "response_too_large") => "glitchtip_response_too_large",
        ("opencode", "unavailable") => "opencode_unavailable",
        ("opencode", "http") => "opencode_http",
        ("opencode", "response_too_large") => "opencode_response_too_large",
        ("github", "unavailable") => "github_unavailable",
        ("github", "http") => "github_http",
        ("github", "response_too_large") => "github_response_too_large",
        _ => "integration_unavailable",
    }
}

fn provider_detail(provider: &str, suffix: &str) -> String {
    let name = match provider {
        "glitchtip" => "GlitchTip",
        "opencode" => "OpenCode",
        "github" => "GitHub",
        _ => "Источник интеграции",
    };
    format!("{name} {suffix}")
}

fn has_next_page(headers: &HeaderMap) -> bool {
    headers
        .get_all(LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|link| {
            let is_next = link.contains("rel=\"next\"") || link.contains("rel=next");
            let results_are_false =
                link.contains("results=\"false\"") || link.contains("results=false");
            is_next && !results_are_false
        })
}

fn fixed_url(value: &str) -> Result<Url, IntegrationCollectionError> {
    let url = Url::parse(value).map_err(|_| {
        IntegrationCollectionError::new(
            "integration_configuration_invalid",
            "Встроенный адрес интеграции некорректен.",
        )
    })?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(IntegrationCollectionError::new(
            "integration_configuration_invalid",
            "Встроенный адрес интеграции нарушает HTTPS-контракт.",
        ));
    }
    Ok(url)
}

fn valid_credential_directory(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<std::path::PathBuf>() == path
}

fn read_optional_credential(
    directory: Option<&Path>,
    name: &'static str,
) -> Result<Option<String>, IntegrationCollectorConfigError> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let path = directory.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(IntegrationCollectorConfigError::CredentialRead(name, error)),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(IntegrationCollectorConfigError::InvalidCredential(name));
    }
    let bytes = fs::read(&path)
        .map_err(|error| IntegrationCollectorConfigError::CredentialRead(name, error))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| IntegrationCollectorConfigError::InvalidCredential(name))?
        .trim_end_matches(['\r', '\n']);
    if value.is_empty()
        || value.len() > usize::try_from(MAX_CREDENTIAL_BYTES).unwrap_or(usize::MAX)
        || value != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(IntegrationCollectorConfigError::InvalidCredential(name));
    }
    Ok(Some(value.to_owned()))
}

fn authorization_header(
    scheme: &'static str,
    token: &str,
) -> Result<HeaderValue, IntegrationCollectorConfigError> {
    let mut value = HeaderValue::from_str(&format!("{scheme} {token}"))
        .map_err(|_| IntegrationCollectorConfigError::InvalidAuthorizationCredential)?;
    value.set_sensitive(true);
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationCollectionError {
    code: &'static str,
    detail: String,
}

impl IntegrationCollectionError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn into_failure(self) -> IntegrationFailureV1 {
        IntegrationFailureV1::new(self.code, self.detail).unwrap_or_else(|_| IntegrationFailureV1 {
            code: "integration_failure_invalid".to_owned(),
            detail: "Сбой интеграции не удалось представить безопасно.".to_owned(),
        })
    }
}

impl std::fmt::Display for IntegrationCollectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for IntegrationCollectionError {}

#[derive(Debug, thiserror::Error)]
pub enum IntegrationCollectorConfigError {
    #[error("integration collection timeout must be non-zero")]
    ZeroTimeout,
    #[error("CREDENTIALS_DIRECTORY must be an absolute normalized path")]
    InvalidCredentialDirectory,
    #[error("credential {0} could not be read: {1}")]
    CredentialRead(&'static str, std::io::Error),
    #[error("credential {0} must be a bounded regular UTF-8 file")]
    InvalidCredential(&'static str),
    #[error("provider authorization credential is invalid")]
    InvalidAuthorizationCredential,
    #[error("integration HTTP client could not be created")]
    HttpClient,
    #[error("fixed integration project ID is invalid")]
    InternalProjectId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_json() -> &'static str {
        r#"[
          {
            "id": "raw-secret-id",
            "title": "customer@example.com /srv/private/payment.rs",
            "culprit": "payments::capture secret-marker",
            "count": "9",
            "level": "error",
            "userCount": 3,
            "firstSeen": "2026-07-19T10:00:00Z",
            "lastSeen": "2026-07-19T11:00:00Z",
            "permalink": "https://glitchtip.4u.ge/organizations/4u/issues/42/",
            "metadata": {"type": "Database::Busy"}
          }
        ]"#
    }

    fn live_test_collectors(
        glitchtip: &str,
        opencode: &str,
        github: &str,
    ) -> ProjectIntegrationCollectors {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20))
            .user_agent("rdashboard-integration-live-test/1")
            .build()
            .expect("client");
        ProjectIntegrationCollectors {
            project_id: ProjectId::from_str(PROJECT_ID).expect("project"),
            client,
            collection_deadline: Duration::from_secs(20),
            glitchtip_authorization: Some(
                authorization_header("Bearer", glitchtip).expect("GlitchTip header"),
            ),
            opencode_authorization: Some(
                authorization_header("Bearer", opencode).expect("OpenCode header"),
            ),
            github_authorization: Some(
                authorization_header("Bearer", github).expect("GitHub header"),
            ),
        }
    }

    #[test]
    fn model_packet_is_structurally_anonymous() {
        let issues: Vec<GlitchTipIssue> =
            serde_json::from_str(issue_json()).unwrap_or_else(|error| panic!("issues: {error}"));
        let page =
            ErrorPage::from_issues(issues, false).unwrap_or_else(|error| panic!("page: {error}"));
        assert_eq!(page.groups[0].safe_label, "Database::Busy");
        let facts = ModelErrorFacts::from_groups(&page.groups, false)
            .unwrap_or_else(|error| panic!("facts: {error}"));
        let encoded =
            serde_json::to_string(&facts).unwrap_or_else(|error| panic!("encode facts: {error}"));
        for forbidden in [
            "raw-secret-id",
            "customer@example.com",
            "/srv/private",
            "secret-marker",
            "Database::Busy",
            "issues/42",
        ] {
            assert!(!encoded.contains(forbidden), "leaked {forbidden}");
        }
        assert!(encoded.contains("\"event_count\":9"));
    }

    #[tokio::test]
    async fn empty_page_is_deterministic_without_analyzer() {
        let data = assemble_errors(
            ProjectId::from_str(PROJECT_ID).expect("project"),
            ErrorPage {
                groups: Vec::new(),
                truncated: false,
            },
            None,
            10,
        )
        .await
        .unwrap_or_else(|error| panic!("empty errors: {error}"));
        assert_eq!(data.unresolved_groups, 0);
        assert_eq!(data.insight.source, InsightSourceV1::Deterministic);
        assert_eq!(data.insight.priority, InsightPriorityV1::None);
        assert!(data.analysis_error.is_none());
    }

    #[test]
    fn check_state_does_not_imply_unobserved_success() {
        assert_eq!(
            classify_check_runs(&[], false),
            DependencyCheckStateV1::Unknown
        );
        assert_eq!(
            classify_check_runs(
                &[GitHubCheckRun {
                    status: "in_progress".to_owned(),
                    conclusion: None,
                }],
                false
            ),
            DependencyCheckStateV1::Pending
        );
        assert_eq!(
            classify_check_runs(
                &[
                    GitHubCheckRun {
                        status: "completed".to_owned(),
                        conclusion: Some("success".to_owned()),
                    },
                    GitHubCheckRun {
                        status: "completed".to_owned(),
                        conclusion: Some("failure".to_owned()),
                    },
                ],
                false
            ),
            DependencyCheckStateV1::Failing
        );
        assert_eq!(
            classify_check_runs(
                &[GitHubCheckRun {
                    status: "completed".to_owned(),
                    conclusion: Some("success".to_owned()),
                }],
                true,
            ),
            DependencyCheckStateV1::Unknown
        );
    }

    #[test]
    fn dependency_updates_are_defensively_bound_to_main() {
        let parse = |base: &str| {
            serde_json::from_value::<GitHubPull>(serde_json::json!({
                "number": 42,
                "title": "Update dependency",
                "html_url": "https://github.com/mrDenai/rimg/pull/42",
                "head": {
                    "ref": "renovate/example-1.x",
                    "sha": "0123456789abcdef0123456789abcdef01234567"
                },
                "base": { "ref": base },
                "updated_at": "2026-07-19T11:00:00Z",
                "user": { "login": "renovate[bot]" },
                "labels": []
            }))
            .expect("pull")
        };
        assert!(parse("main").is_dependency_update());
        assert!(!parse("release").is_dependency_update());
    }

    #[test]
    fn sentry_pagination_does_not_treat_an_empty_next_cursor_as_data() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static(
                "<https://example.invalid/prev>; rel=\"previous\"; results=\"false\", <https://example.invalid/next>; rel=\"next\"; results=\"false\"",
            ),
        );
        assert!(!has_next_page(&headers));
        headers.insert(
            LINK,
            HeaderValue::from_static(
                "<https://example.invalid/next>; rel=\"next\"; results=\"true\"",
            ),
        );
        assert!(has_next_page(&headers));
    }

    #[test]
    fn credential_directory_rejects_symlinked_tokens() {
        let directory = tempfile::tempdir().expect("directory");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("missing", directory.path().join(GLITCHTIP_CREDENTIAL))
                .expect("symlink");
            assert!(matches!(
                read_optional_credential(Some(directory.path()), GLITCHTIP_CREDENTIAL),
                Err(IntegrationCollectorConfigError::InvalidCredential(
                    GLITCHTIP_CREDENTIAL
                ))
            ));
        }
    }

    #[tokio::test]
    #[ignore = "uses operator credentials and live read-only providers"]
    async fn live_project_four_and_rimg_metadata_follow_the_bounded_contracts() {
        let glitchtip = std::env::var("GLITCHTIP_TOKEN").expect("GLITCHTIP_TOKEN");
        let opencode = std::env::var("DEEPSEEK_FREE_KEY").expect("DEEPSEEK_FREE_KEY");
        let output = std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .expect("gh auth token");
        assert!(output.status.success(), "gh auth token failed");
        let github = std::str::from_utf8(&output.stdout)
            .expect("GitHub token UTF-8")
            .trim();
        let collectors = live_test_collectors(&glitchtip, &opencode, github);
        let now_ms = crate::unix_time_ms().expect("clock");
        let (errors, updates) = tokio::join!(
            collectors.collect_errors(now_ms),
            collectors.collect_updates(now_ms),
        );
        let errors = errors.unwrap_or_else(|error| panic!("live errors: {error}"));
        let updates = updates.unwrap_or_else(|error| panic!("live updates: {error}"));
        errors.validate().expect("errors contract");
        updates.validate().expect("updates contract");
        assert_eq!(errors.project_id.as_str(), PROJECT_ID);
        assert_eq!(updates.project_id.as_str(), PROJECT_ID);
        if errors.unresolved_groups == 0 {
            assert_eq!(errors.insight.source, InsightSourceV1::Deterministic);
            assert!(errors.analysis_error.is_none());
        }
    }

    #[tokio::test]
    #[ignore = "uses the operator OpenCode credential and live read-only model route"]
    async fn live_deepseek_accepts_only_the_anonymous_fact_contract() {
        let opencode = std::env::var("DEEPSEEK_FREE_KEY").expect("DEEPSEEK_FREE_KEY");
        let collectors = live_test_collectors("unused", &opencode, "unused");
        let groups = vec![ErrorGroupV1 {
            safe_label: "Database::Busy".to_owned(),
            level: ErrorLevelV1::Error,
            event_count: 9,
            affected_users: 3,
            first_seen: "2026-07-19T10:00:00Z".to_owned(),
            last_seen: "2026-07-19T11:00:00Z".to_owned(),
            deep_link: "https://glitchtip.4u.ge/organizations/4u/issues/42/".to_owned(),
        }];
        let facts = ModelErrorFacts::from_groups(&groups, false).expect("facts");
        let encoded = serde_jcs::to_vec(&facts).expect("encode");
        let analyzer = OpenCodeAnalyzer {
            client: collectors.client,
            authorization: collectors.opencode_authorization.expect("OpenCode header"),
        };
        let insight = analyzer
            .analyze(
                &encoded,
                EvidenceDigest::sha256(&encoded),
                crate::unix_time_ms().expect("clock"),
            )
            .await
            .unwrap_or_else(|error| panic!("live DeepSeek: {error}"));
        assert_eq!(insight.source, InsightSourceV1::DeepseekV4FlashFree);
        insight.validate().expect("insight contract");
    }
}
