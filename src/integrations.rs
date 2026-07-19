use serde::{Deserialize, Serialize};

use crate::domain::{EvidenceDigest, GitCommitId, ProjectId};

pub const PROJECT_INTEGRATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_ERROR_GROUPS: usize = 20;
pub const MAX_DEPENDENCY_UPDATES: usize = 50;
pub const MAX_BROWSER_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_BROWSER_SAFE_TIMESTAMP: i64 = 9_007_199_254_740_991;
const MAX_SAFE_LABEL_BYTES: usize = 96;
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_ACTION_BYTES: usize = 240;
const MAX_ACTIONS: usize = 3;
const MAX_FAILURE_DETAIL_BYTES: usize = 240;
const MAX_FAILURE_CODE_BYTES: usize = 64;
const MAX_UPDATE_TITLE_BYTES: usize = 240;
const MAX_HEAD_REF_BYTES: usize = 160;
const MAX_TIMESTAMP_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKindV1 {
    Errors,
    Updates,
}

impl IntegrationKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Errors => "errors",
            Self::Updates => "updates",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationFailureV1 {
    pub code: String,
    pub detail: String,
}

impl IntegrationFailureV1 {
    pub fn new(
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, IntegrationContractError> {
        let failure = Self {
            code: code.into(),
            detail: detail.into(),
        };
        failure.validate()?;
        Ok(failure)
    }

    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        if !bounded_token(&self.code, MAX_FAILURE_CODE_BYTES)
            || !bounded_display_text(&self.detail, MAX_FAILURE_DETAIL_BYTES)
        {
            return Err(IntegrationContractError::InvalidFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorLevelV1 {
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightPriorityV1 {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightSourceV1 {
    Deterministic,
    DeepseekV4FlashFree,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorInsightV1 {
    pub source: InsightSourceV1,
    pub priority: InsightPriorityV1,
    pub summary: String,
    pub actions: Vec<String>,
    pub generated_at_ms: i64,
    pub input_digest: EvidenceDigest,
}

impl ErrorInsightV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        if !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&self.generated_at_ms)
            || !bounded_display_text(&self.summary, MAX_SUMMARY_BYTES)
            || self.actions.len() > MAX_ACTIONS
            || self
                .actions
                .iter()
                .any(|action| !bounded_display_text(action, MAX_ACTION_BYTES))
        {
            return Err(IntegrationContractError::InvalidInsight);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorGroupV1 {
    pub safe_label: String,
    pub level: ErrorLevelV1,
    pub event_count: u64,
    pub affected_users: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub deep_link: String,
}

impl ErrorGroupV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        if !bounded_safe_label(&self.safe_label)
            || self.event_count == 0
            || self.event_count > MAX_BROWSER_SAFE_INTEGER
            || self.affected_users > MAX_BROWSER_SAFE_INTEGER
            || !bounded_timestamp(&self.first_seen)
            || !bounded_timestamp(&self.last_seen)
            || !valid_https_link(&self.deep_link, "glitchtip.4u.ge")
        {
            return Err(IntegrationContractError::InvalidErrorGroup);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectErrorsDataV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub unresolved_groups: u64,
    /// `true` when `GlitchTip` advertised another page beyond the bounded set below.
    pub truncated: bool,
    pub total_events: u64,
    pub affected_users: u64,
    pub highest_level: ErrorLevelV1,
    pub groups: Vec<ErrorGroupV1>,
    pub insight: ErrorInsightV1,
    pub analysis_error: Option<IntegrationFailureV1>,
}

impl ProjectErrorsDataV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        let observed_groups = u64::try_from(self.groups.len())
            .map_err(|_| IntegrationContractError::InvalidErrorsData)?;
        if self.schema_version != PROJECT_INTEGRATION_SCHEMA_VERSION
            || self.groups.len() > MAX_ERROR_GROUPS
            || self.unresolved_groups != observed_groups
        {
            return Err(IntegrationContractError::InvalidErrorsData);
        }
        let mut total_events = 0_u64;
        let mut affected_users = 0_u64;
        let mut highest_level = ErrorLevelV1::Unknown;
        for group in &self.groups {
            group.validate()?;
            total_events = total_events
                .checked_add(group.event_count)
                .filter(|total| *total <= MAX_BROWSER_SAFE_INTEGER)
                .ok_or(IntegrationContractError::InvalidErrorsData)?;
            affected_users = affected_users
                .checked_add(group.affected_users)
                .filter(|total| *total <= MAX_BROWSER_SAFE_INTEGER)
                .ok_or(IntegrationContractError::InvalidErrorsData)?;
            if error_level_rank(group.level) > error_level_rank(highest_level) {
                highest_level = group.level;
            }
        }
        if self.total_events != total_events
            || self.affected_users != affected_users
            || self.highest_level != highest_level
        {
            return Err(IntegrationContractError::InvalidErrorsData);
        }
        self.insight.validate()?;
        if let Some(failure) = &self.analysis_error {
            failure.validate()?;
        }
        if self.unresolved_groups == 0
            && (self.total_events != 0
                || self.affected_users != 0
                || self.truncated
                || !self.groups.is_empty()
                || self.highest_level != ErrorLevelV1::Unknown
                || self.insight.source != InsightSourceV1::Deterministic
                || self.analysis_error.is_some())
        {
            return Err(IntegrationContractError::InvalidErrorsData);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyCheckStateV1 {
    Passing,
    Pending,
    Failing,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyUpdateV1 {
    pub number: u64,
    pub title: String,
    pub head_ref: String,
    pub head: GitCommitId,
    pub updated_at: String,
    pub deep_link: String,
    pub check_state: DependencyCheckStateV1,
}

impl DependencyUpdateV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        if self.number == 0
            || self.number > MAX_BROWSER_SAFE_INTEGER
            || !bounded_display_text(&self.title, MAX_UPDATE_TITLE_BYTES)
            || !bounded_ref(&self.head_ref)
            || !bounded_timestamp(&self.updated_at)
            || !valid_https_link(&self.deep_link, "github.com")
        {
            return Err(IntegrationContractError::InvalidDependencyUpdate);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUpdatesDataV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    /// `true` when GitHub advertised another page beyond the bounded set below.
    pub truncated: bool,
    pub updates: Vec<DependencyUpdateV1>,
}

impl ProjectUpdatesDataV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        if self.schema_version != PROJECT_INTEGRATION_SCHEMA_VERSION
            || self.updates.len() > MAX_DEPENDENCY_UPDATES
        {
            return Err(IntegrationContractError::InvalidUpdatesData);
        }
        for update in &self.updates {
            update.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectErrorsRecordV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub attempted_at_ms: i64,
    pub successful_at_ms: Option<i64>,
    pub collection_error: Option<IntegrationFailureV1>,
    pub data: Option<ProjectErrorsDataV1>,
}

impl ProjectErrorsRecordV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_record_shape(
            self.schema_version,
            self.attempted_at_ms,
            self.successful_at_ms,
            self.collection_error.as_ref(),
            self.data.is_some(),
        )?;
        if let Some(data) = &self.data {
            data.validate()?;
            if data.project_id != self.project_id {
                return Err(IntegrationContractError::ProjectBinding);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUpdatesRecordV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub attempted_at_ms: i64,
    pub successful_at_ms: Option<i64>,
    pub collection_error: Option<IntegrationFailureV1>,
    pub data: Option<ProjectUpdatesDataV1>,
}

impl ProjectUpdatesRecordV1 {
    pub fn validate(&self) -> Result<(), IntegrationContractError> {
        validate_record_shape(
            self.schema_version,
            self.attempted_at_ms,
            self.successful_at_ms,
            self.collection_error.as_ref(),
            self.data.is_some(),
        )?;
        if let Some(data) = &self.data {
            data.validate()?;
            if data.project_id != self.project_id {
                return Err(IntegrationContractError::ProjectBinding);
            }
        }
        Ok(())
    }
}

fn validate_record_shape(
    schema_version: u16,
    attempted_at_ms: i64,
    successful_at_ms: Option<i64>,
    failure: Option<&IntegrationFailureV1>,
    has_data: bool,
) -> Result<(), IntegrationContractError> {
    if schema_version != PROJECT_INTEGRATION_SCHEMA_VERSION
        || !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&attempted_at_ms)
        || successful_at_ms.is_some_and(|success| {
            !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&success) || success > attempted_at_ms
        })
        || successful_at_ms.is_some() != has_data
        || (failure.is_none() && successful_at_ms != Some(attempted_at_ms))
    {
        return Err(IntegrationContractError::InvalidRecord);
    }
    if let Some(failure) = failure {
        failure.validate()?;
    }
    Ok(())
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

fn bounded_safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SAFE_LABEL_BYTES
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '.' | '$' | '#')
        })
}

fn bounded_display_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= maximum_bytes
        && !value.chars().any(char::is_control)
}

fn bounded_token(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn bounded_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && value.is_ascii()
        && value.contains('T')
        && (value.ends_with('Z') || value.contains('+'))
}

fn bounded_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEAD_REF_BYTES
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn valid_https_link(value: &str, required_host: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some(required_host)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IntegrationContractError {
    #[error("integration failure metadata is invalid")]
    InvalidFailure,
    #[error("error insight is invalid")]
    InvalidInsight,
    #[error("error group aggregate is invalid")]
    InvalidErrorGroup,
    #[error("project error aggregate is invalid")]
    InvalidErrorsData,
    #[error("dependency update aggregate is invalid")]
    InvalidDependencyUpdate,
    #[error("project dependency update aggregate is invalid")]
    InvalidUpdatesData,
    #[error("project integration record is invalid")]
    InvalidRecord,
    #[error("project integration payload does not match its record project")]
    ProjectBinding,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> ProjectId {
        "rimg"
            .parse()
            .unwrap_or_else(|error| panic!("project: {error}"))
    }

    fn digest() -> EvidenceDigest {
        EvidenceDigest::sha256("safe aggregate facts")
    }

    fn empty_errors() -> ProjectErrorsDataV1 {
        ProjectErrorsDataV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project(),
            unresolved_groups: 0,
            truncated: false,
            total_events: 0,
            affected_users: 0,
            highest_level: ErrorLevelV1::Unknown,
            groups: Vec::new(),
            insight: ErrorInsightV1 {
                source: InsightSourceV1::Deterministic,
                priority: InsightPriorityV1::None,
                summary: "Открытых ошибок нет.".to_owned(),
                actions: Vec::new(),
                generated_at_ms: 10,
                input_digest: digest(),
            },
            analysis_error: None,
        }
    }

    #[test]
    fn empty_error_contract_is_strict_and_deterministic() {
        empty_errors()
            .validate()
            .unwrap_or_else(|error| panic!("valid empty errors: {error}"));
        let mut invalid = empty_errors();
        invalid.insight.source = InsightSourceV1::DeepseekV4FlashFree;
        assert_eq!(
            invalid.validate(),
            Err(IntegrationContractError::InvalidErrorsData)
        );
    }

    #[test]
    fn safe_labels_cannot_smuggle_display_text() {
        assert!(bounded_safe_label("Database::Busy"));
        for invalid in ["", "user@example.com", "/private/path", "Error message"] {
            assert!(!bounded_safe_label(invalid));
        }
    }

    #[test]
    fn records_preserve_last_success_only_with_data() {
        let record = ProjectErrorsRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project(),
            attempted_at_ms: 20,
            successful_at_ms: Some(10),
            collection_error: Some(
                IntegrationFailureV1::new("timeout", "Источник не ответил.")
                    .unwrap_or_else(|error| panic!("failure: {error}")),
            ),
            data: Some(empty_errors()),
        };
        record
            .validate()
            .unwrap_or_else(|error| panic!("last-known record: {error}"));
        let mut invalid = record;
        invalid.data = None;
        assert_eq!(
            invalid.validate(),
            Err(IntegrationContractError::InvalidRecord)
        );
    }

    #[test]
    fn error_aggregates_must_match_groups_and_browser_integer_limits() {
        let mut invalid = empty_errors();
        invalid.groups.push(ErrorGroupV1 {
            safe_label: "ApplicationError".to_owned(),
            level: ErrorLevelV1::Error,
            event_count: 1,
            affected_users: 0,
            first_seen: "2026-07-19T10:00:00Z".to_owned(),
            last_seen: "2026-07-19T11:00:00Z".to_owned(),
            deep_link: "https://glitchtip.4u.ge/organizations/4u/issues/42/".to_owned(),
        });
        invalid.unresolved_groups = 1;
        invalid.total_events = 1;
        invalid.highest_level = ErrorLevelV1::Warning;
        assert_eq!(
            invalid.validate(),
            Err(IntegrationContractError::InvalidErrorsData)
        );

        invalid.highest_level = ErrorLevelV1::Error;
        invalid.groups[0].event_count = MAX_BROWSER_SAFE_INTEGER + 1;
        assert_eq!(
            invalid.validate(),
            Err(IntegrationContractError::InvalidErrorGroup)
        );
    }
}
