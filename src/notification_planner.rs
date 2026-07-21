use serde::Serialize;

use crate::{
    integrations::{
        DependencyCheckStateV1, DependencyUpdateV1, ErrorLevelV1, InsightPriorityV1,
        ProjectErrorsDataV1, ProjectErrorsRecordV1, ProjectUpdatesRecordV1,
    },
    notifications::{NotificationContractError, NotificationEventV1, NotificationKindV1},
};

pub fn plan_error_notifications(
    previous: Option<&ProjectErrorsRecordV1>,
    current: &ProjectErrorsRecordV1,
) -> Result<Vec<NotificationEventV1>, NotificationPlanningError> {
    current.validate()?;
    validate_project(&current.project_id)?;
    if let Some(previous) = previous {
        previous.validate()?;
        if previous.project_id != current.project_id {
            return Err(NotificationPlanningError::ProjectMismatch);
        }
    }
    let mut events = Vec::new();
    let previous_failure = previous.and_then(|record| record.collection_error.as_ref());
    match (previous_failure, current.collection_error.as_ref()) {
        (None, Some(failure)) if !is_unconfigured(&failure.code) => {
            events.push(error_collection_failed(current, &failure.code)?);
        }
        (Some(previous_failure), None) if !is_unconfigured(&previous_failure.code) => {
            events.push(NotificationEventV1::new(
                current.project_id.clone(),
                NotificationKindV1::ErrorCollectionRecovered,
                "rdashboard.rimg.errors.collection",
                &format!("errors-recovered:{}", current.attempted_at_ms),
                "rimg: сбор ошибок восстановлен",
                current.attempted_at_ms,
            )?);
        }
        (Some(previous), Some(current_failure))
            if previous.code != current_failure.code && !is_unconfigured(&current_failure.code) =>
        {
            events.push(error_collection_failed(current, &current_failure.code)?);
        }
        _ => {}
    }

    let previous_priority = previous
        .and_then(|record| record.data.as_ref())
        .map(deterministic_priority);
    if let Some(data) = current.data.as_ref() {
        let current_priority = deterministic_priority(data);
        let meaningful = current_priority != InsightPriorityV1::None
            || previous_priority.is_some_and(|priority| priority != InsightPriorityV1::None);
        if previous_priority != Some(current_priority) && meaningful {
            let priority = priority_name(current_priority);
            let text = if current_priority == InsightPriorityV1::None {
                "rimg: приоритет ошибок снят".to_owned()
            } else {
                format!("rimg: приоритет ошибок — {priority}")
            };
            events.push(NotificationEventV1::new(
                current.project_id.clone(),
                NotificationKindV1::ErrorPriorityChanged,
                "rdashboard.rimg.errors.priority",
                &format!(
                    "errors-priority:{}:{priority}:{}",
                    data.insight.input_digest, current.attempted_at_ms
                ),
                text,
                current.attempted_at_ms,
            )?);
        }
    }
    Ok(events)
}

fn error_collection_failed(
    current: &ProjectErrorsRecordV1,
    code: &str,
) -> Result<NotificationEventV1, NotificationPlanningError> {
    Ok(NotificationEventV1::new(
        current.project_id.clone(),
        NotificationKindV1::ErrorCollectionFailed,
        "rdashboard.rimg.errors.collection",
        &format!(
            "errors-failed:{}:{code}:{}",
            current.successful_at_ms.map_or(0, |value| value),
            current.attempted_at_ms
        ),
        format!("rimg: сбор ошибок недоступен ({code})"),
        current.attempted_at_ms,
    )?)
}

pub fn plan_update_notifications(
    previous: Option<&ProjectUpdatesRecordV1>,
    current: &ProjectUpdatesRecordV1,
) -> Result<Vec<NotificationEventV1>, NotificationPlanningError> {
    current.validate()?;
    validate_project(&current.project_id)?;
    if let Some(previous) = previous {
        previous.validate()?;
        if previous.project_id != current.project_id {
            return Err(NotificationPlanningError::ProjectMismatch);
        }
    }
    let mut events = Vec::new();
    let previous_failure = previous.and_then(|record| record.collection_error.as_ref());
    match (previous_failure, current.collection_error.as_ref()) {
        (None, Some(failure)) if !is_unconfigured(&failure.code) => {
            events.push(update_collection_failed(current, &failure.code)?);
        }
        (Some(previous_failure), None) if !is_unconfigured(&previous_failure.code) => {
            events.push(NotificationEventV1::new(
                current.project_id.clone(),
                NotificationKindV1::DependencyCollectionRecovered,
                "rdashboard.rimg.updates.collection",
                &format!("updates-recovered:{}", current.attempted_at_ms),
                "rimg: сбор обновлений восстановлен",
                current.attempted_at_ms,
            )?);
        }
        (Some(previous), Some(current_failure))
            if previous.code != current_failure.code && !is_unconfigured(&current_failure.code) =>
        {
            events.push(update_collection_failed(current, &current_failure.code)?);
        }
        _ => {}
    }

    let current_updates = current.data.as_ref().map(|data| &data.updates);
    let previous_updates = previous
        .and_then(|record| record.data.as_ref())
        .map(|data| &data.updates);
    if let Some(current_updates) = current_updates {
        let current_digest = update_digest(current_updates)?;
        let previous_digest = previous_updates
            .map(|updates| update_digest(updates))
            .transpose()?;
        let previous_had_updates = previous_updates.is_some_and(|updates| !updates.is_empty());
        if previous_digest.as_ref() != Some(&current_digest)
            && (!current_updates.is_empty() || previous_had_updates)
        {
            let text = if current_updates.is_empty() {
                "rimg: обновления зависимостей закрыты".to_owned()
            } else {
                format!(
                    "rimg: открыто обновлений зависимостей: {}",
                    current_updates.len()
                )
            };
            events.push(NotificationEventV1::new(
                current.project_id.clone(),
                NotificationKindV1::DependencyUpdateChanged,
                "rdashboard.rimg.updates",
                &format!("updates:{current_digest}:{}", current.attempted_at_ms),
                text,
                current.attempted_at_ms,
            )?);
        }

        let current_failing = failing_digest(current_updates)?;
        let previous_failing = previous_updates
            .map(|updates| failing_digest(updates))
            .transpose()?
            .flatten();
        match (previous_failing.as_ref(), current_failing.as_ref()) {
            (previous, Some((count, digest)))
                if previous.is_none_or(|value| value != &(*count, digest.clone())) =>
            {
                events.push(NotificationEventV1::new(
                    current.project_id.clone(),
                    NotificationKindV1::DependencyChecksFailed,
                    "rdashboard.rimg.updates.checks",
                    &format!("checks-failed:{digest}:{}", current.attempted_at_ms),
                    format!("rimg: проверки не прошли для обновлений: {count}"),
                    current.attempted_at_ms,
                )?);
            }
            (Some((_, previous_digest)), None) => {
                events.push(NotificationEventV1::new(
                    current.project_id.clone(),
                    NotificationKindV1::DependencyChecksRecovered,
                    "rdashboard.rimg.updates.checks",
                    &format!(
                        "checks-recovered:{previous_digest}:{}",
                        current.attempted_at_ms
                    ),
                    "rimg: проверки обновлений восстановлены",
                    current.attempted_at_ms,
                )?);
            }
            _ => {}
        }
    }
    Ok(events)
}

fn update_collection_failed(
    current: &ProjectUpdatesRecordV1,
    code: &str,
) -> Result<NotificationEventV1, NotificationPlanningError> {
    Ok(NotificationEventV1::new(
        current.project_id.clone(),
        NotificationKindV1::DependencyCollectionFailed,
        "rdashboard.rimg.updates.collection",
        &format!(
            "updates-failed:{}:{code}:{}",
            current.successful_at_ms.map_or(0, |value| value),
            current.attempted_at_ms
        ),
        format!("rimg: сбор обновлений недоступен ({code})"),
        current.attempted_at_ms,
    )?)
}

fn update_digest(updates: &[DependencyUpdateV1]) -> Result<String, NotificationPlanningError> {
    let mut facts: Vec<_> = updates
        .iter()
        .map(|update| (update.number, update.head.as_str()))
        .collect();
    facts.sort_unstable();
    structural_digest(&facts)
}

fn failing_digest(
    updates: &[DependencyUpdateV1],
) -> Result<Option<(usize, String)>, NotificationPlanningError> {
    let mut failing: Vec<_> = updates
        .iter()
        .filter(|update| update.check_state == DependencyCheckStateV1::Failing)
        .map(|update| (update.number, update.head.as_str()))
        .collect();
    failing.sort_unstable();
    if failing.is_empty() {
        Ok(None)
    } else {
        Ok(Some((failing.len(), structural_digest(&failing)?)))
    }
}

fn structural_digest(value: &impl Serialize) -> Result<String, NotificationPlanningError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| NotificationPlanningError::Encoding)?;
    Ok(crate::domain::EvidenceDigest::sha256(bytes).to_string())
}

fn deterministic_priority(data: &ProjectErrorsDataV1) -> InsightPriorityV1 {
    if data.unresolved_groups == 0 {
        return InsightPriorityV1::None;
    }
    match data.highest_level {
        ErrorLevelV1::Fatal => InsightPriorityV1::Critical,
        ErrorLevelV1::Error => InsightPriorityV1::High,
        ErrorLevelV1::Warning | ErrorLevelV1::Unknown => InsightPriorityV1::Medium,
        ErrorLevelV1::Info | ErrorLevelV1::Debug => InsightPriorityV1::Low,
    }
}

fn validate_project(
    project_id: &crate::domain::ProjectId,
) -> Result<(), NotificationPlanningError> {
    if project_id.as_str() != "rimg" {
        return Err(NotificationPlanningError::UnsupportedProject);
    }
    Ok(())
}

fn is_unconfigured(code: &str) -> bool {
    code.ends_with("_not_configured")
}

const fn priority_name(priority: InsightPriorityV1) -> &'static str {
    match priority {
        InsightPriorityV1::None => "none",
        InsightPriorityV1::Low => "low",
        InsightPriorityV1::Medium => "medium",
        InsightPriorityV1::High => "high",
        InsightPriorityV1::Critical => "critical",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationPlanningError {
    #[error("notification source integration contract is invalid: {0}")]
    Integration(#[from] crate::integrations::IntegrationContractError),
    #[error("notification event contract is invalid: {0}")]
    Notification(#[from] NotificationContractError),
    #[error("notification transition joins different projects")]
    ProjectMismatch,
    #[error("notification planning supports only the fixed rimg project")]
    UnsupportedProject,
    #[error("notification transition digest could not be encoded")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::{EvidenceDigest, GitCommitId, ProjectId},
        integrations::{
            DependencyUpdateV1, ErrorGroupV1, ErrorInsightV1, ErrorLevelV1, InsightSourceV1,
            IntegrationFailureV1, PROJECT_INTEGRATION_SCHEMA_VERSION, ProjectErrorsDataV1,
            ProjectUpdatesDataV1,
        },
    };

    use super::*;

    fn project() -> ProjectId {
        "rimg".parse().expect("project")
    }

    fn errors(priority: InsightPriorityV1, at: i64) -> ProjectErrorsRecordV1 {
        ProjectErrorsRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project(),
            attempted_at_ms: at,
            successful_at_ms: Some(at),
            collection_error: None,
            data: Some(ProjectErrorsDataV1 {
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
                    priority,
                    summary: "No unresolved errors.".to_owned(),
                    actions: Vec::new(),
                    generated_at_ms: at,
                    input_digest: EvidenceDigest::sha256(format!("facts:{at}")),
                },
                analysis_error: None,
            }),
        }
    }

    fn updates(state: DependencyCheckStateV1, at: i64) -> ProjectUpdatesRecordV1 {
        ProjectUpdatesRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project(),
            attempted_at_ms: at,
            successful_at_ms: Some(at),
            collection_error: None,
            data: Some(ProjectUpdatesDataV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: project(),
                truncated: false,
                updates: vec![DependencyUpdateV1 {
                    number: 1,
                    title: "Update dependency".to_owned(),
                    head_ref: "renovate/dependency".to_owned(),
                    head: "0123456789abcdef0123456789abcdef01234567"
                        .parse::<GitCommitId>()
                        .expect("head"),
                    updated_at: "2026-07-19T00:00:00Z".to_owned(),
                    deep_link: "https://github.com/mrDenai/rimg/pull/1".to_owned(),
                    check_state: state,
                }],
            }),
        }
    }

    fn nonempty_errors(
        model_priority: InsightPriorityV1,
        level: ErrorLevelV1,
        at: i64,
    ) -> ProjectErrorsRecordV1 {
        ProjectErrorsRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project(),
            attempted_at_ms: at,
            successful_at_ms: Some(at),
            collection_error: None,
            data: Some(ProjectErrorsDataV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: project(),
                unresolved_groups: 1,
                truncated: false,
                total_events: 2,
                affected_users: 1,
                highest_level: level,
                groups: vec![ErrorGroupV1 {
                    safe_label: "RuntimeError".to_owned(),
                    level,
                    event_count: 2,
                    affected_users: 1,
                    first_seen: "2026-07-19T00:00:00Z".to_owned(),
                    last_seen: "2026-07-19T00:05:00Z".to_owned(),
                    deep_link: "https://glitchtip.4u.ge/4u/issues/1/".to_owned(),
                }],
                insight: ErrorInsightV1 {
                    source: InsightSourceV1::DeepseekV4FlashFree,
                    priority: model_priority,
                    summary: "Advisory model summary.".to_owned(),
                    actions: Vec::new(),
                    generated_at_ms: at,
                    input_digest: EvidenceDigest::sha256("anonymous facts"),
                },
                analysis_error: None,
            }),
        }
    }

    #[test]
    fn persistent_collection_failure_emits_once_then_recovery() {
        let good = errors(InsightPriorityV1::None, 10);
        let mut failed = good.clone();
        failed.attempted_at_ms = 20;
        failed.collection_error =
            Some(IntegrationFailureV1::new("timeout", "Provider timed out.").expect("failure"));
        assert_eq!(
            plan_error_notifications(Some(&good), &failed)
                .expect("failed transition")
                .len(),
            1
        );
        let mut repeated = failed.clone();
        repeated.attempted_at_ms = 30;
        assert!(
            plan_error_notifications(Some(&failed), &repeated)
                .expect("repeat")
                .is_empty()
        );
        let recovered = errors(InsightPriorityV1::None, 40);
        assert_eq!(
            plan_error_notifications(Some(&repeated), &recovered).expect("recovery")[0].kind,
            NotificationKindV1::ErrorCollectionRecovered
        );
    }

    #[test]
    fn dependency_check_failure_and_recovery_are_explicit_without_metadata_noise() {
        let passing = updates(DependencyCheckStateV1::Passing, 10);
        let failing = updates(DependencyCheckStateV1::Failing, 20);
        let events = plan_update_notifications(Some(&passing), &failing).expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, NotificationKindV1::DependencyChecksFailed);
        let recovered = updates(DependencyCheckStateV1::Passing, 30);
        assert_eq!(
            plan_update_notifications(Some(&failing), &recovered).expect("recovered")[0].kind,
            NotificationKindV1::DependencyChecksRecovered
        );
    }

    #[test]
    fn telegram_priority_is_deterministic_and_model_priority_is_advisory() {
        let first = nonempty_errors(InsightPriorityV1::Low, ErrorLevelV1::Error, 10);
        let initial = plan_error_notifications(None, &first).expect("initial");
        assert_eq!(initial.len(), 1);
        assert!(initial[0].text.contains("high"));

        let changed_model = nonempty_errors(InsightPriorityV1::Critical, ErrorLevelV1::Error, 20);
        assert!(
            plan_error_notifications(Some(&first), &changed_model)
                .expect("advisory-only change")
                .is_empty()
        );

        let resolved = errors(InsightPriorityV1::None, 30);
        let resolution =
            plan_error_notifications(Some(&changed_model), &resolved).expect("resolution");
        assert_eq!(resolution.len(), 1);
        assert_eq!(resolution[0].kind, NotificationKindV1::ErrorPriorityChanged);
        assert!(resolution[0].text.contains("снят"));
    }
}
