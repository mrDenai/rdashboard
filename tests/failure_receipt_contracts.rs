use std::str::FromStr as _;

use rdashboard::domain::{
    EvidenceDigest, ExecutionCleanupReceiptV1, ExecutionCleanupStateV1, ExecutionIoUsageV1,
    ExecutionMemoryEventsV1, ExecutionProcessOutcomeV1, ExecutionResourceUsageV1,
    ExecutionResultV1, ExecutionStorageUsageV1, ExecutionTerminalReceiptV1, FailureArtifactV2,
    FailureCapsule, FailureCapsuleV2Input, FailureContextEventV2, FailureContextRelationV2,
    FailureRollbackStateV2, OperationPhase, ProductionMutationStateV2, ProjectId, Redactor,
    Retryability, StructuredError,
};
use uuid::Uuid;

const LEGACY_CAPSULE_JSON: &str = r#"{"schema_version":1,"failing_step":"testing","error":{"code":"ci_failed","summary":"CI failed","retryability":"operator_runbook","runbook_id":null},"excerpt":"old evidence","truncated":false}"#;

fn project() -> ProjectId {
    ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"))
}

fn failed_process() -> ExecutionProcessOutcomeV1 {
    ExecutionProcessOutcomeV1 {
        result: ExecutionResultV1::Failed,
        exit_code: Some(17),
        signal: None,
        timed_out: false,
        oom_killed: false,
    }
}

fn measured_resources() -> ExecutionResourceUsageV1 {
    ExecutionResourceUsageV1 {
        cpu_usage_usec: Some(42_000),
        memory_peak_bytes: Some(128 * 1024 * 1024),
        memory_events: Some(ExecutionMemoryEventsV1::default()),
        io: Some(ExecutionIoUsageV1 {
            read_bytes: 1_024,
            write_bytes: 2_048,
            read_operations: 2,
            write_operations: 3,
        }),
        tasks_peak: Some(12),
    }
}

fn measured_storage() -> ExecutionStorageUsageV1 {
    ExecutionStorageUsageV1 {
        scratch_before_bytes: Some(100),
        scratch_after_bytes: Some(300),
        scratch_peak_bytes: Some(400),
        cache_delta_bytes: Some(0),
        log_delta_bytes: Some(200),
        filesystem_available_after_bytes: Some(20 * 1024 * 1024 * 1024),
        emergency_reserve_required_bytes: Some(12 * 1024 * 1024 * 1024),
        emergency_reserve_remaining_bytes: Some(8 * 1024 * 1024 * 1024),
        emergency_reserve_deficit_bytes: Some(0),
    }
}

fn failure_v2_input() -> FailureCapsuleV2Input {
    FailureCapsuleV2Input {
        failure_id: Uuid::new_v4(),
        project_id: project(),
        workflow_kind: "deploy".to_owned(),
        source_sha: Some(
            "0123456789abcdef0123456789abcdef01234567"
                .parse()
                .unwrap_or_else(|error| panic!("sha: {error}")),
        ),
        policy_digest: Some(EvidenceDigest::sha256("policy")),
        request_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        phase: OperationPhase::Testing,
        step_id: "bare-ci".to_owned(),
        step_display_name: "Bare CI known-production-secret".to_owned(),
        started_at_ms: 1_000,
        failed_at_ms: 2_500,
        error: StructuredError {
            code: "ci_failed".to_owned(),
            summary: "CI failed token=summary-secret".to_owned(),
            retryability: Retryability::OperatorRunbook,
            runbook_id: None,
        },
        first_cause: "\u{1b}[31mdependency check failed\u{1b}[0m password=cause-secret".to_owned(),
        raw_excerpt: format!(
            "Bearer abcdefghijk {} {}",
            "known-production-secret",
            "x".repeat(96 * 1024)
        ),
        process: failed_process(),
        resources: measured_resources(),
        storage: measured_storage(),
        artifacts: vec![
            FailureArtifactV2 {
                kind: "test-log".to_owned(),
                digest: EvidenceDigest::sha256("log"),
                size_bytes: 300,
            },
            FailureArtifactV2 {
                kind: "build-plan".to_owned(),
                digest: EvidenceDigest::sha256("plan"),
                size_bytes: 200,
            },
        ],
        context: vec![
            FailureContextEventV2 {
                at_ms: 2_400,
                relation: FailureContextRelationV2::Cause,
                kind: "command-exit".to_owned(),
                summary: "token=context-secret".to_owned(),
            },
            FailureContextEventV2 {
                at_ms: 1_100,
                relation: FailureContextRelationV2::Before,
                kind: "command-start".to_owned(),
                summary: "started".to_owned(),
            },
        ],
        raw_log: None,
        previous_release_digest: None,
        attempted_release_digest: Some(EvidenceDigest::sha256("candidate")),
        health_evidence_digest: None,
        terminal_receipt_digest: Some(EvidenceDigest::sha256("terminal")),
        cleanup_receipt_digest: None,
        production_mutation: ProductionMutationStateV2::NotStarted,
        rollback: FailureRollbackStateV2::NotRequired,
    }
}

#[test]
fn legacy_v1_json_decodes_without_gaining_a_v2_field_and_renders_truthfully() {
    let capsule: FailureCapsule = serde_json::from_str(LEGACY_CAPSULE_JSON)
        .unwrap_or_else(|error| panic!("legacy decode: {error}"));

    capsule
        .validate()
        .unwrap_or_else(|error| panic!("legacy validate: {error}"));
    assert_eq!(capsule.v2, None);
    assert_eq!(
        serde_json::to_string(&capsule).unwrap_or_else(|error| panic!("legacy encode: {error}")),
        LEGACY_CAPSULE_JSON
    );
    let rendered = capsule
        .render_markdown()
        .unwrap_or_else(|error| panic!("legacy render: {error}"));
    assert!(rendered.contains("Legacy capsule (v1)"));
    assert!(
        rendered.contains("resource, cleanup, release, and context evidence were not recorded")
    );
}

#[test]
fn v2_is_bounded_canonical_redacted_and_cause_first() {
    let redactor = Redactor::new(["known-production-secret"])
        .unwrap_or_else(|error| panic!("redactor: {error}"));
    let capsule = FailureCapsule::from_v2_raw(failure_v2_input(), &redactor)
        .unwrap_or_else(|error| panic!("v2 capsule: {error}"));

    let bytes = capsule
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonical capsule: {error}"));
    assert!(bytes.len() <= 64 * 1024);
    assert_eq!(
        FailureCapsule::decode_canonical(&bytes)
            .unwrap_or_else(|error| panic!("canonical decode: {error}")),
        capsule
    );
    let encoded = String::from_utf8(bytes).unwrap_or_else(|error| panic!("UTF-8: {error}"));
    for secret in [
        "known-production-secret",
        "summary-secret",
        "cause-secret",
        "context-secret",
        "abcdefghijk",
        "\u{1b}[31m",
    ] {
        assert!(
            !encoded.contains(secret),
            "secret/control leaked: {secret:?}"
        );
    }
    assert!(capsule.truncated);
    let evidence = capsule.v2.as_ref().unwrap_or_else(|| panic!("v2 evidence"));
    assert!(evidence.redaction.replacement_count >= 6);
    assert_eq!(evidence.duration_ms, 1_500);
    assert_eq!(evidence.artifacts[0].kind, "build-plan");
    assert_eq!(evidence.context[0].kind, "command-start");
    let rendered = capsule
        .render_markdown()
        .unwrap_or_else(|error| panic!("render: {error}"));
    assert!(rendered.len() <= 64 * 1024);
    assert!(
        rendered
            .find("Cause:")
            .is_some_and(|cause| cause < rendered.find("## Resource").unwrap_or(usize::MAX))
    );
    assert!(rendered.contains("`raw_log`"));
    assert!(rendered.contains("`cleanup_receipt`"));
}

#[test]
fn version_mixtures_gap_tampering_and_invalid_cleanup_are_rejected() {
    let terminal = ExecutionTerminalReceiptV1::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvidenceDigest::sha256("execution start"),
        project(),
        OperationPhase::Building,
        "build".to_owned(),
        1,
        10,
        30,
        failed_process(),
        ExecutionResourceUsageV1::default(),
        ExecutionStorageUsageV1::default(),
    )
    .unwrap_or_else(|error| panic!("terminal: {error}"));
    let bytes = terminal
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("terminal bytes: {error}"));
    assert_eq!(
        ExecutionTerminalReceiptV1::decode_canonical(&bytes)
            .unwrap_or_else(|error| panic!("terminal decode: {error}")),
        terminal
    );

    let mut tampered = terminal.clone();
    tampered.evidence_gaps.pop();
    assert!(tampered.validate().is_err());

    let complete = ExecutionCleanupReceiptV1::new(
        terminal.attempt_id,
        terminal.receipt_digest.clone(),
        ExecutionCleanupStateV1::Complete,
        true,
        Some(0),
        0,
        Some(10_000),
        None,
        31,
    )
    .unwrap_or_else(|error| panic!("cleanup: {error}"));
    assert!(complete.validate().is_ok());
    assert!(
        ExecutionCleanupReceiptV1::new(
            terminal.attempt_id,
            terminal.receipt_digest,
            ExecutionCleanupStateV1::Complete,
            false,
            None,
            1,
            None,
            Some("cleanup-failed".to_owned()),
            31,
        )
        .is_err()
    );

    let legacy: FailureCapsule =
        serde_json::from_str(LEGACY_CAPSULE_JSON).unwrap_or_else(|error| panic!("legacy: {error}"));
    let mut invalid = legacy;
    invalid.schema_version = 2;
    assert!(invalid.validate().is_err());
}

#[test]
fn emergency_reserve_deficit_is_explicit_and_internally_consistent() {
    let mut storage = measured_storage();
    storage.filesystem_available_after_bytes = Some(5 * 1024 * 1024 * 1024);
    storage.emergency_reserve_required_bytes = Some(8 * 1024 * 1024 * 1024);
    storage.emergency_reserve_remaining_bytes = Some(0);
    storage.emergency_reserve_deficit_bytes = Some(3 * 1024 * 1024 * 1024);
    let terminal = ExecutionTerminalReceiptV1::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvidenceDigest::sha256("reserve start"),
        project(),
        OperationPhase::Building,
        "build".to_owned(),
        1,
        10,
        20,
        failed_process(),
        measured_resources(),
        storage.clone(),
    )
    .unwrap_or_else(|error| panic!("deficit receipt: {error}"));
    assert_eq!(
        terminal.storage.emergency_reserve_deficit_bytes,
        Some(3 * 1024 * 1024 * 1024)
    );

    storage.emergency_reserve_deficit_bytes = Some(0);
    assert!(
        ExecutionTerminalReceiptV1::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EvidenceDigest::sha256("invalid reserve start"),
            project(),
            OperationPhase::Building,
            "build".to_owned(),
            1,
            10,
            20,
            failed_process(),
            measured_resources(),
            storage,
        )
        .is_err()
    );
}
