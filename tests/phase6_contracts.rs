use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rdashboard::authorization::ActionGrantRoleV1;
use rdashboard::{
    adapter_identity::{AdapterOperationIdentityKindV1, AdapterOperationIdentityV1},
    backup::{
        AuthorizedBackupSpecInputV1, AuthorizedBackupSpecV1, BackupCapturePurposeV1,
        BackupCheckEvidenceV1, BackupCheckKindV1, BackupCheckOutcomeV1, BackupCheckSpecV1,
        BackupConsistencyMechanismV1, BackupEncryptionAlgorithmV1, BackupEncryptionEvidenceV1,
        BackupFreshnessEvidenceV1, BackupManifestInputV1, BackupManifestV1, BackupObjectKindV1,
        BackupObjectV1, BackupProviderV1, BackupSnapshotKindV1, BackupUnitSpecInputV1,
        BackupUnitSpecV1, ExpectedBackupObjectV1, LocalBackupEvidenceV1,
        OffsiteVerificationEvidenceV1, OffsiteVerificationInputV1, ProviderUploadReceiptInputV1,
        ProviderUploadReceiptV1, TrustedClockEvidenceV1, VerifiedBackupChainV1,
        base_phase_artifacts, cutover_phase_artifacts,
    },
    backup_driver::{
        BackupDiskProbeErrorV1, BackupDiskProbeV1, BackupDriverPoliciesV1,
        BackupDriverPolicySourceErrorV1, BackupDriverPolicySourceV1, BackupOperationDriverV1,
    },
    build::{
        InstalledKamalPolicyInputV1, InstalledKamalPolicyV1, KamalClearEnvironmentV1,
        KamalContainerPath, KamalEnvironmentKey, KamalEnvironmentValue, KamalHostPath,
        KamalImageName, KamalLoggingDriverV1, KamalLoggingPolicyV1, KamalMountAccessV1,
        KamalMountV1, KamalNetworkAlias, KamalNetworkName, KamalPortBindingV1, KamalPortProtocolV1,
        KamalSecretBindingV1, KamalSecretName, KamalServiceName, KamalSshUser, KamalTargetHost,
        KamalUnixIdentityV1, ReleaseBundleV1, ReleaseRollbackContractV1,
    },
    domain::{
        BlockingReason, DiskAvailabilityObservation, DiskReservation, EvidenceDigest,
        InstalledPolicyIdentity, OperationActor, OperationEvidence, OperationKind, OperationPhase,
        OperationRecord, OperationResult, OperationState, PhaseArtifacts, ProjectId,
        RelativePolicyPath, ReleaseClass,
    },
    executor::{
        DeterministicModelEffects, DiskSpaceProbe, EffectObservation, ExternalEffectError,
        ExternalEffects, PhaseEffectEvidence, PhaseIntent,
    },
    installed_intent_resolver::{
        InstalledBackupMutationPolicyInputV1, InstalledBackupMutationPolicyV1,
    },
    phase6::{
        AuthorizedPhasePrerequisitesV1, AuthorizedPhaseSpecInputV1, AuthorizedPhaseSpecV1,
        FixedAdapterProfileV1, FixedAdapterRequestV1, InstalledRimgPolicyInputV1,
        InstalledRimgPolicyV1, InstalledSchemaTransitionV1, Phase6ContractError,
        ReleaseClassificationAuthorityV1, ReleaseClassificationInputV1,
        RimgDeploymentCapabilitiesV1, RimgProtocolVersionsV1, RimgTimeoutPolicyV1,
        SchemaContractEvaluationEvidenceV1, SchemaContractEvaluationInputV1, SchemaContractKindV1,
        SchemaContractVerdictV1, SchemaInspectionEvidenceInputV1, SchemaInspectionEvidenceV1,
    },
    store::{
        AcceptedMutationV1, AuthorizedPhaseSpecBinding, BackupBoundaryLease, ExecutionResource,
        ExecutorAuthorization, ExecutorPhaseBranch, ExecutorPhasePlan, FenceLease,
        FenceObservation, ObservationAcceptance, PhaseIntentRequest, SecurityStore, StoreError,
        VerifiedBackupChainBinding,
    },
};
use tempfile::tempdir;
use uuid::Uuid;

fn digest(label: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn project() -> ProjectId {
    ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"))
}

fn installed_policy() -> InstalledPolicyIdentity {
    InstalledPolicyIdentity {
        digest: digest("installed-policy-v1"),
        version: 1,
    }
}

fn relative_path(value: &str) -> RelativePolicyPath {
    RelativePolicyPath::from_str(value).unwrap_or_else(|error| panic!("relative path: {error}"))
}

fn backup_unit() -> BackupUnitSpecV1 {
    BackupUnitSpecV1::new(BackupUnitSpecInputV1 {
        unit_id: "rimg-primary".to_owned(),
        consistency: BackupConsistencyMechanismV1::SqliteOnlineBackupV1,
        expected_objects: vec![
            ExpectedBackupObjectV1 {
                path: relative_path("data/masters"),
                kind: BackupObjectKindV1::Master,
                uid: 10_001,
                gid: 10_001,
                mode: 0o600,
            },
            ExpectedBackupObjectV1 {
                path: relative_path("data/rimg.sqlite3"),
                kind: BackupObjectKindV1::SqliteDatabase,
                uid: 10_001,
                gid: 10_001,
                mode: 0o600,
            },
        ],
        primary_sqlite_path: relative_path("data/rimg.sqlite3"),
        required_checks: vec![
            check_spec("staged_smoke", BackupCheckKindV1::StagedReadSmoke),
            check_spec("integrity", BackupCheckKindV1::SqliteIntegrity),
            check_spec("foreign_keys", BackupCheckKindV1::ForeignKeys),
            check_spec("domain_masters", BackupCheckKindV1::DomainInvariant),
            check_spec("database_files", BackupCheckKindV1::DatabaseToFiles),
        ],
    })
    .unwrap_or_else(|error| panic!("backup unit: {error}"))
}

fn check_spec(name: &str, kind: BackupCheckKindV1) -> BackupCheckSpecV1 {
    BackupCheckSpecV1 {
        name: name.to_owned(),
        kind,
        definition_digest: digest(&format!("check definition {name}")),
    }
}

fn kamal_policy() -> InstalledKamalPolicyV1 {
    InstalledKamalPolicyV1::new(InstalledKamalPolicyInputV1 {
        project_id: project(),
        installed_policy: installed_policy(),
        service: KamalServiceName::from_str("rimg")
            .unwrap_or_else(|error| panic!("service: {error}")),
        image: KamalImageName::from_str("mrdenai/rimg")
            .unwrap_or_else(|error| panic!("image: {error}")),
        target_host: KamalTargetHost::from_str("45.151.142.168")
            .unwrap_or_else(|error| panic!("target: {error}")),
        ssh_user: KamalSshUser::from_str("deploy")
            .unwrap_or_else(|error| panic!("SSH user: {error}")),
        ssh_port: 22,
        network: KamalNetworkName::from_str("kamal")
            .unwrap_or_else(|error| panic!("network: {error}")),
        network_alias: KamalNetworkAlias::from_str("rimg")
            .unwrap_or_else(|error| panic!("alias: {error}")),
        run_as: KamalUnixIdentityV1 {
            uid: 10_001,
            gid: 10_001,
        },
        allowed_host_roots: vec![
            KamalHostPath::from_str("/srv/rimg")
                .unwrap_or_else(|error| panic!("host root: {error}")),
        ],
        mounts: vec![KamalMountV1 {
            host_path: KamalHostPath::from_str("/srv/rimg/data")
                .unwrap_or_else(|error| panic!("host path: {error}")),
            container_path: KamalContainerPath::from_str("/app/data")
                .unwrap_or_else(|error| panic!("container path: {error}")),
            access: KamalMountAccessV1::ReadWrite,
        }],
        ports: vec![KamalPortBindingV1 {
            host_port: 8080,
            container_port: 3000,
            protocol: KamalPortProtocolV1::Tcp,
        }],
        clear_environment: vec![KamalClearEnvironmentV1 {
            key: KamalEnvironmentKey::from_str("RUST_LOG")
                .unwrap_or_else(|error| panic!("environment key: {error}")),
            value: KamalEnvironmentValue::from_str("info")
                .unwrap_or_else(|error| panic!("environment value: {error}")),
        }],
        secret_bindings: vec![KamalSecretBindingV1 {
            environment_key: KamalEnvironmentKey::from_str("RIMG_DATABASE_KEY")
                .unwrap_or_else(|error| panic!("secret key: {error}")),
            secret_name: KamalSecretName::from_str("RIMG_DATABASE_KEY")
                .unwrap_or_else(|error| panic!("secret name: {error}")),
            credential_version: 1,
        }],
        logging: KamalLoggingPolicyV1 {
            driver: KamalLoggingDriverV1::Local,
            max_size_bytes: 16 * 1024 * 1024,
            max_files: 4,
        },
        template_digest: digest("root-owned Kamal template"),
    })
    .unwrap_or_else(|error| panic!("Kamal policy: {error}"))
}

fn complete_protocols() -> RimgProtocolVersionsV1 {
    RimgProtocolVersionsV1 {
        schema_inspection: Some(1),
        explicit_migration: Some(1),
        persisted_fence: Some(1),
        persisted_drain: Some(1),
        truthful_readiness: Some(1),
        coherent_backup: Some(1),
    }
}

fn rimg_policy(protocols: RimgProtocolVersionsV1) -> InstalledRimgPolicyV1 {
    rimg_policy_with_transitions(protocols, vec![])
}

fn rimg_policy_with_transitions(
    protocols: RimgProtocolVersionsV1,
    schema_transitions: Vec<InstalledSchemaTransitionV1>,
) -> InstalledRimgPolicyV1 {
    rimg_policy_with_capabilities(
        protocols,
        schema_transitions,
        RimgDeploymentCapabilitiesV1 {
            bootstrap_with_declared_downtime: true,
            stable_routing: false,
            automatic_code_rollback: false,
        },
    )
}

fn rimg_policy_with_capabilities(
    protocols: RimgProtocolVersionsV1,
    schema_transitions: Vec<InstalledSchemaTransitionV1>,
    capabilities: RimgDeploymentCapabilitiesV1,
) -> InstalledRimgPolicyV1 {
    InstalledRimgPolicyV1::new(
        InstalledRimgPolicyInputV1 {
            project_id: project(),
            installed_policy: installed_policy(),
            protocols,
            timeouts: RimgTimeoutPolicyV1 {
                backup_ms: 300_000,
                drain_ms: 60_000,
                migration_ms: 300_000,
                deploy_ms: 300_000,
                readiness_ms: 60_000,
                smoke_ms: 180_000,
                soak_ms: 600_000,
            },
            capabilities,
            schema_transitions,
            backup_units: vec![backup_unit()],
            backup_recipient_fingerprints: vec![digest("age recipient")],
            backup_provider: BackupProviderV1::GoogleDrive,
            backup_provider_credential_version: 1,
            migration_backup_max_age_ms: 60 * 60 * 1_000,
            code_only_backup_max_age_ms: 24 * 60 * 60 * 1_000,
            schema_contract_digest: digest("schema contract"),
            readiness_contract_digest: digest("readiness contract"),
            consumer_smoke_contract_digest: digest("consumer smoke contract"),
        },
        kamal_policy(),
    )
    .unwrap_or_else(|error| panic!("rimg policy: {error}"))
}

#[derive(Clone, Debug)]
struct StaticBackupDriverPolicies(BackupDriverPoliciesV1);

impl BackupDriverPolicySourceV1 for StaticBackupDriverPolicies {
    fn load(&self) -> Result<BackupDriverPoliciesV1, BackupDriverPolicySourceErrorV1> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Debug)]
struct FixedBackupDiskProbe {
    filesystem_identity: EvidenceDigest,
}

impl DiskSpaceProbe for FixedBackupDiskProbe {
    fn observe(
        &self,
        _project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<DiskAvailabilityObservation, StoreError> {
        Ok(DiskAvailabilityObservation {
            filesystem_identity: self.filesystem_identity.clone(),
            available_bytes: 100 * 1024 * 1024 * 1024,
            observed_at_ms: now_ms,
        })
    }
}

impl BackupDiskProbeV1 for FixedBackupDiskProbe {
    fn reservation(
        &self,
        policy: &InstalledBackupMutationPolicyV1,
        now_ms: i64,
    ) -> Result<DiskReservation, BackupDiskProbeErrorV1> {
        Ok(DiskReservation {
            filesystem_identity: self.filesystem_identity.clone(),
            filesystem_total_bytes: 100 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 100 * 1024 * 1024 * 1024,
            observed_at_ms: now_ms,
            backup_staging_bytes: policy.backup_staging_bytes,
            build_peak_bytes: 0,
            registry_peak_bytes: 0,
            last_known_good_bytes: 0,
            projected_hot_store_growth_bytes: policy.projected_hot_store_growth_bytes,
        })
    }
}

#[derive(Clone, Debug)]
struct VerifiedBackupEffects {
    security: SecurityStore,
    fence: DeterministicModelEffects,
    applications: Arc<AtomicUsize>,
}

impl VerifiedBackupEffects {
    fn phase_and_backup(
        &self,
        intent: &PhaseIntent,
    ) -> Result<(AuthorizedPhaseSpecV1, AuthorizedBackupSpecV1), ExternalEffectError> {
        let record = self
            .security
            .authorized_phase_spec_in_branch(
                intent.attempt_id,
                OperationPhase::BackingUp,
                ExecutorPhaseBranch::Primary,
            )
            .map_err(|_| ExternalEffectError::ConflictingState)?
            .ok_or(ExternalEffectError::ConflictingState)?;
        let phase = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)
            .map_err(|_| ExternalEffectError::ConflictingState)?;
        let backup = phase
            .backup
            .clone()
            .ok_or(ExternalEffectError::ConflictingState)?;
        Ok((phase, backup))
    }
}

impl ExternalEffects for VerifiedBackupEffects {
    fn observe_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        if intent.phase != OperationPhase::BackingUp {
            return Err(ExternalEffectError::ConflictingState);
        }
        if self
            .security
            .verified_backup_chain_in_branch(
                intent.attempt_id,
                OperationPhase::BackingUp,
                ExecutorPhaseBranch::Primary,
            )
            .map_err(|_| ExternalEffectError::ConflictingState)?
            .is_none()
        {
            return Ok(EffectObservation::Absent);
        }
        let (_phase, backup) = self.phase_and_backup(intent)?;
        let chain = base_chain(&backup);
        let verified = chain.verified(&backup);
        let artifacts = base_phase_artifacts(
            &backup,
            &chain.manifest,
            &chain.local,
            &chain.upload,
            &chain.offsite,
        )
        .map_err(|_| ExternalEffectError::ConflictingState)?;
        Ok(EffectObservation::Applied(Box::new(PhaseEffectEvidence {
            intent_digest: intent.digest.clone(),
            observation_digest: verified.chain_digest().clone(),
            artifacts,
        })))
    }

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        let (phase, backup) = self.phase_and_backup(intent)?;
        self.security
            .authorize_bound_phase_spec(
                intent.attempt_id,
                OperationPhase::BackingUp,
                ExecutorPhaseBranch::Primary,
                1_500,
            )
            .map_err(|_| ExternalEffectError::ConflictingState)?;
        let chain = base_chain(&backup);
        bind_verified_base_chain(
            &self.security,
            intent.attempt_id,
            &intent.project_id,
            &phase,
            &backup,
            &chain,
            1_500,
        );
        self.applications.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn observe_fence(
        &self,
        project_id: &ProjectId,
    ) -> Result<FenceObservation, ExternalEffectError> {
        self.fence.observe_fence(project_id)
    }

    fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.fence.acquire_fence(lease)
    }

    fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.fence.release_fence(lease)
    }
}

#[test]
fn installed_rimg_policy_decode_reconstructs_and_revalidates_every_derived_digest() {
    let policy = rimg_policy(complete_protocols());
    let canonical = serde_jcs::to_vec(&policy)
        .unwrap_or_else(|error| panic!("canonical installed policy: {error}"));
    assert_eq!(
        InstalledRimgPolicyV1::decode_canonical(&canonical)
            .unwrap_or_else(|error| panic!("decode installed policy: {error}")),
        policy
    );

    let mut tampered: serde_json::Value = serde_json::from_slice(&canonical)
        .unwrap_or_else(|error| panic!("installed policy value: {error}"));
    tampered["policy_digest"] = serde_json::Value::String(digest("tampered policy").to_string());
    let tampered = serde_jcs::to_vec(&tampered)
        .unwrap_or_else(|error| panic!("tampered installed policy: {error}"));
    assert!(InstalledRimgPolicyV1::decode_canonical(&tampered).is_err());
}

fn release_bundle_document(
    project_id: &ProjectId,
    application_schema_version: &str,
    rollback: ReleaseRollbackContractV1,
    label: &str,
) -> Vec<u8> {
    let evidence = |field: &str| digest(&format!("{label}:{field}"));
    let mut deployment_plan = serde_json::json!({
        "purpose": "rdashboard.kamal-deployment-plan.v1",
        "project_id": project_id,
        "source_head": "dddddddddddddddddddddddddddddddddddddddd",
        "release_identity_digest": evidence("release identity"),
        "installed_policy": installed_policy(),
        "context_digest": evidence("build context"),
        "image_registry_digest": format!("sha256:{}", "a".repeat(64)),
        "service": "rimg",
        "image": "mrdenai/rimg",
        "target_host": "45.151.142.168",
        "ssh_user": "deploy",
        "ssh_port": 22,
        "network": "kamal",
        "network_alias": "rimg",
        "run_as": { "uid": 10001, "gid": 10001 },
        "mounts": [],
        "ports": [],
        "clear_environment": [],
        "secret_bindings": [],
        "credential_versions_digest": evidence("credential versions"),
        "logging": { "driver": "local", "max_size_bytes": 1_048_576, "max_files": 2 },
        "runtime_policy_digest": evidence("runtime policy"),
        "template_digest": evidence("template"),
        "sanitized_diff_digest": evidence("sanitized diff"),
        "repository_configuration": "ignored",
        "hooks": "disabled",
        "template_evaluation": "disabled",
        "registry_transport": "loopback_port5555",
    });
    let plan_digest = EvidenceDigest::sha256(
        serde_jcs::to_vec(&deployment_plan)
            .unwrap_or_else(|error| panic!("deployment plan digest payload: {error}")),
    );
    let plan_document = deployment_plan
        .as_object_mut()
        .unwrap_or_else(|| panic!("deployment plan payload is not an object"));
    plan_document.remove("purpose");
    plan_document.insert("plan_digest".to_owned(), serde_json::json!(plan_digest));
    let mut payload = serde_json::json!({
        "purpose": "rdashboard.release-bundle.v1",
        "schema_version": 3,
        "project_id": project_id,
        "release_identity_digest": evidence("release identity"),
        "source_export_digest": evidence("source export"),
        "prefetch_evidence_digest": evidence("prefetch"),
        "ci_evidence_digest": evidence("ci"),
        "build_context_digest": evidence("build context"),
        "resource_reservation_digest": evidence("reservation"),
        "build_plan_digest": evidence("build plan"),
        "image_registry_digest": format!("sha256:{}", "a".repeat(64)),
        "local_image_id": format!("sha256:{}", "b".repeat(64)),
        "image_archive_digest": evidence(&format!("{label}:OCI archive")),
        "deployment_plan": deployment_plan,
        "runtime_policy_digest": evidence("runtime policy"),
        "credential_versions_digest": evidence("credential versions"),
        "application_schema_version": application_schema_version,
        "rollback": rollback,
    });
    let bundle_digest = EvidenceDigest::sha256(
        serde_jcs::to_vec(&payload)
            .unwrap_or_else(|error| panic!("release bundle digest payload: {error}")),
    );
    let document = payload
        .as_object_mut()
        .unwrap_or_else(|| panic!("release bundle payload is not an object"));
    document.remove("purpose");
    document.insert("bundle_digest".to_owned(), serde_json::json!(bundle_digest));
    serde_jcs::to_vec(&payload)
        .unwrap_or_else(|error| panic!("canonical release bundle document: {error}"))
}

fn release_bundle(
    application_schema_version: &str,
    rollback: ReleaseRollbackContractV1,
    label: &str,
) -> ReleaseBundleV1 {
    ReleaseBundleV1::decode_canonical_json(&release_bundle_document(
        &project(),
        application_schema_version,
        rollback,
        label,
    ))
    .unwrap_or_else(|error| panic!("release bundle fixture: {error}"))
}

fn deploy_intent(
    current: &ReleaseBundleV1,
    candidate: &ReleaseBundleV1,
    release_class: ReleaseClass,
) -> PhaseIntent {
    release_intent(
        &project(),
        installed_policy(),
        current,
        candidate,
        OperationKind::Deploy,
        release_class,
        OperationPhase::Deploying,
    )
}

fn release_intent(
    project_id: &ProjectId,
    policy: InstalledPolicyIdentity,
    current: &ReleaseBundleV1,
    candidate: &ReleaseBundleV1,
    operation_kind: OperationKind,
    release_class: ReleaseClass,
    phase: OperationPhase,
) -> PhaseIntent {
    let (release_bundle_digest, previous_release_bundle_digest) = match operation_kind {
        OperationKind::Deploy => (
            Some(candidate.digest().clone()),
            Some(current.digest().clone()),
        ),
        OperationKind::CodeRollback => (
            Some(current.digest().clone()),
            Some(candidate.digest().clone()),
        ),
        OperationKind::BackupOnly => panic!("release intent cannot be backup-only"),
    };
    let deployment_plan_digest = match operation_kind {
        OperationKind::Deploy => candidate.deployment_plan_digest().clone(),
        OperationKind::CodeRollback => current.deployment_plan_digest().clone(),
        OperationKind::BackupOnly => panic!("release intent cannot be backup-only"),
    };
    let operation = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        attempt_number: 1,
        project_id: project_id.clone(),
        operation_kind,
        target_commit: None,
        release_class: Some(release_class),
        state: OperationState {
            phase,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
        actor: OperationActor::Interactive {
            user_id: Uuid::new_v4(),
        },
        evidence: OperationEvidence {
            installed_policy: Some(policy),
            deployment_plan_digest: Some(deployment_plan_digest),
            release_bundle_digest,
            previous_release_bundle_digest,
            ..OperationEvidence::default()
        },
        failure_capsule: None,
        created_at_ms: 1_000,
        updated_at_ms: 1_000,
    };
    PhaseIntent::from_operation(&operation, digest("classification authorization"))
        .unwrap_or_else(|error| panic!("classification intent: {error}"))
}

fn schema_contract_evidence(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    kind: SchemaContractKindV1,
    contract_digest: EvidenceDigest,
    observation: &str,
) -> SchemaContractEvaluationEvidenceV1 {
    SchemaContractEvaluationEvidenceV1::new(SchemaContractEvaluationInputV1 {
        intent,
        policy,
        kind,
        current_schema_version: Some("1"),
        candidate_schema_version: "2",
        migration_id: Some("schema-v2"),
        contract_digest,
        verdict: SchemaContractVerdictV1::Satisfied,
        observation_digest: digest(observation),
        evaluated_at_ms: 1_100,
    })
    .unwrap_or_else(|error| panic!("schema contract evidence: {error}"))
}

fn resign_schema_inspection(evidence: &mut SchemaInspectionEvidenceV1) {
    let mut payload = serde_json::to_value(&*evidence)
        .unwrap_or_else(|error| panic!("schema inspection payload: {error}"));
    let object = payload
        .as_object_mut()
        .unwrap_or_else(|| panic!("schema inspection is not an object"));
    object.remove("evidence_digest");
    object.insert(
        "purpose".to_owned(),
        serde_json::json!("rdashboard.schema-inspection-evidence.v1"),
    );
    evidence.evidence_digest = EvidenceDigest::sha256(
        serde_jcs::to_vec(&payload)
            .unwrap_or_else(|error| panic!("schema inspection digest: {error}")),
    );
}

#[test]
fn release_bundle_rejects_schema_versions_other_phase6_contracts_cannot_consume() {
    for invalid in ["v1 beta", "схема-v1"] {
        assert!(
            ReleaseBundleV1::decode_canonical_json(&release_bundle_document(
                &project(),
                invalid,
                ReleaseRollbackContractV1::CodeOnlyCompatible,
                "invalid schema",
            ))
            .is_err()
        );
    }
}

struct StatefulClassificationFixture {
    transition: InstalledSchemaTransitionV1,
    policy: InstalledRimgPolicyV1,
    current: ReleaseBundleV1,
    candidate: ReleaseBundleV1,
    intent: PhaseIntent,
    inspection: SchemaInspectionEvidenceV1,
}

fn stateful_inspection_for_intent(
    transition: &InstalledSchemaTransitionV1,
    policy: &InstalledRimgPolicyV1,
    current: &ReleaseBundleV1,
    candidate: &ReleaseBundleV1,
    intent: &PhaseIntent,
    label: &str,
) -> SchemaInspectionEvidenceV1 {
    let migration_plan = schema_contract_evidence(
        intent,
        policy,
        SchemaContractKindV1::MigrationPlan,
        transition.migration_plan_contract_digest.clone(),
        &format!("{label} migration plan"),
    );
    let data_compatibility = schema_contract_evidence(
        intent,
        policy,
        SchemaContractKindV1::DataCompatibility,
        transition.data_compatibility_contract_digest.clone(),
        &format!("{label} data compatibility"),
    );
    SchemaInspectionEvidenceV1::new(SchemaInspectionEvidenceInputV1 {
        intent,
        policy,
        current_bundle: Some(current),
        candidate_bundle: candidate,
        migration_id: Some(transition.migration_id.clone()),
        migration_plan_evidence: Some(&migration_plan),
        data_compatibility_evidence: &data_compatibility,
        observation_digest: digest(&format!("{label} schema inspection")),
        inspected_at_ms: 1_101,
    })
    .unwrap_or_else(|error| panic!("stateful schema inspection: {error}"))
}

fn stateful_classification_fixture() -> StatefulClassificationFixture {
    let transition = InstalledSchemaTransitionV1 {
        from_schema_version: "1".to_owned(),
        to_schema_version: "2".to_owned(),
        migration_id: "schema-v2".to_owned(),
        release_class: ReleaseClass::StatefulCompatible,
        migration_plan_contract_digest: digest("migration plan contract"),
        data_compatibility_contract_digest: digest("data compatibility contract"),
    };
    let policy = rimg_policy_with_transitions(complete_protocols(), vec![transition.clone()]);
    let current = release_bundle(
        "1",
        ReleaseRollbackContractV1::CodeOnlyCompatible,
        "current",
    );
    let candidate = release_bundle(
        "2",
        ReleaseRollbackContractV1::BidirectionalStateful,
        "candidate-v2",
    );
    let intent = deploy_intent(&current, &candidate, ReleaseClass::StatefulCompatible);
    let inspection = stateful_inspection_for_intent(
        &transition,
        &policy,
        &current,
        &candidate,
        &intent,
        "classification",
    );
    StatefulClassificationFixture {
        transition,
        policy,
        current,
        candidate,
        intent,
        inspection,
    }
}

fn resigned_inspection_for_candidate(
    fixture: &StatefulClassificationFixture,
    actual_candidate: &ReleaseBundleV1,
) -> (PhaseIntent, SchemaInspectionEvidenceV1) {
    let intent = deploy_intent(
        &fixture.current,
        actual_candidate,
        ReleaseClass::StatefulCompatible,
    );
    let migration_plan = schema_contract_evidence(
        &intent,
        &fixture.policy,
        SchemaContractKindV1::MigrationPlan,
        fixture.transition.migration_plan_contract_digest.clone(),
        "substituted migration plan evaluation",
    );
    let data_compatibility = schema_contract_evidence(
        &intent,
        &fixture.policy,
        SchemaContractKindV1::DataCompatibility,
        fixture
            .transition
            .data_compatibility_contract_digest
            .clone(),
        "substituted data compatibility evaluation",
    );
    let mut inspection = SchemaInspectionEvidenceV1::new(SchemaInspectionEvidenceInputV1 {
        intent: &intent,
        policy: &fixture.policy,
        current_bundle: Some(&fixture.current),
        candidate_bundle: &fixture.candidate,
        migration_id: Some("schema-v2".to_owned()),
        migration_plan_evidence: Some(&migration_plan),
        data_compatibility_evidence: &data_compatibility,
        observation_digest: digest("resigned schema inspection"),
        inspected_at_ms: 1_101,
    })
    .unwrap_or_else(|error| panic!("forgeable inspection precursor: {error}"));
    inspection.candidate_release_bundle_digest = actual_candidate.digest().clone();
    resign_schema_inspection(&mut inspection);
    (intent, inspection)
}

#[test]
fn classification_rederives_bundle_schema_instead_of_trusting_resigned_inspection() {
    let fixture = stateful_classification_fixture();
    let authority = ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
        intent: &fixture.intent,
        policy: &fixture.policy,
        current_bundle: Some(&fixture.current),
        candidate_bundle: &fixture.candidate,
        schema_inspection: &fixture.inspection,
    })
    .unwrap_or_else(|error| panic!("valid classification authority: {error}"));
    assert_eq!(
        authority.evidence().effective_class,
        ReleaseClass::StatefulCompatible
    );

    let actual_candidate = release_bundle(
        "3",
        ReleaseRollbackContractV1::StatefulBreakingNoAutomatic,
        "candidate-v3",
    );
    let (substituted_intent, resigned_inspection) =
        resigned_inspection_for_candidate(&fixture, &actual_candidate);
    assert!(
        resigned_inspection
            .has_valid_digest()
            .unwrap_or_else(|error| panic!("resigned inspection digest: {error}"))
    );
    assert!(matches!(
        ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
            intent: &substituted_intent,
            policy: &fixture.policy,
            current_bundle: Some(&fixture.current),
            candidate_bundle: &actual_candidate,
            schema_inspection: &resigned_inspection,
        }),
        Err(Phase6ContractError::InvalidClassification)
    ));
}

#[test]
fn classification_authority_rejects_an_intent_from_another_policy_generation() {
    let fixture = stateful_classification_fixture();
    let mismatched_policy = InstalledPolicyIdentity {
        digest: digest("another installed policy"),
        version: installed_policy().version + 1,
    };
    let intent = release_intent(
        &project(),
        mismatched_policy,
        &fixture.current,
        &fixture.candidate,
        OperationKind::Deploy,
        ReleaseClass::StatefulCompatible,
        OperationPhase::Deploying,
    );
    let inspection = stateful_inspection_for_intent(
        &fixture.transition,
        &fixture.policy,
        &fixture.current,
        &fixture.candidate,
        &intent,
        "mismatched policy generation",
    );
    assert!(matches!(
        ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
            intent: &intent,
            policy: &fixture.policy,
            current_bundle: Some(&fixture.current),
            candidate_bundle: &fixture.candidate,
            schema_inspection: &inspection,
        }),
        Err(Phase6ContractError::InvalidClassification)
    ));
}

#[test]
fn classification_authority_drives_a_stateful_phase_spec() {
    let fixture = stateful_classification_fixture();
    let health_intent = release_intent(
        &project(),
        installed_policy(),
        &fixture.current,
        &fixture.candidate,
        OperationKind::Deploy,
        ReleaseClass::StatefulCompatible,
        OperationPhase::HealthChecking,
    );
    let health_inspection = stateful_inspection_for_intent(
        &fixture.transition,
        &fixture.policy,
        &fixture.current,
        &fixture.candidate,
        &health_intent,
        "stateful health",
    );
    let health_authority =
        ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
            intent: &health_intent,
            policy: &fixture.policy,
            current_bundle: Some(&fixture.current),
            candidate_bundle: &fixture.candidate,
            schema_inspection: &health_inspection,
        })
        .unwrap_or_else(|error| panic!("stateful health authority: {error}"));
    let health_spec = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent: &health_intent,
        policy: &fixture.policy,
        classification: Some(&health_authority),
        backup: None,
        prerequisites: AuthorizedPhasePrerequisitesV1::default(),
    })
    .unwrap_or_else(|error| panic!("stateful health phase spec: {error}"));
    assert_eq!(
        health_spec.effective_release_class,
        Some(ReleaseClass::StatefulCompatible)
    );
    assert_eq!(
        health_spec.classification_evidence_digest,
        Some(health_authority.evidence().evidence_digest.clone())
    );
    assert_eq!(
        health_spec.steps[0].profile,
        FixedAdapterProfileV1::RimgReadiness
    );

    let stale_authority = ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
        intent: &fixture.intent,
        policy: &fixture.policy,
        current_bundle: Some(&fixture.current),
        candidate_bundle: &fixture.candidate,
        schema_inspection: &fixture.inspection,
    })
    .unwrap_or_else(|error| panic!("deploy authority: {error}"));
    assert!(matches!(
        AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
            intent: &health_intent,
            policy: &fixture.policy,
            classification: Some(&stale_authority),
            backup: None,
            prerequisites: AuthorizedPhasePrerequisitesV1::default(),
        }),
        Err(Phase6ContractError::InvalidClassification)
    ));
}

#[test]
fn classification_authority_drives_a_rollback_phase_spec() {
    let rollback_policy = rimg_policy_with_capabilities(
        complete_protocols(),
        Vec::new(),
        RimgDeploymentCapabilitiesV1 {
            bootstrap_with_declared_downtime: true,
            stable_routing: true,
            automatic_code_rollback: true,
        },
    );
    let running = release_bundle(
        "1",
        ReleaseRollbackContractV1::CodeOnlyCompatible,
        "rollback running",
    );
    let rollback_target = release_bundle(
        "1",
        ReleaseRollbackContractV1::CodeOnlyCompatible,
        "rollback target",
    );
    let rollback_intent = release_intent(
        &project(),
        installed_policy(),
        &running,
        &rollback_target,
        OperationKind::CodeRollback,
        ReleaseClass::Rollback,
        OperationPhase::Rollback,
    );
    let rollback_compatibility =
        SchemaContractEvaluationEvidenceV1::new(SchemaContractEvaluationInputV1 {
            intent: &rollback_intent,
            policy: &rollback_policy,
            kind: SchemaContractKindV1::DataCompatibility,
            current_schema_version: Some("1"),
            candidate_schema_version: "1",
            migration_id: None,
            contract_digest: digest("schema contract"),
            verdict: SchemaContractVerdictV1::Satisfied,
            observation_digest: digest("rollback compatibility"),
            evaluated_at_ms: 1_100,
        })
        .unwrap_or_else(|error| panic!("rollback compatibility evidence: {error}"));
    let rollback_inspection = SchemaInspectionEvidenceV1::new(SchemaInspectionEvidenceInputV1 {
        intent: &rollback_intent,
        policy: &rollback_policy,
        current_bundle: Some(&running),
        candidate_bundle: &rollback_target,
        migration_id: None,
        migration_plan_evidence: None,
        data_compatibility_evidence: &rollback_compatibility,
        observation_digest: digest("rollback schema inspection"),
        inspected_at_ms: 1_101,
    })
    .unwrap_or_else(|error| panic!("rollback schema inspection: {error}"));
    let rollback_authority =
        ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
            intent: &rollback_intent,
            policy: &rollback_policy,
            current_bundle: Some(&running),
            candidate_bundle: &rollback_target,
            schema_inspection: &rollback_inspection,
        })
        .unwrap_or_else(|error| panic!("rollback authority: {error}"));
    let rollback_spec = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent: &rollback_intent,
        policy: &rollback_policy,
        classification: Some(&rollback_authority),
        backup: None,
        prerequisites: AuthorizedPhasePrerequisitesV1::default(),
    })
    .unwrap_or_else(|error| panic!("rollback phase spec: {error}"));
    assert_eq!(rollback_spec.operation_kind, OperationKind::CodeRollback);
    assert_eq!(
        rollback_spec.effective_release_class,
        Some(ReleaseClass::Rollback)
    );
    assert_eq!(
        rollback_spec.steps[0].profile,
        FixedAdapterProfileV1::KamalCodeRollback
    );
}

fn backup_operation(attempt_id: Uuid, request_id: Uuid) -> OperationRecord {
    OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id,
        attempt_id,
        attempt_number: 1,
        project_id: project(),
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        release_class: None,
        state: OperationState {
            phase: OperationPhase::BackingUp,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
        actor: OperationActor::Interactive {
            user_id: Uuid::new_v4(),
        },
        evidence: OperationEvidence {
            installed_policy: Some(installed_policy()),
            ..OperationEvidence::default()
        },
        failure_capsule: None,
        created_at_ms: 1_000,
        updated_at_ms: 1_000,
    }
}

fn base_backup_spec(
    policy: &InstalledRimgPolicyV1,
    intent: &PhaseIntent,
) -> AuthorizedBackupSpecV1 {
    AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
        attempt_id: intent.attempt_id,
        project_id: project(),
        installed_policy: installed_policy(),
        installed_rimg_policy_digest: policy.digest().clone(),
        phase_intent_digest: intent.digest.clone(),
        backup_set_id: Uuid::new_v4(),
        backup_id: Uuid::new_v4(),
        snapshot_kind: BackupSnapshotKindV1::Base,
        capture_purpose: BackupCapturePurposeV1::DeploymentBase,
        unit: backup_unit(),
        recipient_fingerprint: digest("age recipient"),
        provider: BackupProviderV1::GoogleDrive,
        provider_credential_version: 1,
        capture_deadline_ms: 2_000,
        fencing_epoch: None,
        fence_receipt_digest: None,
    })
    .unwrap_or_else(|error| panic!("authorized backup: {error}"))
}

fn manifest_objects() -> Vec<BackupObjectV1> {
    vec![
        BackupObjectV1 {
            path: relative_path("data/rimg.sqlite3"),
            kind: BackupObjectKindV1::SqliteDatabase,
            size_bytes: 4_096,
            sha256: digest("sqlite snapshot"),
            uid: 10_001,
            gid: 10_001,
            mode: 0o600,
            hard_link_count: 1,
        },
        BackupObjectV1 {
            path: relative_path("data/masters"),
            kind: BackupObjectKindV1::Master,
            size_bytes: 1_024,
            sha256: digest("masters archive"),
            uid: 10_001,
            gid: 10_001,
            mode: 0o600,
            hard_link_count: 1,
        },
    ]
}

fn manifest_checks() -> Vec<BackupCheckEvidenceV1> {
    backup_unit()
        .required_checks
        .into_iter()
        .rev()
        .map(|check| BackupCheckEvidenceV1 {
            name: check.name,
            kind: check.kind,
            definition_digest: check.definition_digest,
            checked_object_digest: digest("sqlite snapshot"),
            outcome: BackupCheckOutcomeV1::Passed,
            observation_digest: digest("check observation"),
        })
        .collect()
}

struct BaseChain {
    manifest: BackupManifestV1,
    local: LocalBackupEvidenceV1,
    upload: ProviderUploadReceiptV1,
    offsite: OffsiteVerificationEvidenceV1,
}

impl BaseChain {
    fn verified(&self, spec: &AuthorizedBackupSpecV1) -> VerifiedBackupChainV1 {
        VerifiedBackupChainV1::new_base(
            spec,
            &self.manifest,
            &self.local,
            &self.upload,
            &self.offsite,
        )
        .unwrap_or_else(|error| panic!("verified chain: {error}"))
    }
}

fn bind_verified_base_chain(
    security: &SecurityStore,
    attempt_id: Uuid,
    project_id: &ProjectId,
    phase_spec: &AuthorizedPhaseSpecV1,
    backup_spec: &AuthorizedBackupSpecV1,
    chain: &BaseChain,
    persisted_at_ms: i64,
) {
    let verified_chain = chain.verified(backup_spec);
    security
        .bind_verified_backup_chain(VerifiedBackupChainBinding {
            attempt_id,
            project_id,
            phase: OperationPhase::BackingUp,
            branch: ExecutorPhaseBranch::Primary,
            authorized_phase_spec_digest: &phase_spec.spec_digest,
            chain: &verified_chain,
            persisted_at_ms,
        })
        .unwrap_or_else(|error| panic!("bind verified chain: {error}"));
}

fn bind_phase_spec_idempotently(
    security: &SecurityStore,
    operation: &OperationRecord,
    intent: &PhaseIntent,
    spec: &AuthorizedPhaseSpecV1,
    persisted_at_ms: i64,
) {
    let canonical_json = spec
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode spec: {error}"));
    let binding = AuthorizedPhaseSpecBinding {
        attempt_id: operation.attempt_id,
        project_id: &operation.project_id,
        phase: operation.state.phase,
        branch: ExecutorPhaseBranch::Primary,
        intent_digest: &intent.digest,
        spec_digest: &spec.spec_digest,
        canonical_json: &canonical_json,
        persisted_at_ms,
    };
    let first = security
        .bind_authorized_phase_spec(binding)
        .unwrap_or_else(|error| panic!("bind spec: {error}"));
    assert_eq!(
        security
            .bind_authorized_phase_spec(binding)
            .unwrap_or_else(|error| panic!("idempotent bind: {error}")),
        first
    );
}

fn base_chain(spec: &AuthorizedBackupSpecV1) -> BaseChain {
    let manifest = BackupManifestV1::new(
        spec,
        BackupManifestInputV1 {
            application_schema_version: "1".to_owned(),
            started_at_ms: 1_100,
            completed_at_ms: 1_200,
            objects: manifest_objects(),
            checks: manifest_checks(),
        },
    )
    .unwrap_or_else(|error| panic!("manifest: {error}"));
    let local = LocalBackupEvidenceV1::new(
        spec,
        &manifest,
        BackupEncryptionEvidenceV1 {
            algorithm: BackupEncryptionAlgorithmV1::AgeX25519,
            authorized_spec_digest: spec.spec_digest.clone(),
            backup_id: spec.backup_id,
            manifest_digest: manifest.manifest_digest.clone(),
            plaintext_archive_digest: digest("plaintext archive"),
            recipient_fingerprint: digest("age recipient"),
            ciphertext_digest: digest("ciphertext"),
            ciphertext_size_bytes: 8_192,
            encrypted_at_ms: 1_300,
        },
    )
    .unwrap_or_else(|error| panic!("local evidence: {error}"));
    let upload = ProviderUploadReceiptV1::new(
        spec,
        &local,
        ProviderUploadReceiptInputV1 {
            provider: BackupProviderV1::GoogleDrive,
            provider_credential_version: 1,
            object_id: "drive-object".to_owned(),
            version_id: "drive-version-1".to_owned(),
            uploaded_at_ms: 1_400,
            provider_receipt_digest: digest("provider upload receipt"),
        },
    )
    .unwrap_or_else(|error| panic!("upload receipt: {error}"));
    let offsite = OffsiteVerificationEvidenceV1::new(
        spec,
        &local,
        &upload,
        OffsiteVerificationInputV1 {
            readback_size_bytes: 8_192,
            readback_ciphertext_digest: digest("ciphertext"),
            readback_observation_digest: digest("readback observation"),
            verified_at_ms: 1_500,
        },
    )
    .unwrap_or_else(|error| panic!("offsite evidence: {error}"));
    BaseChain {
        manifest,
        local,
        upload,
        offsite,
    }
}

fn backup_driver_policy_and_acceptance() -> (StaticBackupDriverPolicies, AcceptedMutationV1) {
    let rimg = rimg_policy(complete_protocols());
    let mutation = InstalledBackupMutationPolicyV1::new(InstalledBackupMutationPolicyInputV1 {
        project_id: project(),
        installed_policy: installed_policy(),
        installed_rimg_policy_digest: rimg.digest().clone(),
        backup_unit_digest: backup_unit().unit_digest,
        recipient_fingerprint: digest("age recipient"),
        backup_staging_bytes: 64 * 1024 * 1024,
        projected_hot_store_growth_bytes: 16 * 1024 * 1024,
        intent_ttl_ms: 60_000,
    })
    .unwrap_or_else(|error| panic!("mutation policy: {error}"));
    let accepted = AcceptedMutationV1 {
        intent_id: Uuid::new_v4(),
        intent_digest: digest("signed intent"),
        signed_intent: "test-only-signed-intent".to_owned(),
        attempt_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        project_id: project(),
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        proposed_release_class: None,
        effective_release_class: None,
        installed_policy_digest: mutation.document_digest.clone(),
        source_attestation_digest: None,
        source_sequence: None,
        release_bundle_digest: None,
        build_attestation_digest: None,
        migration_id: None,
        previous_release_bundle_digest: None,
        intent_expires_at_ms: 61_000,
        actor_id: Uuid::new_v4(),
        action_grant_role: ActionGrantRoleV1::Operator,
        action_grant_nonce: Uuid::new_v4(),
        action_grant_digest: digest("action grant"),
        lease_id: Uuid::new_v4(),
        lease_generation: 1,
        grant_expires_at_ms: 61_000,
        accepted_at_ms: 1_000,
    };
    (
        StaticBackupDriverPolicies(BackupDriverPoliciesV1 { mutation, rimg }),
        accepted,
    )
}

#[test]
fn accepted_backup_driver_recovers_from_receipts_without_reapplying_the_effect() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let (policies, accepted) = backup_driver_policy_and_acceptance();
    let attempt_id = accepted.attempt_id;
    let applications = Arc::new(AtomicUsize::new(0));
    let disk = FixedBackupDiskProbe {
        filesystem_identity: digest("backup filesystem"),
    };
    let effects = VerifiedBackupEffects {
        security: security.clone(),
        fence: DeterministicModelEffects::default(),
        applications: Arc::clone(&applications),
    };
    let first =
        BackupOperationDriverV1::new(security.clone(), policies.clone(), disk.clone(), effects)
            .drive_accepted(&accepted, 2_000)
            .unwrap_or_else(|error| panic!("drive accepted backup: {error}"));
    assert_eq!(first.state.result, OperationResult::Succeeded);
    assert_eq!(applications.load(Ordering::Relaxed), 1);
    let authorization = security
        .executor_authorization(attempt_id)
        .unwrap_or_else(|error| panic!("load authorization: {error}"));
    let receipt = security
        .phase_receipt(attempt_id, OperationPhase::BackingUp)
        .unwrap_or_else(|error| panic!("load backup receipt: {error}"));

    let reopened = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("reopen security store: {error}"));
    let replay = BackupOperationDriverV1::new(
        reopened.clone(),
        policies,
        disk,
        VerifiedBackupEffects {
            security: reopened.clone(),
            fence: DeterministicModelEffects::default(),
            applications: Arc::clone(&applications),
        },
    )
    .drive_accepted(&accepted, 3_000)
    .unwrap_or_else(|error| panic!("replay accepted backup: {error}"));
    assert_eq!(replay, first);
    assert_eq!(applications.load(Ordering::Relaxed), 1);
    assert_eq!(
        reopened
            .executor_authorization(attempt_id)
            .unwrap_or_else(|error| panic!("reload authorization: {error}")),
        authorization
    );
    assert_eq!(
        reopened
            .phase_receipt(attempt_id, OperationPhase::BackingUp)
            .unwrap_or_else(|error| panic!("reload backup receipt: {error}")),
        receipt
    );
}

#[test]
fn backup_chain_is_policy_bound_canonical_and_fresh() {
    let policy = rimg_policy(complete_protocols());
    let operation = backup_operation(Uuid::new_v4(), Uuid::new_v4());
    let intent = PhaseIntent::from_operation(&operation, digest("executor authorization"))
        .unwrap_or_else(|error| panic!("phase intent: {error}"));
    let spec = base_backup_spec(&policy, &intent);
    let chain = base_chain(&spec);
    let verified_chain = chain.verified(&spec);

    let artifacts = base_phase_artifacts(
        &spec,
        &chain.manifest,
        &chain.local,
        &chain.upload,
        &chain.offsite,
    )
    .unwrap_or_else(|error| panic!("base artifacts: {error}"));
    assert_eq!(
        artifacts.base_backup_offsite_evidence_digest,
        Some(chain.offsite.evidence_digest.clone())
    );

    let encoded = chain
        .manifest
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode manifest: {error}"));
    assert_eq!(
        BackupManifestV1::decode_canonical(&encoded)
            .unwrap_or_else(|error| panic!("decode manifest: {error}")),
        chain.manifest
    );
    let pretty = serde_json::to_vec_pretty(&chain.manifest)
        .unwrap_or_else(|error| panic!("pretty manifest: {error}"));
    assert!(BackupManifestV1::decode_canonical(&pretty).is_err());

    let clock = TrustedClockEvidenceV1::new(
        true,
        12,
        chain.local.completed_at_ms + 1_000,
        digest("chrony observation"),
    )
    .unwrap_or_else(|error| panic!("clock: {error}"));
    let freshness = BackupFreshnessEvidenceV1::new(
        &verified_chain,
        &clock,
        clock.observed_at_ms,
        60 * 60 * 1_000,
        true,
    )
    .unwrap_or_else(|error| panic!("freshness: {error}"));
    let fresh_clock = TrustedClockEvidenceV1::new(
        true,
        8,
        clock.observed_at_ms + 1_000,
        digest("fresh chrony observation"),
    )
    .unwrap_or_else(|error| panic!("fresh clock: {error}"));
    freshness
        .require_current(
            &verified_chain,
            &fresh_clock,
            fresh_clock.observed_at_ms,
            60 * 60 * 1_000,
            true,
        )
        .unwrap_or_else(|error| panic!("current freshness: {error}"));
}

#[test]
fn backup_substitution_and_stale_or_untrusted_evidence_fail_closed() {
    let policy = rimg_policy(complete_protocols());
    let operation = backup_operation(Uuid::new_v4(), Uuid::new_v4());
    let intent = PhaseIntent::from_operation(&operation, digest("executor authorization"))
        .unwrap_or_else(|error| panic!("phase intent: {error}"));
    let spec = base_backup_spec(&policy, &intent);
    let chain = base_chain(&spec);
    let verified_chain = chain.verified(&spec);

    let mut bad_encryption = chain.local.encryption.clone();
    bad_encryption.recipient_fingerprint = digest("uninstalled recipient");
    assert!(LocalBackupEvidenceV1::new(&spec, &chain.manifest, bad_encryption).is_err());

    let mut bad_checks = manifest_checks();
    bad_checks[0].checked_object_digest = digest("another database");
    assert!(
        BackupManifestV1::new(
            &spec,
            BackupManifestInputV1 {
                application_schema_version: "1".to_owned(),
                started_at_ms: 1_100,
                completed_at_ms: 1_200,
                objects: manifest_objects(),
                checks: bad_checks,
            },
        )
        .is_err()
    );

    assert!(TrustedClockEvidenceV1::new(false, 0, 2_000, digest("unsynchronized clock")).is_err());
    let stale_clock = TrustedClockEvidenceV1::new(
        true,
        0,
        chain.local.completed_at_ms + 60 * 60 * 1_000 + 1,
        digest("stale clock"),
    )
    .unwrap_or_else(|error| panic!("stale clock evidence: {error}"));
    assert!(
        BackupFreshnessEvidenceV1::new(
            &verified_chain,
            &stale_clock,
            stale_clock.observed_at_ms,
            60 * 60 * 1_000,
            true,
        )
        .is_err()
    );
}

#[test]
fn cutover_local_evidence_does_not_change_when_offsite_upload_happens_later() {
    let policy = rimg_policy(complete_protocols());
    let operation = backup_operation(Uuid::new_v4(), Uuid::new_v4());
    let intent = PhaseIntent::from_operation(&operation, digest("executor authorization"))
        .unwrap_or_else(|error| panic!("phase intent: {error}"));
    let base = base_backup_spec(&policy, &intent);
    let fence_receipt = digest("fence receipt");
    let cutover = AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
        attempt_id: intent.attempt_id,
        project_id: project(),
        installed_policy: installed_policy(),
        installed_rimg_policy_digest: policy.digest().clone(),
        phase_intent_digest: intent.digest.clone(),
        backup_set_id: base.backup_set_id,
        backup_id: Uuid::new_v4(),
        snapshot_kind: BackupSnapshotKindV1::Cutover,
        capture_purpose: BackupCapturePurposeV1::DeploymentCutover,
        unit: backup_unit(),
        recipient_fingerprint: digest("age recipient"),
        provider: BackupProviderV1::GoogleDrive,
        provider_credential_version: 1,
        capture_deadline_ms: 2_000,
        fencing_epoch: Some(7),
        fence_receipt_digest: Some(fence_receipt),
    })
    .unwrap_or_else(|error| panic!("cutover spec: {error}"));
    let manifest = BackupManifestV1::new(
        &cutover,
        BackupManifestInputV1 {
            application_schema_version: "1".to_owned(),
            started_at_ms: 1_100,
            completed_at_ms: 1_200,
            objects: manifest_objects(),
            checks: manifest_checks(),
        },
    )
    .unwrap_or_else(|error| panic!("cutover manifest: {error}"));
    let local = LocalBackupEvidenceV1::new(
        &cutover,
        &manifest,
        BackupEncryptionEvidenceV1 {
            algorithm: BackupEncryptionAlgorithmV1::AgeX25519,
            authorized_spec_digest: cutover.spec_digest.clone(),
            backup_id: cutover.backup_id,
            manifest_digest: manifest.manifest_digest.clone(),
            plaintext_archive_digest: digest("cutover plaintext"),
            recipient_fingerprint: digest("age recipient"),
            ciphertext_digest: digest("cutover ciphertext"),
            ciphertext_size_bytes: 9_000,
            encrypted_at_ms: 1_300,
        },
    )
    .unwrap_or_else(|error| panic!("cutover local: {error}"));
    let original_local_digest = local.evidence_digest.clone();
    let artifacts = cutover_phase_artifacts(&cutover, &manifest, &local)
        .unwrap_or_else(|error| panic!("cutover artifacts: {error}"));
    assert_eq!(
        artifacts.cutover_backup_evidence_digest,
        Some(original_local_digest)
    );
}

#[test]
fn phase_spec_uses_only_fixed_profiles_and_requires_installed_rimg_protocols() {
    let operation = backup_operation(Uuid::new_v4(), Uuid::new_v4());
    let intent = PhaseIntent::from_operation(&operation, digest("executor authorization"))
        .unwrap_or_else(|error| panic!("phase intent: {error}"));
    let policy = rimg_policy(complete_protocols());
    let backup = base_backup_spec(&policy, &intent);
    let spec = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent: &intent,
        policy: &policy,
        classification: None,
        backup: Some(backup),
        prerequisites: AuthorizedPhasePrerequisitesV1::default(),
    })
    .unwrap_or_else(|error| panic!("phase spec: {error}"));
    assert_eq!(spec.steps.len(), 4);
    for step in &spec.steps {
        assert_eq!(step.timeout_ms, 300_000);
        let command = step.profile.command();
        assert!(command.executable.starts_with("/usr/libexec/rdashboard/"));
        assert_eq!(command.working_directory, "/job");
        assert!(command.environment_cleared);
        assert!(!command.shell);
        assert!(command.argv.contains(&"/job/request.jcs"));
        assert!(command.argv.contains(&"/job/spec.jcs"));
        assert!(command.argv.contains(&"/job/result.jcs"));
        assert!(command.argv.contains(&"/job/operation-identity.jcs"));

        let request = spec
            .fixed_adapter_request(step.sequence)
            .unwrap_or_else(|error| panic!("fixed adapter request: {error}"));
        let request_bytes = request
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("encode fixed adapter request: {error}"));
        assert_eq!(
            EvidenceDigest::sha256(&request_bytes),
            step.request_document_digest
        );
        assert_eq!(
            FixedAdapterRequestV1::decode_authorized(&request_bytes, &spec, step.sequence)
                .unwrap_or_else(|error| panic!("decode fixed adapter request: {error}")),
            request
        );
    }
    assert_eq!(spec.steps[0].profile, FixedAdapterProfileV1::BackupCapture);
    let encoded = spec
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode phase spec: {error}"));
    assert_eq!(
        AuthorizedPhaseSpecV1::decode_canonical(&encoded)
            .unwrap_or_else(|error| panic!("decode phase spec: {error}")),
        spec
    );

    let mut substituted_request = spec
        .fixed_adapter_request(1)
        .unwrap_or_else(|error| panic!("fixed adapter request: {error}"));
    substituted_request.request_id = Uuid::new_v4();
    let substituted_bytes = substituted_request
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("substituted fixed adapter request: {error}"));
    assert!(matches!(
        FixedAdapterRequestV1::decode_authorized(&substituted_bytes, &spec, 1),
        Err(Phase6ContractError::AdapterRequestMismatch)
    ));
    assert!(matches!(
        spec.fixed_adapter_request(0),
        Err(Phase6ContractError::UnknownAdapterStep(0))
    ));
    let mut substituted_timeout = spec.clone();
    substituted_timeout.steps[0].timeout_ms += 1;
    assert!(
        !substituted_timeout
            .has_valid_digest()
            .unwrap_or_else(|error| panic!("timeout binding: {error}"))
    );

    let unavailable = rimg_policy(RimgProtocolVersionsV1 {
        schema_inspection: None,
        explicit_migration: None,
        persisted_fence: None,
        persisted_drain: None,
        truthful_readiness: None,
        coherent_backup: None,
    });
    let unavailable_backup = base_backup_spec(&unavailable, &intent);
    assert!(matches!(
        AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
            intent: &intent,
            policy: &unavailable,
            classification: None,
            backup: Some(unavailable_backup),
            prerequisites: AuthorizedPhasePrerequisitesV1::default(),
        }),
        Err(Phase6ContractError::RimgProtocolUnavailable)
    ));
}

#[test]
fn security_journal_persists_spec_before_effect_and_binds_observation() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let attempt_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let authorization_digest = digest("executor authorization");
    let operation = backup_operation(attempt_id, request_id);
    let intent = prepare_backup_phase(&security, &operation, &authorization_digest);
    let policy = rimg_policy(complete_protocols());
    let backup = base_backup_spec(&policy, &intent);
    let chain = base_chain(&backup);
    let spec = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent: &intent,
        policy: &policy,
        classification: None,
        backup: Some(backup.clone()),
        prerequisites: AuthorizedPhasePrerequisitesV1::default(),
    })
    .unwrap_or_else(|error| panic!("resolve spec: {error}"));
    bind_phase_spec_idempotently(&security, &operation, &intent, &spec, 121);
    let permit = security
        .authorize_bound_phase_spec(
            attempt_id,
            OperationPhase::BackingUp,
            ExecutorPhaseBranch::Primary,
            121,
        )
        .unwrap_or_else(|error| panic!("phase permit: {error}"));
    assert_eq!(permit.spec_digest, spec.spec_digest);
    security
        .acquire_resource(
            &ExecutionResource::ProjectDeploy(operation.project_id.clone()),
            attempt_id,
            121,
        )
        .unwrap_or_else(|error| panic!("acquire base backup project resource: {error}"));
    let boundary = begin_base_backup_boundary(&security, &operation, 121);
    assert_base_backup_identity(&spec, &boundary);

    let unbound_artifacts = base_phase_artifacts(
        &backup,
        &chain.manifest,
        &chain.local,
        &chain.upload,
        &chain.offsite,
    )
    .unwrap_or_else(|error| panic!("base artifacts: {error}"));
    assert!(matches!(
        security.record_phase_observation(
            attempt_id,
            OperationPhase::BackingUp,
            &intent.digest,
            &digest("backup observation"),
            &unbound_artifacts,
            122,
        ),
        Err(StoreError::AuthorizedPhaseSpecMissing)
    ));

    bind_verified_base_chain(
        &security,
        attempt_id,
        &operation.project_id,
        &spec,
        &backup,
        &chain,
        122,
    );

    let bound_artifacts = spec
        .bind_artifacts(unbound_artifacts)
        .unwrap_or_else(|error| panic!("bind artifacts: {error}"));
    assert_eq!(
        security
            .record_phase_observation(
                attempt_id,
                OperationPhase::BackingUp,
                &intent.digest,
                &digest("backup observation"),
                &bound_artifacts,
                123,
            )
            .unwrap_or_else(|error| panic!("observe backup: {error}")),
        ObservationAcceptance::Accepted
    );
    security
        .mark_phase_verified(attempt_id, OperationPhase::BackingUp, 124)
        .unwrap_or_else(|error| panic!("verify backup: {error}"));
    let receipt = security
        .commit_phase_receipt(attempt_id, OperationPhase::BackingUp, 125)
        .unwrap_or_else(|error| panic!("commit backup: {error}"));
    assert_eq!(
        receipt.artifacts.authorized_phase_spec_digest,
        Some(spec.spec_digest)
    );
    assert!(
        security
            .active_backup_boundary(&operation.project_id)
            .unwrap_or_else(|error| panic!("released base backup boundary: {error}"))
            .is_none()
    );
}

fn begin_base_backup_boundary(
    security: &SecurityStore,
    operation: &OperationRecord,
    now_ms: i64,
) -> BackupBoundaryLease {
    let boundary = security
        .begin_backup_boundary(&operation.project_id, operation.attempt_id, now_ms)
        .unwrap_or_else(|error| panic!("begin base backup boundary: {error}"));
    assert_eq!(
        security
            .begin_backup_boundary(&operation.project_id, operation.attempt_id, now_ms)
            .unwrap_or_else(|error| panic!("replay base backup boundary: {error}")),
        boundary
    );
    assert_eq!(
        security
            .active_backup_boundary(&operation.project_id)
            .unwrap_or_else(|error| panic!("active base backup boundary: {error}")),
        Some(boundary.clone())
    );
    boundary
}

fn assert_base_backup_identity(spec: &AuthorizedPhaseSpecV1, boundary: &BackupBoundaryLease) {
    let identity = AdapterOperationIdentityV1::from_backup_boundary(spec, 1, boundary)
        .unwrap_or_else(|error| panic!("base backup adapter identity: {error}"));
    assert_eq!(identity.kind, AdapterOperationIdentityKindV1::BaseBackup);
    assert_eq!(identity.epoch, boundary.epoch);
    assert_eq!(identity.token, boundary.token);
    let request = spec
        .fixed_adapter_request(1)
        .unwrap_or_else(|error| panic!("base backup capture request: {error}"));
    let bytes = identity
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("base backup identity bytes: {error}"));
    assert_eq!(
        AdapterOperationIdentityV1::decode_authorized(&bytes, spec, &request)
            .unwrap_or_else(|error| panic!("decode base backup identity: {error}")),
        identity
    );
}

fn prepare_backup_phase(
    security: &SecurityStore,
    operation: &OperationRecord,
    authorization_digest: &EvidenceDigest,
) -> PhaseIntent {
    let attempt_id = operation.attempt_id;
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: Uuid::new_v4(),
                digest: authorization_digest.clone(),
                attempt_id,
                project_id: project(),
                expires_at_ms: 10_000,
                disk_reservation: None,
            },
            100,
        )
        .unwrap_or_else(|error| panic!("authorize attempt: {error}"));
    let phases = [OperationPhase::Queued, OperationPhase::BackingUp];
    let queued_intent = digest("queued intent");
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id,
            project_id: &operation.project_id,
            phase: OperationPhase::Queued,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(&phases, false),
            intent_digest: &queued_intent,
            authorization_digest,
            started_at_ms: 110,
        })
        .unwrap_or_else(|error| panic!("begin queued: {error}"));
    assert_eq!(
        security
            .record_phase_observation(
                attempt_id,
                OperationPhase::Queued,
                &queued_intent,
                &digest("queued observation"),
                &PhaseArtifacts::default(),
                111,
            )
            .unwrap_or_else(|error| panic!("observe queued: {error}")),
        ObservationAcceptance::Accepted
    );
    security
        .mark_phase_verified(attempt_id, OperationPhase::Queued, 112)
        .unwrap_or_else(|error| panic!("verify queued: {error}"));
    security
        .commit_phase_receipt(attempt_id, OperationPhase::Queued, 113)
        .unwrap_or_else(|error| panic!("commit queued: {error}"));

    let intent = PhaseIntent::from_operation(operation, authorization_digest.clone())
        .unwrap_or_else(|error| panic!("phase intent: {error}"));
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id,
            project_id: &operation.project_id,
            phase: OperationPhase::BackingUp,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(&phases, false),
            intent_digest: &intent.digest,
            authorization_digest,
            started_at_ms: 120,
        })
        .unwrap_or_else(|error| panic!("begin backup: {error}"));
    intent
}
