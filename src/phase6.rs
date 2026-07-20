use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    backup::{
        AuthorizedBackupSpecV1, BackupProviderV1, BackupSnapshotKindV1, BackupUnitSpecV1,
        MAX_TRUSTED_CLOCK_EVIDENCE_AGE_MS, TrustedClockEvidenceV1, VerifiedBackupChainV1,
    },
    build::{InstalledKamalPolicyV1, ReleaseBundleV1, ReleaseRollbackContractV1},
    domain::{
        EvidenceDigest, ExecutorPhaseBranch, FenceAcquisitionReceiptV1, InstalledPolicyIdentity,
        OperationKind, OperationPhase, PhaseArtifacts, ProjectId, ReleaseClass,
        valid_application_schema_version,
    },
    executor::PhaseIntent,
};

pub const INSTALLED_RIMG_POLICY_SCHEMA_VERSION: u16 = 1;
pub const RELEASE_CLASSIFICATION_SCHEMA_VERSION: u16 = 1;
pub const AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION: u16 = 3;
pub const FIXED_ADAPTER_REQUEST_SCHEMA_VERSION: u16 = 1;
pub const SCHEMA_CONTRACT_EVALUATION_SCHEMA_VERSION: u16 = 1;

const MAX_BACKUP_UNITS: usize = 64;
const MAX_RECIPIENTS: usize = 16;
const MAX_SCHEMA_TRANSITIONS: usize = 128;
const MAX_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
const MAX_RUNTIME_STATE_TTL_MS: i64 = 60_000;
const MAX_MUTATION_GRANT_TTL_MS: i64 = 5 * 60 * 1_000;
const MAX_FIXED_ADAPTER_REQUEST_BYTES: usize = 256 * 1024;
const FIXED_ADAPTER_REQUEST_PURPOSE: &str = "rdashboard.fixed-adapter-request.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgProtocolVersionsV1 {
    pub schema_inspection: Option<u16>,
    pub explicit_migration: Option<u16>,
    pub persisted_fence: Option<u16>,
    pub persisted_drain: Option<u16>,
    pub truthful_readiness: Option<u16>,
    pub coherent_backup: Option<u16>,
}

impl RimgProtocolVersionsV1 {
    #[must_use]
    pub const fn production_ready(self) -> bool {
        matches!(self.schema_inspection, Some(1))
            && matches!(self.explicit_migration, Some(1))
            && matches!(self.persisted_fence, Some(1))
            && matches!(self.persisted_drain, Some(1))
            && matches!(self.truthful_readiness, Some(1))
            && matches!(self.coherent_backup, Some(1))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSchemaTransitionV1 {
    pub from_schema_version: String,
    pub to_schema_version: String,
    pub migration_id: String,
    pub release_class: ReleaseClass,
    pub migration_plan_contract_digest: EvidenceDigest,
    pub data_compatibility_contract_digest: EvidenceDigest,
}

impl InstalledSchemaTransitionV1 {
    fn is_valid(&self) -> bool {
        valid_schema_version(&self.from_schema_version)
            && valid_schema_version(&self.to_schema_version)
            && self.from_schema_version != self.to_schema_version
            && valid_migration_id(&self.migration_id)
            && matches!(
                self.release_class,
                ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking
            )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaContractKindV1 {
    MigrationPlan,
    DataCompatibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaContractVerdictV1 {
    Satisfied,
    Rejected,
}

#[derive(Clone, Debug)]
pub struct SchemaContractEvaluationInputV1<'a> {
    pub intent: &'a PhaseIntent,
    pub policy: &'a InstalledRimgPolicyV1,
    pub kind: SchemaContractKindV1,
    pub current_schema_version: Option<&'a str>,
    pub candidate_schema_version: &'a str,
    pub migration_id: Option<&'a str>,
    pub contract_digest: EvidenceDigest,
    pub verdict: SchemaContractVerdictV1,
    pub observation_digest: EvidenceDigest,
    pub evaluated_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaContractEvaluationEvidenceV1 {
    pub schema_version: u16,
    pub kind: SchemaContractKindV1,
    pub phase_intent_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub current_schema_version: Option<String>,
    pub candidate_schema_version: String,
    pub migration_id: Option<String>,
    pub contract_digest: EvidenceDigest,
    pub verdict: SchemaContractVerdictV1,
    pub observation_digest: EvidenceDigest,
    pub evaluated_at_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SchemaContractEvaluationDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    kind: SchemaContractKindV1,
    phase_intent_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    current_schema_version: &'a Option<String>,
    candidate_schema_version: &'a str,
    migration_id: &'a Option<String>,
    contract_digest: &'a EvidenceDigest,
    verdict: SchemaContractVerdictV1,
    observation_digest: &'a EvidenceDigest,
    evaluated_at_ms: i64,
}

struct SchemaContractBindingContext<'a> {
    kind: SchemaContractKindV1,
    phase_intent_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    current_schema_version: Option<&'a str>,
    candidate_schema_version: &'a str,
    migration_id: Option<&'a str>,
    contract_digest: &'a EvidenceDigest,
    inspected_at_ms: i64,
}

struct SchemaInspectionContractContext<'a> {
    intent: &'a PhaseIntent,
    policy: &'a InstalledRimgPolicyV1,
    current_schema_version: Option<&'a str>,
    candidate_schema_version: &'a str,
    transition: Option<&'a InstalledSchemaTransitionV1>,
    migration_id: Option<&'a str>,
    migration_plan_evidence: Option<&'a SchemaContractEvaluationEvidenceV1>,
    data_compatibility_evidence: &'a SchemaContractEvaluationEvidenceV1,
    inspected_at_ms: i64,
}

impl SchemaContractEvaluationEvidenceV1 {
    pub fn new(input: SchemaContractEvaluationInputV1<'_>) -> Result<Self, Phase6ContractError> {
        if !input.intent.has_valid_digest()?
            || !input.policy.has_valid_digest()?
            || input.intent.project_id != *input.policy.project_id()
            || input.intent.payload.operation_kind == OperationKind::BackupOnly
            || input.kind == SchemaContractKindV1::MigrationPlan
                && input.intent.payload.operation_kind != OperationKind::Deploy
            || !valid_schema_contract_context(
                input.kind,
                input.current_schema_version,
                input.candidate_schema_version,
                input.migration_id,
            )
            || input.evaluated_at_ms < 0
        {
            return Err(Phase6ContractError::InvalidClassification);
        }
        let mut evidence = Self {
            schema_version: SCHEMA_CONTRACT_EVALUATION_SCHEMA_VERSION,
            kind: input.kind,
            phase_intent_digest: input.intent.digest.clone(),
            project_id: input.intent.project_id.clone(),
            installed_policy: input.policy.installed_policy.clone(),
            installed_rimg_policy_digest: input.policy.policy_digest.clone(),
            current_schema_version: input.current_schema_version.map(str::to_owned),
            candidate_schema_version: input.candidate_schema_version.to_owned(),
            migration_id: input.migration_id.map(str::to_owned),
            contract_digest: input.contract_digest,
            verdict: input.verdict,
            observation_digest: input.observation_digest,
            evaluated_at_ms: input.evaluated_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn has_valid_digest(&self) -> Result<bool, Phase6ContractError> {
        if self.schema_version != SCHEMA_CONTRACT_EVALUATION_SCHEMA_VERSION
            || self.installed_policy.version == 0
            || self.evaluated_at_ms < 0
            || !valid_schema_contract_context(
                self.kind,
                self.current_schema_version.as_deref(),
                &self.candidate_schema_version,
                self.migration_id.as_deref(),
            )
        {
            return Ok(false);
        }
        Ok(self.evidence_digest == self.calculate_digest()?)
    }

    fn matches_bindings(
        &self,
        expected: &SchemaContractBindingContext<'_>,
    ) -> Result<bool, Phase6ContractError> {
        Ok(self.has_valid_digest()?
            && self.kind == expected.kind
            && self.verdict == SchemaContractVerdictV1::Satisfied
            && self.phase_intent_digest == *expected.phase_intent_digest
            && self.project_id == *expected.project_id
            && self.installed_policy == *expected.installed_policy
            && self.installed_rimg_policy_digest == *expected.installed_rimg_policy_digest
            && self.current_schema_version.as_deref() == expected.current_schema_version
            && self.candidate_schema_version == expected.candidate_schema_version
            && self.migration_id.as_deref() == expected.migration_id
            && self.contract_digest == *expected.contract_digest
            && self.evaluated_at_ms <= expected.inspected_at_ms)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&SchemaContractEvaluationDigestPayload {
            purpose: "rdashboard.schema-contract-evaluation.v1",
            schema_version: self.schema_version,
            kind: self.kind,
            phase_intent_digest: &self.phase_intent_digest,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            current_schema_version: &self.current_schema_version,
            candidate_schema_version: &self.candidate_schema_version,
            migration_id: &self.migration_id,
            contract_digest: &self.contract_digest,
            verdict: self.verdict,
            observation_digest: &self.observation_digest,
            evaluated_at_ms: self.evaluated_at_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgTimeoutPolicyV1 {
    pub backup_ms: u64,
    pub drain_ms: u64,
    pub migration_ms: u64,
    pub deploy_ms: u64,
    pub readiness_ms: u64,
    pub smoke_ms: u64,
    pub soak_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgDeploymentCapabilitiesV1 {
    pub bootstrap_with_declared_downtime: bool,
    pub stable_routing: bool,
    pub automatic_code_rollback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRimgPolicyInputV1 {
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub protocols: RimgProtocolVersionsV1,
    pub timeouts: RimgTimeoutPolicyV1,
    pub capabilities: RimgDeploymentCapabilitiesV1,
    pub backup_units: Vec<BackupUnitSpecV1>,
    pub backup_recipient_fingerprints: Vec<EvidenceDigest>,
    pub backup_provider: BackupProviderV1,
    pub backup_provider_credential_version: u64,
    pub migration_backup_max_age_ms: i64,
    pub code_only_backup_max_age_ms: i64,
    pub schema_contract_digest: EvidenceDigest,
    pub readiness_contract_digest: EvidenceDigest,
    pub consumer_smoke_contract_digest: EvidenceDigest,
    pub schema_transitions: Vec<InstalledSchemaTransitionV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRimgPolicyV1 {
    schema_version: u16,
    project_id: ProjectId,
    installed_policy: InstalledPolicyIdentity,
    kamal_policy: InstalledKamalPolicyV1,
    protocols: RimgProtocolVersionsV1,
    timeouts: RimgTimeoutPolicyV1,
    capabilities: RimgDeploymentCapabilitiesV1,
    backup_units: Vec<BackupUnitSpecV1>,
    backup_recipient_fingerprints: Vec<EvidenceDigest>,
    backup_provider: BackupProviderV1,
    backup_provider_credential_version: u64,
    migration_backup_max_age_ms: i64,
    code_only_backup_max_age_ms: i64,
    schema_contract_digest: EvidenceDigest,
    readiness_contract_digest: EvidenceDigest,
    consumer_smoke_contract_digest: EvidenceDigest,
    schema_transitions: Vec<InstalledSchemaTransitionV1>,
    policy_digest: EvidenceDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledRimgPolicyWireV1 {
    schema_version: u16,
    project_id: ProjectId,
    installed_policy: InstalledPolicyIdentity,
    kamal_policy: InstalledKamalPolicyV1,
    protocols: RimgProtocolVersionsV1,
    timeouts: RimgTimeoutPolicyV1,
    capabilities: RimgDeploymentCapabilitiesV1,
    backup_units: Vec<BackupUnitSpecV1>,
    backup_recipient_fingerprints: Vec<EvidenceDigest>,
    backup_provider: BackupProviderV1,
    backup_provider_credential_version: u64,
    migration_backup_max_age_ms: i64,
    code_only_backup_max_age_ms: i64,
    schema_contract_digest: EvidenceDigest,
    readiness_contract_digest: EvidenceDigest,
    consumer_smoke_contract_digest: EvidenceDigest,
    schema_transitions: Vec<InstalledSchemaTransitionV1>,
    policy_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct InstalledRimgPolicyDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    kamal_policy: &'a InstalledKamalPolicyV1,
    protocols: RimgProtocolVersionsV1,
    timeouts: RimgTimeoutPolicyV1,
    capabilities: RimgDeploymentCapabilitiesV1,
    backup_units: &'a [BackupUnitSpecV1],
    backup_recipient_fingerprints: &'a [EvidenceDigest],
    backup_provider: BackupProviderV1,
    backup_provider_credential_version: u64,
    migration_backup_max_age_ms: i64,
    code_only_backup_max_age_ms: i64,
    schema_contract_digest: &'a EvidenceDigest,
    readiness_contract_digest: &'a EvidenceDigest,
    consumer_smoke_contract_digest: &'a EvidenceDigest,
    schema_transitions: &'a [InstalledSchemaTransitionV1],
}

impl<'de> Deserialize<'de> for InstalledRimgPolicyV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let wire = InstalledRimgPolicyWireV1::deserialize(deserializer)?;
        let schema_version = wire.schema_version;
        let policy_digest = wire.policy_digest.clone();
        let policy = Self::new(
            InstalledRimgPolicyInputV1 {
                project_id: wire.project_id,
                installed_policy: wire.installed_policy,
                protocols: wire.protocols,
                timeouts: wire.timeouts,
                capabilities: wire.capabilities,
                backup_units: wire.backup_units,
                backup_recipient_fingerprints: wire.backup_recipient_fingerprints,
                backup_provider: wire.backup_provider,
                backup_provider_credential_version: wire.backup_provider_credential_version,
                migration_backup_max_age_ms: wire.migration_backup_max_age_ms,
                code_only_backup_max_age_ms: wire.code_only_backup_max_age_ms,
                schema_contract_digest: wire.schema_contract_digest,
                readiness_contract_digest: wire.readiness_contract_digest,
                consumer_smoke_contract_digest: wire.consumer_smoke_contract_digest,
                schema_transitions: wire.schema_transitions,
            },
            wire.kamal_policy,
        )
        .map_err(D::Error::custom)?;
        if schema_version != INSTALLED_RIMG_POLICY_SCHEMA_VERSION
            || policy.policy_digest != policy_digest
        {
            return Err(D::Error::custom(
                "installed rimg policy derived digest mismatch",
            ));
        }
        Ok(policy)
    }
}

impl InstalledRimgPolicyV1 {
    pub fn new(
        mut input: InstalledRimgPolicyInputV1,
        kamal_policy: InstalledKamalPolicyV1,
    ) -> Result<Self, Phase6ContractError> {
        if input.project_id != *kamal_policy.project_id()
            || input.installed_policy != *kamal_policy.installed_policy()
            || !kamal_policy.has_valid_digest()?
            || input.backup_units.is_empty()
            || input.backup_units.len() > MAX_BACKUP_UNITS
            || input.backup_recipient_fingerprints.is_empty()
            || input.backup_recipient_fingerprints.len() > MAX_RECIPIENTS
            || input.schema_transitions.len() > MAX_SCHEMA_TRANSITIONS
            || input.backup_provider_credential_version == 0
            || !(1..=60 * 60 * 1_000).contains(&input.migration_backup_max_age_ms)
            || !(input.migration_backup_max_age_ms..=24 * 60 * 60 * 1_000)
                .contains(&input.code_only_backup_max_age_ms)
            || !valid_timeouts(input.timeouts)
            || input.capabilities.automatic_code_rollback && !input.capabilities.stable_routing
        {
            return Err(Phase6ContractError::InvalidInstalledPolicy);
        }
        input
            .backup_units
            .sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
        input.backup_recipient_fingerprints.sort();
        input.schema_transitions.sort_by(|left, right| {
            (
                left.from_schema_version.as_str(),
                left.to_schema_version.as_str(),
                left.migration_id.as_str(),
            )
                .cmp(&(
                    right.from_schema_version.as_str(),
                    right.to_schema_version.as_str(),
                    right.migration_id.as_str(),
                ))
        });
        for unit in &input.backup_units {
            if !unit.has_valid_digest()? {
                return Err(Phase6ContractError::InvalidInstalledPolicy);
            }
        }
        if input
            .backup_units
            .windows(2)
            .any(|pair| pair[0].unit_id == pair[1].unit_id)
            || input
                .backup_recipient_fingerprints
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || input
                .schema_transitions
                .iter()
                .any(|value| !value.is_valid())
            || input.schema_transitions.windows(2).any(|pair| {
                pair[0].from_schema_version == pair[1].from_schema_version
                    && pair[0].to_schema_version == pair[1].to_schema_version
            })
        {
            return Err(Phase6ContractError::InvalidInstalledPolicy);
        }
        let mut policy = Self {
            schema_version: INSTALLED_RIMG_POLICY_SCHEMA_VERSION,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            kamal_policy,
            protocols: input.protocols,
            timeouts: input.timeouts,
            capabilities: input.capabilities,
            backup_units: input.backup_units,
            backup_recipient_fingerprints: input.backup_recipient_fingerprints,
            backup_provider: input.backup_provider,
            backup_provider_credential_version: input.backup_provider_credential_version,
            migration_backup_max_age_ms: input.migration_backup_max_age_ms,
            code_only_backup_max_age_ms: input.code_only_backup_max_age_ms,
            schema_contract_digest: input.schema_contract_digest,
            readiness_contract_digest: input.readiness_contract_digest,
            consumer_smoke_contract_digest: input.consumer_smoke_contract_digest,
            schema_transitions: input.schema_transitions,
            policy_digest: EvidenceDigest::sha256([]),
        };
        policy.policy_digest = policy.calculate_digest()?;
        Ok(policy)
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.policy_digest
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Phase6ContractError> {
        let policy: Self = decode_canonical(bytes)?;
        if !policy.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        Ok(policy)
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn installed_policy(&self) -> &InstalledPolicyIdentity {
        &self.installed_policy
    }

    pub const fn protocols(&self) -> RimgProtocolVersionsV1 {
        self.protocols
    }

    pub const fn timeouts(&self) -> RimgTimeoutPolicyV1 {
        self.timeouts
    }

    pub const fn capabilities(&self) -> RimgDeploymentCapabilitiesV1 {
        self.capabilities
    }

    pub const fn schema_contract_digest(&self) -> &EvidenceDigest {
        &self.schema_contract_digest
    }

    pub const fn migration_backup_max_age_ms(&self) -> i64 {
        self.migration_backup_max_age_ms
    }

    pub const fn code_only_backup_max_age_ms(&self) -> i64 {
        self.code_only_backup_max_age_ms
    }

    pub fn backup_unit_by_digest(&self, digest: &EvidenceDigest) -> Option<&BackupUnitSpecV1> {
        self.backup_unit(digest)
    }

    pub fn authorizes_backup_recipient(&self, fingerprint: &EvidenceDigest) -> bool {
        self.backup_recipient_fingerprints.contains(fingerprint)
    }

    pub const fn backup_provider(&self) -> BackupProviderV1 {
        self.backup_provider
    }

    pub const fn backup_provider_credential_version(&self) -> u64 {
        self.backup_provider_credential_version
    }

    fn schema_transition(&self, from: &str, to: &str) -> Option<&InstalledSchemaTransitionV1> {
        self.schema_transitions.iter().find(|transition| {
            transition.from_schema_version == from && transition.to_schema_version == to
        })
    }

    pub fn installed_schema_transition(
        &self,
        from: &str,
        to: &str,
    ) -> Option<InstalledSchemaTransitionV1> {
        self.schema_transition(from, to).cloned()
    }

    pub fn has_valid_digest(&self) -> Result<bool, Phase6ContractError> {
        Ok(self.policy_digest == self.calculate_digest()?
            && self.kamal_policy.has_valid_digest()?)
    }

    fn backup_unit(&self, digest: &EvidenceDigest) -> Option<&BackupUnitSpecV1> {
        self.backup_units
            .iter()
            .find(|unit| &unit.unit_digest == digest)
    }

    fn authorizes_backup_spec(
        &self,
        intent: &PhaseIntent,
        backup: &AuthorizedBackupSpecV1,
    ) -> Result<(), Phase6ContractError> {
        if !backup.has_valid_digest()?
            || backup.project_id != self.project_id
            || backup.installed_policy != self.installed_policy
            || backup.installed_rimg_policy_digest != self.policy_digest
            || backup.phase_intent_digest != intent.digest
            || backup.attempt_id != intent.attempt_id
            || self.backup_unit(&backup.unit.unit_digest).is_none()
            || !self
                .backup_recipient_fingerprints
                .contains(&backup.recipient_fingerprint)
            || backup.provider != self.backup_provider
            || backup.provider_credential_version != self.backup_provider_credential_version
        {
            return Err(Phase6ContractError::UnauthorizedBackupSpec);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&InstalledRimgPolicyDigestPayload {
            purpose: "rdashboard.installed-rimg-policy.v1",
            schema_version: self.schema_version,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            kamal_policy: &self.kamal_policy,
            protocols: self.protocols,
            timeouts: self.timeouts,
            capabilities: self.capabilities,
            backup_units: &self.backup_units,
            backup_recipient_fingerprints: &self.backup_recipient_fingerprints,
            backup_provider: self.backup_provider,
            backup_provider_credential_version: self.backup_provider_credential_version,
            migration_backup_max_age_ms: self.migration_backup_max_age_ms,
            code_only_backup_max_age_ms: self.code_only_backup_max_age_ms,
            schema_contract_digest: &self.schema_contract_digest,
            readiness_contract_digest: &self.readiness_contract_digest,
            consumer_smoke_contract_digest: &self.consumer_smoke_contract_digest,
            schema_transitions: &self.schema_transitions,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SchemaInspectionEvidenceInputV1<'a> {
    pub intent: &'a PhaseIntent,
    pub policy: &'a InstalledRimgPolicyV1,
    pub current_bundle: Option<&'a ReleaseBundleV1>,
    pub candidate_bundle: &'a ReleaseBundleV1,
    pub migration_id: Option<String>,
    pub migration_plan_evidence: Option<&'a SchemaContractEvaluationEvidenceV1>,
    pub data_compatibility_evidence: &'a SchemaContractEvaluationEvidenceV1,
    pub observation_digest: EvidenceDigest,
    pub inspected_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaInspectionEvidenceV1 {
    pub schema_version: u16,
    pub phase_intent_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub schema_contract_digest: EvidenceDigest,
    pub current_release_bundle_digest: Option<EvidenceDigest>,
    pub candidate_release_bundle_digest: EvidenceDigest,
    pub current_schema_version: Option<String>,
    pub candidate_schema_version: String,
    pub migration_id: Option<String>,
    pub schema_transition_digest: Option<EvidenceDigest>,
    pub migration_plan_evidence: Option<SchemaContractEvaluationEvidenceV1>,
    pub data_compatibility_evidence: SchemaContractEvaluationEvidenceV1,
    pub observation_digest: EvidenceDigest,
    pub inspected_at_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SchemaInspectionDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    phase_intent_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    schema_contract_digest: &'a EvidenceDigest,
    current_release_bundle_digest: &'a Option<EvidenceDigest>,
    candidate_release_bundle_digest: &'a EvidenceDigest,
    current_schema_version: &'a Option<String>,
    candidate_schema_version: &'a str,
    migration_id: &'a Option<String>,
    schema_transition_digest: &'a Option<EvidenceDigest>,
    migration_plan_evidence: &'a Option<SchemaContractEvaluationEvidenceV1>,
    data_compatibility_evidence: &'a SchemaContractEvaluationEvidenceV1,
    observation_digest: &'a EvidenceDigest,
    inspected_at_ms: i64,
}

impl SchemaInspectionEvidenceV1 {
    pub fn new(input: SchemaInspectionEvidenceInputV1<'_>) -> Result<Self, Phase6ContractError> {
        input
            .current_bundle
            .map(ReleaseBundleV1::verify)
            .transpose()?;
        input.candidate_bundle.verify()?;
        let current_schema_version = input
            .current_bundle
            .map(|bundle| bundle.application_schema_version().to_owned());
        let candidate_schema_version = input
            .candidate_bundle
            .application_schema_version()
            .to_owned();
        if !input.intent.has_valid_digest()?
            || !input.policy.has_valid_digest()?
            || input.intent.project_id != *input.policy.project_id()
            || input.candidate_bundle.project_id() != input.policy.project_id()
            || input
                .current_bundle
                .is_some_and(|bundle| bundle.project_id() != input.policy.project_id())
            || input.inspected_at_ms < 0
        {
            return Err(Phase6ContractError::InvalidClassification);
        }
        let transition = match current_schema_version.as_deref() {
            Some(current) if current != candidate_schema_version => input
                .policy
                .schema_transition(current, &candidate_schema_version)
                .ok_or(Phase6ContractError::InvalidClassification)?
                .into(),
            _ => None,
        };
        let transition_digest = transition.map(digest_jcs).transpose()?;
        if !schema_inspection_contract_evidence_matches(&SchemaInspectionContractContext {
            intent: input.intent,
            policy: input.policy,
            current_schema_version: current_schema_version.as_deref(),
            candidate_schema_version: &candidate_schema_version,
            transition,
            migration_id: input.migration_id.as_deref(),
            migration_plan_evidence: input.migration_plan_evidence,
            data_compatibility_evidence: input.data_compatibility_evidence,
            inspected_at_ms: input.inspected_at_ms,
        })? {
            return Err(Phase6ContractError::InvalidClassification);
        }
        let mut evidence = Self {
            schema_version: RELEASE_CLASSIFICATION_SCHEMA_VERSION,
            phase_intent_digest: input.intent.digest.clone(),
            project_id: input.intent.project_id.clone(),
            installed_policy: input.policy.installed_policy.clone(),
            installed_rimg_policy_digest: input.policy.policy_digest.clone(),
            schema_contract_digest: input.policy.schema_contract_digest.clone(),
            current_release_bundle_digest: input
                .current_bundle
                .map(|bundle| bundle.digest().clone()),
            candidate_release_bundle_digest: input.candidate_bundle.digest().clone(),
            current_schema_version,
            candidate_schema_version,
            migration_id: input.migration_id,
            schema_transition_digest: transition_digest,
            migration_plan_evidence: input.migration_plan_evidence.cloned(),
            data_compatibility_evidence: input.data_compatibility_evidence.clone(),
            observation_digest: input.observation_digest,
            inspected_at_ms: input.inspected_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn has_valid_digest(&self) -> Result<bool, Phase6ContractError> {
        let stateful = self
            .current_schema_version
            .as_ref()
            .is_some_and(|current| current != &self.candidate_schema_version);
        let migration_evidence_valid = self
            .migration_plan_evidence
            .as_ref()
            .map(SchemaContractEvaluationEvidenceV1::has_valid_digest)
            .transpose()?
            .unwrap_or(true);
        if self.schema_version != RELEASE_CLASSIFICATION_SCHEMA_VERSION
            || self.installed_policy.version == 0
            || self.inspected_at_ms < 0
            || !valid_schema_version(&self.candidate_schema_version)
            || self
                .current_schema_version
                .as_deref()
                .is_some_and(|value| !valid_schema_version(value))
            || stateful != self.migration_id.is_some()
            || stateful != self.schema_transition_digest.is_some()
            || stateful != self.migration_plan_evidence.is_some()
            || !self.data_compatibility_evidence.has_valid_digest()?
            || !migration_evidence_valid
            || !self.embedded_evidence_context_matches()
        {
            return Ok(false);
        }
        Ok(self.evidence_digest == self.calculate_digest()?)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&SchemaInspectionDigestPayload {
            purpose: "rdashboard.schema-inspection-evidence.v1",
            schema_version: self.schema_version,
            phase_intent_digest: &self.phase_intent_digest,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            schema_contract_digest: &self.schema_contract_digest,
            current_release_bundle_digest: &self.current_release_bundle_digest,
            candidate_release_bundle_digest: &self.candidate_release_bundle_digest,
            current_schema_version: &self.current_schema_version,
            candidate_schema_version: &self.candidate_schema_version,
            migration_id: &self.migration_id,
            schema_transition_digest: &self.schema_transition_digest,
            migration_plan_evidence: &self.migration_plan_evidence,
            data_compatibility_evidence: &self.data_compatibility_evidence,
            observation_digest: &self.observation_digest,
            inspected_at_ms: self.inspected_at_ms,
        })
    }

    fn embedded_evidence_context_matches(&self) -> bool {
        let evidence_matches = |evidence: &SchemaContractEvaluationEvidenceV1,
                                kind: SchemaContractKindV1| {
            evidence.kind == kind
                && evidence.verdict == SchemaContractVerdictV1::Satisfied
                && evidence.phase_intent_digest == self.phase_intent_digest
                && evidence.project_id == self.project_id
                && evidence.installed_policy == self.installed_policy
                && evidence.installed_rimg_policy_digest == self.installed_rimg_policy_digest
                && evidence.current_schema_version == self.current_schema_version
                && evidence.candidate_schema_version == self.candidate_schema_version
                && evidence.migration_id == self.migration_id
                && evidence.evaluated_at_ms <= self.inspected_at_ms
        };
        self.migration_plan_evidence
            .as_ref()
            .is_none_or(|evidence| evidence_matches(evidence, SchemaContractKindV1::MigrationPlan))
            && evidence_matches(
                &self.data_compatibility_evidence,
                SchemaContractKindV1::DataCompatibility,
            )
            && (self.migration_plan_evidence.is_some()
                || self.data_compatibility_evidence.contract_digest == self.schema_contract_digest)
    }
}

#[derive(Clone, Debug)]
pub struct ReleaseClassificationInputV1<'a> {
    pub intent: &'a PhaseIntent,
    pub policy: &'a InstalledRimgPolicyV1,
    pub current_bundle: Option<&'a ReleaseBundleV1>,
    pub candidate_bundle: &'a ReleaseBundleV1,
    pub schema_inspection: &'a SchemaInspectionEvidenceV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseClassificationEvidenceV1 {
    pub schema_version: u16,
    pub phase_intent_digest: EvidenceDigest,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub current_release_bundle_digest: Option<EvidenceDigest>,
    pub candidate_release_bundle_digest: EvidenceDigest,
    pub effective_class: ReleaseClass,
    pub current_schema_version: Option<String>,
    pub candidate_schema_version: String,
    pub migration_id: Option<String>,
    pub schema_transition_digest: Option<EvidenceDigest>,
    pub schema_inspection_evidence_digest: EvidenceDigest,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ReleaseClassificationDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    phase_intent_digest: &'a EvidenceDigest,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    current_release_bundle_digest: &'a Option<EvidenceDigest>,
    candidate_release_bundle_digest: &'a EvidenceDigest,
    effective_class: ReleaseClass,
    current_schema_version: &'a Option<String>,
    candidate_schema_version: &'a str,
    migration_id: &'a Option<String>,
    schema_transition_digest: &'a Option<EvidenceDigest>,
    schema_inspection_evidence_digest: &'a EvidenceDigest,
}

impl ReleaseClassificationEvidenceV1 {
    pub fn derive(input: &ReleaseClassificationInputV1<'_>) -> Result<Self, Phase6ContractError> {
        verify_release_bundles(input)?;
        let inspection = input.schema_inspection;
        if !input.intent.has_valid_digest()?
            || !input.policy.has_valid_digest()?
            || !inspection.has_valid_digest()?
            || !classification_authority_bindings_match(input.intent, input.policy)
            || inspection.phase_intent_digest != input.intent.digest
            || inspection.installed_rimg_policy_digest != *input.policy.digest()
            || inspection.installed_policy != *input.policy.installed_policy()
            || inspection.project_id != input.intent.project_id
            || inspection.schema_contract_digest != input.policy.schema_contract_digest
            || inspection.current_release_bundle_digest
                != input.current_bundle.map(|bundle| bundle.digest().clone())
            || inspection.candidate_release_bundle_digest != *input.candidate_bundle.digest()
            || inspection.current_schema_version.as_deref()
                != input
                    .current_bundle
                    .map(ReleaseBundleV1::application_schema_version)
            || inspection.candidate_schema_version
                != input.candidate_bundle.application_schema_version()
            || input.candidate_bundle.project_id() != input.policy.project_id()
            || input
                .current_bundle
                .is_some_and(|bundle| bundle.project_id() != input.policy.project_id())
        {
            return Err(Phase6ContractError::InvalidClassification);
        }
        validate_bundle_bindings(input.intent, input.current_bundle, input.candidate_bundle)?;
        let inspection_transition = match inspection.current_schema_version.as_deref() {
            Some(current) if current != inspection.candidate_schema_version => input
                .policy
                .schema_transition(current, &inspection.candidate_schema_version)
                .ok_or(Phase6ContractError::InvalidClassification)?
                .into(),
            _ => None,
        };
        if !schema_inspection_contract_evidence_matches(&SchemaInspectionContractContext {
            intent: input.intent,
            policy: input.policy,
            current_schema_version: inspection.current_schema_version.as_deref(),
            candidate_schema_version: &inspection.candidate_schema_version,
            transition: inspection_transition,
            migration_id: inspection.migration_id.as_deref(),
            migration_plan_evidence: inspection.migration_plan_evidence.as_ref(),
            data_compatibility_evidence: &inspection.data_compatibility_evidence,
            inspected_at_ms: inspection.inspected_at_ms,
        })? {
            return Err(Phase6ContractError::InvalidClassification);
        }
        let effective_class = match input.intent.payload.operation_kind {
            OperationKind::BackupOnly => return Err(Phase6ContractError::InvalidClassification),
            OperationKind::CodeRollback => {
                let current = input
                    .current_bundle
                    .ok_or(Phase6ContractError::InvalidClassification)?;
                if current.application_schema_version()
                    != input.candidate_bundle.application_schema_version()
                    || current.rollback_contract() != ReleaseRollbackContractV1::CodeOnlyCompatible
                    || inspection.migration_id.is_some()
                {
                    return Err(Phase6ContractError::InvalidClassification);
                }
                ReleaseClass::Rollback
            }
            OperationKind::Deploy => match inspection.current_schema_version.as_deref() {
                None => ReleaseClass::CodeOnlyCompatible,
                Some(current) if current == inspection.candidate_schema_version => {
                    ReleaseClass::CodeOnlyCompatible
                }
                Some(_) => {
                    let transition =
                        inspection_transition.ok_or(Phase6ContractError::InvalidClassification)?;
                    if inspection.migration_id.as_deref() != Some(transition.migration_id.as_str())
                        || inspection.schema_transition_digest != Some(digest_jcs(transition)?)
                    {
                        return Err(Phase6ContractError::InvalidClassification);
                    }
                    transition.release_class
                }
            },
        };
        let mut evidence = Self {
            schema_version: RELEASE_CLASSIFICATION_SCHEMA_VERSION,
            phase_intent_digest: input.intent.digest.clone(),
            installed_rimg_policy_digest: input.policy.digest().clone(),
            current_release_bundle_digest: inspection.current_release_bundle_digest.clone(),
            candidate_release_bundle_digest: inspection.candidate_release_bundle_digest.clone(),
            effective_class,
            current_schema_version: inspection.current_schema_version.clone(),
            candidate_schema_version: inspection.candidate_schema_version.clone(),
            migration_id: inspection.migration_id.clone(),
            schema_transition_digest: inspection.schema_transition_digest.clone(),
            schema_inspection_evidence_digest: inspection.evidence_digest.clone(),
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn has_valid_digest(&self) -> Result<bool, Phase6ContractError> {
        let stateful = matches!(
            self.effective_class,
            ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking
        );
        if self.schema_version != RELEASE_CLASSIFICATION_SCHEMA_VERSION
            || !valid_schema_version(&self.candidate_schema_version)
            || self
                .current_schema_version
                .as_deref()
                .is_some_and(|value| !valid_schema_version(value))
            || stateful != self.migration_id.is_some()
            || stateful != self.schema_transition_digest.is_some()
            || self.effective_class == ReleaseClass::CodeOnlyCompatible
                && self
                    .current_schema_version
                    .as_deref()
                    .is_some_and(|current| current != self.candidate_schema_version)
            || self.effective_class == ReleaseClass::Rollback
                && self.current_schema_version.as_deref()
                    != Some(self.candidate_schema_version.as_str())
        {
            return Ok(false);
        }
        Ok(self.evidence_digest == self.calculate_digest()?)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&ReleaseClassificationDigestPayload {
            purpose: "rdashboard.release-classification-evidence.v1",
            schema_version: self.schema_version,
            phase_intent_digest: &self.phase_intent_digest,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            current_release_bundle_digest: &self.current_release_bundle_digest,
            candidate_release_bundle_digest: &self.candidate_release_bundle_digest,
            effective_class: self.effective_class,
            current_schema_version: &self.current_schema_version,
            candidate_schema_version: &self.candidate_schema_version,
            migration_id: &self.migration_id,
            schema_transition_digest: &self.schema_transition_digest,
            schema_inspection_evidence_digest: &self.schema_inspection_evidence_digest,
        })
    }
}

/// Opaque authority produced by re-deriving release classification from the exact
/// bundles and schema-inspection document. A serialized evidence document alone
/// is intentionally not sufficient to authorize a privileged phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseClassificationAuthorityV1<'a> {
    evidence: ReleaseClassificationEvidenceV1,
    current_bundle: Option<&'a ReleaseBundleV1>,
    candidate_bundle: &'a ReleaseBundleV1,
    schema_inspection: &'a SchemaInspectionEvidenceV1,
}

impl<'a> ReleaseClassificationAuthorityV1<'a> {
    pub fn derive(input: &ReleaseClassificationInputV1<'a>) -> Result<Self, Phase6ContractError> {
        let evidence = ReleaseClassificationEvidenceV1::derive(input)?;
        Ok(Self {
            evidence,
            current_bundle: input.current_bundle,
            candidate_bundle: input.candidate_bundle,
            schema_inspection: input.schema_inspection,
        })
    }

    pub const fn evidence(&self) -> &ReleaseClassificationEvidenceV1 {
        &self.evidence
    }

    fn revalidate(
        &self,
        intent: &PhaseIntent,
        policy: &InstalledRimgPolicyV1,
    ) -> Result<&ReleaseClassificationEvidenceV1, Phase6ContractError> {
        let derived = ReleaseClassificationEvidenceV1::derive(&ReleaseClassificationInputV1 {
            intent,
            policy,
            current_bundle: self.current_bundle,
            candidate_bundle: self.candidate_bundle,
            schema_inspection: self.schema_inspection,
        })?;
        if derived != self.evidence {
            return Err(Phase6ContractError::InvalidClassification);
        }
        Ok(&self.evidence)
    }
}

fn verify_release_bundles(
    input: &ReleaseClassificationInputV1<'_>,
) -> Result<(), Phase6ContractError> {
    input
        .current_bundle
        .map(ReleaseBundleV1::verify)
        .transpose()?;
    Ok(input.candidate_bundle.verify()?)
}

fn classification_authority_bindings_match(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
) -> bool {
    intent.project_id == *policy.project_id()
        && intent.payload.installed_policy.as_ref() == Some(policy.installed_policy())
}

fn schema_inspection_contract_evidence_matches(
    context: &SchemaInspectionContractContext<'_>,
) -> Result<bool, Phase6ContractError> {
    let expected_migration_id = context.transition.map(|value| value.migration_id.as_str());
    let binding = |kind, contract_digest| SchemaContractBindingContext {
        kind,
        phase_intent_digest: &context.intent.digest,
        project_id: &context.intent.project_id,
        installed_policy: context.policy.installed_policy(),
        installed_rimg_policy_digest: context.policy.digest(),
        current_schema_version: context.current_schema_version,
        candidate_schema_version: context.candidate_schema_version,
        migration_id: context.migration_id,
        contract_digest,
        inspected_at_ms: context.inspected_at_ms,
    };
    let migration_plan_matches = match (context.transition, context.migration_plan_evidence) {
        (Some(transition), Some(evidence)) => evidence.matches_bindings(&binding(
            SchemaContractKindV1::MigrationPlan,
            &transition.migration_plan_contract_digest,
        ))?,
        (None, None) => true,
        _ => false,
    };
    let expected_data_compatibility = context
        .transition
        .map_or(&context.policy.schema_contract_digest, |value| {
            &value.data_compatibility_contract_digest
        });
    Ok(context.migration_id == expected_migration_id
        && migration_plan_matches
        && context
            .data_compatibility_evidence
            .matches_bindings(&binding(
                SchemaContractKindV1::DataCompatibility,
                expected_data_compatibility,
            ))?)
}

fn valid_schema_contract_context(
    kind: SchemaContractKindV1,
    current_schema_version: Option<&str>,
    candidate_schema_version: &str,
    migration_id: Option<&str>,
) -> bool {
    if !valid_schema_version(candidate_schema_version)
        || current_schema_version.is_some_and(|value| !valid_schema_version(value))
        || migration_id.is_some_and(|value| !valid_migration_id(value))
    {
        return false;
    }
    let changes_schema =
        current_schema_version.is_some_and(|value| value != candidate_schema_version);
    match kind {
        SchemaContractKindV1::MigrationPlan => changes_schema && migration_id.is_some(),
        SchemaContractKindV1::DataCompatibility => changes_schema == migration_id.is_some(),
    }
}

fn validate_bundle_bindings(
    intent: &PhaseIntent,
    current: Option<&ReleaseBundleV1>,
    candidate: &ReleaseBundleV1,
) -> Result<(), Phase6ContractError> {
    let matches = match intent.payload.operation_kind {
        OperationKind::Deploy => {
            intent.payload.release_bundle_digest.as_ref() == Some(candidate.digest())
                && intent.payload.previous_release_bundle_digest.as_ref()
                    == current.map(ReleaseBundleV1::digest)
        }
        OperationKind::CodeRollback => {
            intent.payload.release_bundle_digest.as_ref() == current.map(ReleaseBundleV1::digest)
                && intent.payload.previous_release_bundle_digest.as_ref()
                    == Some(candidate.digest())
        }
        OperationKind::BackupOnly => false,
    };
    if !matches {
        return Err(Phase6ContractError::InvalidClassification);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReleaseStateV1 {
    NeverInstalled,
    Installed {
        current_release_bundle_digest: EvidenceDigest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeReleaseStateEvidenceInputV1 {
    pub attempt_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub phase_intent_digest: EvidenceDigest,
    pub state: RuntimeReleaseStateV1,
    pub valid_until_ms: i64,
    pub observation_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReleaseStateEvidenceV1 {
    pub schema_version: u16,
    pub attempt_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub phase_intent_digest: EvidenceDigest,
    pub state: RuntimeReleaseStateV1,
    pub observed_at_ms: i64,
    pub valid_until_ms: i64,
    pub trusted_clock_evidence_digest: EvidenceDigest,
    pub observation_digest: EvidenceDigest,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct RuntimeReleaseStateDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: uuid::Uuid,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    phase_intent_digest: &'a EvidenceDigest,
    state: &'a RuntimeReleaseStateV1,
    observed_at_ms: i64,
    valid_until_ms: i64,
    trusted_clock_evidence_digest: &'a EvidenceDigest,
    observation_digest: &'a EvidenceDigest,
}

impl RuntimeReleaseStateEvidenceV1 {
    pub fn observe(
        input: RuntimeReleaseStateEvidenceInputV1,
        clock: &TrustedClockEvidenceV1,
    ) -> Result<Self, Phase6ContractError> {
        clock.require_synchronized()?;
        if input.attempt_id.is_nil()
            || input.installed_policy.version == 0
            || input.valid_until_ms <= clock.observed_at_ms
            || input.valid_until_ms - clock.observed_at_ms > MAX_RUNTIME_STATE_TTL_MS
        {
            return Err(Phase6ContractError::InvalidRuntimeReleaseState);
        }
        let mut evidence = Self {
            schema_version: 1,
            attempt_id: input.attempt_id,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            phase_intent_digest: input.phase_intent_digest,
            state: input.state,
            observed_at_ms: clock.observed_at_ms,
            valid_until_ms: input.valid_until_ms,
            trusted_clock_evidence_digest: clock.evidence_digest.clone(),
            observation_digest: input.observation_digest,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    fn require_current(
        &self,
        intent: &PhaseIntent,
        policy: &InstalledRimgPolicyV1,
        clock: &TrustedClockEvidenceV1,
        boundary_now_ms: i64,
    ) -> Result<(), Phase6ContractError> {
        clock.require_synchronized()?;
        if self.schema_version != 1
            || self.attempt_id != intent.attempt_id
            || self.project_id != intent.project_id
            || self.installed_policy != *policy.installed_policy()
            || self.phase_intent_digest != intent.digest
            || self.trusted_clock_evidence_digest != clock.evidence_digest
            || boundary_now_ms != clock.observed_at_ms
            || boundary_now_ms < self.observed_at_ms
            || boundary_now_ms > self.valid_until_ms
            || self.valid_until_ms - self.observed_at_ms > MAX_RUNTIME_STATE_TTL_MS
            || self.evidence_digest != self.calculate_digest()?
        {
            return Err(Phase6ContractError::InvalidRuntimeReleaseState);
        }
        match &self.state {
            RuntimeReleaseStateV1::NeverInstalled => {
                if intent.payload.previous_release_bundle_digest.is_some() {
                    return Err(Phase6ContractError::InvalidRuntimeReleaseState);
                }
            }
            RuntimeReleaseStateV1::Installed {
                current_release_bundle_digest,
            } => {
                if intent.payload.previous_release_bundle_digest.as_ref()
                    != Some(current_release_bundle_digest)
                {
                    return Err(Phase6ContractError::InvalidRuntimeReleaseState);
                }
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&RuntimeReleaseStateDigestPayload {
            purpose: "rdashboard.runtime-release-state-evidence.v1",
            schema_version: self.schema_version,
            attempt_id: self.attempt_id,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            phase_intent_digest: &self.phase_intent_digest,
            state: &self.state,
            observed_at_ms: self.observed_at_ms,
            valid_until_ms: self.valid_until_ms,
            trusted_clock_evidence_digest: &self.trusted_clock_evidence_digest,
            observation_digest: &self.observation_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatefulBreakingMutationGrantInputV1 {
    pub grant_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub phase_intent_digest: EvidenceDigest,
    pub classification_evidence_digest: EvidenceDigest,
    pub migration_id: String,
    pub valid_until_ms: i64,
    pub approval_evidence_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatefulBreakingMutationGrantV1 {
    pub schema_version: u16,
    pub grant_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub phase_intent_digest: EvidenceDigest,
    pub classification_evidence_digest: EvidenceDigest,
    pub effective_class: ReleaseClass,
    pub migration_id: String,
    pub issued_at_ms: i64,
    pub valid_until_ms: i64,
    pub trusted_clock_evidence_digest: EvidenceDigest,
    pub approval_evidence_digest: EvidenceDigest,
    pub grant_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct StatefulBreakingMutationGrantDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    grant_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    phase_intent_digest: &'a EvidenceDigest,
    classification_evidence_digest: &'a EvidenceDigest,
    effective_class: ReleaseClass,
    migration_id: &'a str,
    issued_at_ms: i64,
    valid_until_ms: i64,
    trusted_clock_evidence_digest: &'a EvidenceDigest,
    approval_evidence_digest: &'a EvidenceDigest,
}

impl StatefulBreakingMutationGrantV1 {
    pub fn issue(
        input: StatefulBreakingMutationGrantInputV1,
        clock: &TrustedClockEvidenceV1,
    ) -> Result<Self, Phase6ContractError> {
        clock.require_synchronized()?;
        if input.grant_id.is_nil()
            || input.attempt_id.is_nil()
            || input.installed_policy.version == 0
            || !valid_migration_id(&input.migration_id)
            || input.valid_until_ms <= clock.observed_at_ms
            || input.valid_until_ms - clock.observed_at_ms > MAX_MUTATION_GRANT_TTL_MS
        {
            return Err(Phase6ContractError::InvalidMutationGrant);
        }
        let mut grant = Self {
            schema_version: 1,
            grant_id: input.grant_id,
            attempt_id: input.attempt_id,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            phase_intent_digest: input.phase_intent_digest,
            classification_evidence_digest: input.classification_evidence_digest,
            effective_class: ReleaseClass::StatefulBreaking,
            migration_id: input.migration_id,
            issued_at_ms: clock.observed_at_ms,
            valid_until_ms: input.valid_until_ms,
            trusted_clock_evidence_digest: clock.evidence_digest.clone(),
            approval_evidence_digest: input.approval_evidence_digest,
            grant_digest: EvidenceDigest::sha256([]),
        };
        grant.grant_digest = grant.calculate_digest()?;
        Ok(grant)
    }

    fn require_current(
        &self,
        intent: &PhaseIntent,
        policy: &InstalledRimgPolicyV1,
        classification: &ReleaseClassificationEvidenceV1,
        clock: &TrustedClockEvidenceV1,
        boundary_now_ms: i64,
    ) -> Result<(), Phase6ContractError> {
        clock.require_synchronized()?;
        if self.schema_version != 1
            || self.grant_id.is_nil()
            || self.attempt_id != intent.attempt_id
            || self.project_id != intent.project_id
            || self.installed_policy != *policy.installed_policy()
            || self.installed_rimg_policy_digest != *policy.digest()
            || self.phase_intent_digest != intent.digest
            || self.classification_evidence_digest != classification.evidence_digest
            || self.effective_class != ReleaseClass::StatefulBreaking
            || classification.effective_class != ReleaseClass::StatefulBreaking
            || Some(self.migration_id.as_str()) != classification.migration_id.as_deref()
            || self.trusted_clock_evidence_digest != clock.evidence_digest
            || boundary_now_ms != clock.observed_at_ms
            || boundary_now_ms < self.issued_at_ms
            || boundary_now_ms > self.valid_until_ms
            || self.valid_until_ms - self.issued_at_ms > MAX_MUTATION_GRANT_TTL_MS
            || self.grant_digest != self.calculate_digest()?
        {
            return Err(Phase6ContractError::InvalidMutationGrant);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&StatefulBreakingMutationGrantDigestPayload {
            purpose: "rdashboard.stateful-breaking-mutation-grant.v1",
            schema_version: self.schema_version,
            grant_id: self.grant_id,
            attempt_id: self.attempt_id,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            phase_intent_digest: &self.phase_intent_digest,
            classification_evidence_digest: &self.classification_evidence_digest,
            effective_class: self.effective_class,
            migration_id: &self.migration_id,
            issued_at_ms: self.issued_at_ms,
            valid_until_ms: self.valid_until_ms,
            trusted_clock_evidence_digest: &self.trusted_clock_evidence_digest,
            approval_evidence_digest: &self.approval_evidence_digest,
        })
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FixedAdapterProfileV1 {
    BackupCapture,
    BackupEncryptAge,
    BackupUploadGoogleDrive,
    BackupReadbackVerify,
    RimgDrain,
    RimgSchemaInspect,
    RimgMigrate,
    RimgReadiness,
    RimgConsumerSmoke,
    RimgSoakObserve,
    KamalBootstrapDeploy,
    KamalCandidateDeploy,
    KamalCodeRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedCommandDefinitionV1 {
    pub executable: &'static str,
    pub argv: &'static [&'static str],
    pub working_directory: &'static str,
    pub environment_cleared: bool,
    pub shell: bool,
}

const BACKUP_CAPTURE_ARGV: &[&str] = &[
    "capture-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const BACKUP_ENCRYPT_ARGV: &[&str] = &[
    "encrypt-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const BACKUP_UPLOAD_ARGV: &[&str] = &[
    "upload-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const BACKUP_READBACK_ARGV: &[&str] = &[
    "readback-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_DRAIN_ARGV: &[&str] = &[
    "drain-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_SCHEMA_ARGV: &[&str] = &[
    "schema-inspect-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_MIGRATE_ARGV: &[&str] = &[
    "migrate-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_READINESS_ARGV: &[&str] = &[
    "readiness-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_SMOKE_ARGV: &[&str] = &[
    "consumer-smoke-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const RIMG_SOAK_ARGV: &[&str] = &[
    "soak-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const KAMAL_BOOTSTRAP_ARGV: &[&str] = &[
    "bootstrap-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const KAMAL_DEPLOY_ARGV: &[&str] = &[
    "deploy-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];
const KAMAL_ROLLBACK_ARGV: &[&str] = &[
    "rollback-v1",
    "--spec",
    "/job/spec.jcs",
    "--request",
    "/job/request.jcs",
    "--result",
    "/job/result.jcs",
    "--inputs",
    "/inputs",
    "--identity",
    "/job/operation-identity.jcs",
];

impl FixedAdapterProfileV1 {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::BackupCapture => "backup-capture",
            Self::BackupEncryptAge => "backup-encrypt-age",
            Self::BackupUploadGoogleDrive => "backup-upload-google-drive",
            Self::BackupReadbackVerify => "backup-readback-verify",
            Self::RimgDrain => "rimg-drain",
            Self::RimgSchemaInspect => "rimg-schema-inspect",
            Self::RimgMigrate => "rimg-migrate",
            Self::RimgReadiness => "rimg-readiness",
            Self::RimgConsumerSmoke => "rimg-consumer-smoke",
            Self::RimgSoakObserve => "rimg-soak-observe",
            Self::KamalBootstrapDeploy => "kamal-bootstrap-deploy",
            Self::KamalCandidateDeploy => "kamal-candidate-deploy",
            Self::KamalCodeRollback => "kamal-code-rollback",
        }
    }

    #[must_use]
    pub const fn command(self) -> FixedCommandDefinitionV1 {
        let (executable, argv) = match self {
            Self::BackupCapture => (
                "/usr/libexec/rdashboard/backup-adapter",
                BACKUP_CAPTURE_ARGV,
            ),
            Self::BackupEncryptAge => (
                "/usr/libexec/rdashboard/backup-adapter",
                BACKUP_ENCRYPT_ARGV,
            ),
            Self::BackupUploadGoogleDrive => {
                ("/usr/libexec/rdashboard/backup-adapter", BACKUP_UPLOAD_ARGV)
            }
            Self::BackupReadbackVerify => (
                "/usr/libexec/rdashboard/backup-adapter",
                BACKUP_READBACK_ARGV,
            ),
            Self::RimgDrain => (
                "/usr/libexec/rdashboard/rimg-admin-adapter",
                RIMG_DRAIN_ARGV,
            ),
            Self::RimgSchemaInspect => (
                "/usr/libexec/rdashboard/rimg-admin-adapter",
                RIMG_SCHEMA_ARGV,
            ),
            Self::RimgMigrate => (
                "/usr/libexec/rdashboard/rimg-admin-adapter",
                RIMG_MIGRATE_ARGV,
            ),
            Self::RimgReadiness => (
                "/usr/libexec/rdashboard/rimg-admin-adapter",
                RIMG_READINESS_ARGV,
            ),
            Self::RimgConsumerSmoke => (
                "/usr/libexec/rdashboard/rimg-admin-adapter",
                RIMG_SMOKE_ARGV,
            ),
            Self::RimgSoakObserve => ("/usr/libexec/rdashboard/rimg-admin-adapter", RIMG_SOAK_ARGV),
            Self::KamalBootstrapDeploy => (
                "/usr/libexec/rdashboard/kamal-adapter",
                KAMAL_BOOTSTRAP_ARGV,
            ),
            Self::KamalCandidateDeploy => {
                ("/usr/libexec/rdashboard/kamal-adapter", KAMAL_DEPLOY_ARGV)
            }
            Self::KamalCodeRollback => {
                ("/usr/libexec/rdashboard/kamal-adapter", KAMAL_ROLLBACK_ARGV)
            }
        };
        FixedCommandDefinitionV1 {
            executable,
            argv,
            working_directory: "/job",
            environment_cleared: true,
            shell: false,
        }
    }
}

impl RimgTimeoutPolicyV1 {
    pub const fn for_profile(self, profile: FixedAdapterProfileV1) -> u64 {
        match profile {
            FixedAdapterProfileV1::BackupCapture
            | FixedAdapterProfileV1::BackupEncryptAge
            | FixedAdapterProfileV1::BackupUploadGoogleDrive
            | FixedAdapterProfileV1::BackupReadbackVerify => self.backup_ms,
            FixedAdapterProfileV1::RimgDrain => self.drain_ms,
            FixedAdapterProfileV1::RimgSchemaInspect | FixedAdapterProfileV1::RimgMigrate => {
                self.migration_ms
            }
            FixedAdapterProfileV1::RimgReadiness => self.readiness_ms,
            FixedAdapterProfileV1::RimgConsumerSmoke => self.smoke_ms,
            FixedAdapterProfileV1::RimgSoakObserve => self.soak_ms,
            FixedAdapterProfileV1::KamalBootstrapDeploy
            | FixedAdapterProfileV1::KamalCandidateDeploy
            | FixedAdapterProfileV1::KamalCodeRollback => self.deploy_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterResultSchemaV1 {
    BackupManifest,
    LocalBackupEvidence,
    ProviderUploadReceipt,
    OffsiteVerificationEvidence,
    DrainEvidence,
    SchemaInspectionEvidence,
    MigrationEvidence,
    DeploymentEvidence,
    ReadinessEvidence,
    ConsumerSmokeEvidence,
    SoakEvidence,
    RollbackEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPhaseStepV1 {
    pub sequence: u16,
    pub profile: FixedAdapterProfileV1,
    pub timeout_ms: u64,
    pub request_document_digest: EvidenceDigest,
    pub result_schema: AdapterResultSchemaV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedAdapterRequestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub attempt_id: uuid::Uuid,
    pub request_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub sequence: u16,
    pub profile: FixedAdapterProfileV1,
    pub result_schema: AdapterResultSchemaV1,
    pub timeout_ms: u64,
    pub intent_digest: EvidenceDigest,
    pub executor_authorization_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub deployment_plan_digest: Option<EvidenceDigest>,
    pub proposed_release_class: Option<ReleaseClass>,
    pub effective_release_class: Option<ReleaseClass>,
    pub classification_evidence_digest: Option<EvidenceDigest>,
    pub migration_id: Option<String>,
    pub backup: Option<AuthorizedBackupSpecV1>,
    pub verified_base_backup_chain_digest: Option<EvidenceDigest>,
    pub verified_cutover_backup_chain_digest: Option<EvidenceDigest>,
    pub trusted_clock_evidence_digest: Option<EvidenceDigest>,
    pub boundary_now_ms: Option<i64>,
    pub prerequisites_valid_through_ms: Option<i64>,
    pub fencing_epoch: Option<u64>,
    pub fence_receipt_digest: Option<EvidenceDigest>,
    pub mutation_grant_id: Option<uuid::Uuid>,
    pub mutation_grant_digest: Option<EvidenceDigest>,
    pub runtime_release_state: Option<RuntimeReleaseStateV1>,
    pub runtime_release_state_evidence_digest: Option<EvidenceDigest>,
    pub expected_observation_artifacts: PhaseArtifacts,
}

impl FixedAdapterRequestV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Phase6ContractError> {
        let bytes = serde_jcs::to_vec(self)?;
        if bytes.len() > MAX_FIXED_ADAPTER_REQUEST_BYTES {
            return Err(Phase6ContractError::AdapterRequestTooLarge);
        }
        Ok(bytes)
    }

    pub fn decode_authorized(
        bytes: &[u8],
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
    ) -> Result<Self, Phase6ContractError> {
        if bytes.is_empty() || bytes.len() > MAX_FIXED_ADAPTER_REQUEST_BYTES {
            return Err(Phase6ContractError::AdapterRequestTooLarge);
        }
        let request: Self = decode_canonical(bytes)?;
        let expected = spec.fixed_adapter_request(sequence)?;
        if request != expected || EvidenceDigest::sha256(bytes) != expected.digest()? {
            return Err(Phase6ContractError::AdapterRequestMismatch);
        }
        Ok(request)
    }

    pub fn digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        Ok(EvidenceDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorizedPhasePrerequisitesV1<'a> {
    pub base_backup_chain: Option<&'a VerifiedBackupChainV1>,
    pub cutover_backup_chain: Option<&'a VerifiedBackupChainV1>,
    pub trusted_clock: Option<&'a TrustedClockEvidenceV1>,
    pub boundary_now_ms: Option<i64>,
    pub fence_receipt: Option<&'a FenceAcquisitionReceiptV1>,
    pub mutation_grant: Option<&'a StatefulBreakingMutationGrantV1>,
    pub runtime_release_state: Option<&'a RuntimeReleaseStateEvidenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPhaseSpecInputV1<'a> {
    pub intent: &'a PhaseIntent,
    pub policy: &'a InstalledRimgPolicyV1,
    pub classification: Option<&'a ReleaseClassificationAuthorityV1<'a>>,
    pub backup: Option<AuthorizedBackupSpecV1>,
    pub prerequisites: AuthorizedPhasePrerequisitesV1<'a>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPhaseSpecV1 {
    pub schema_version: u16,
    pub attempt_id: uuid::Uuid,
    pub request_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub intent_digest: EvidenceDigest,
    pub executor_authorization_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub deployment_plan_digest: Option<EvidenceDigest>,
    pub timeouts: RimgTimeoutPolicyV1,
    pub proposed_release_class: Option<ReleaseClass>,
    pub effective_release_class: Option<ReleaseClass>,
    pub classification_evidence_digest: Option<EvidenceDigest>,
    pub migration_id: Option<String>,
    pub backup: Option<AuthorizedBackupSpecV1>,
    pub verified_base_backup_chain_digest: Option<EvidenceDigest>,
    pub verified_cutover_backup_chain_digest: Option<EvidenceDigest>,
    pub trusted_clock_evidence_digest: Option<EvidenceDigest>,
    pub boundary_now_ms: Option<i64>,
    pub prerequisites_valid_through_ms: Option<i64>,
    pub fencing_epoch: Option<u64>,
    pub fence_receipt_digest: Option<EvidenceDigest>,
    pub mutation_grant_id: Option<uuid::Uuid>,
    pub mutation_grant_digest: Option<EvidenceDigest>,
    pub runtime_release_state: Option<RuntimeReleaseStateV1>,
    pub runtime_release_state_evidence_digest: Option<EvidenceDigest>,
    pub expected_observation_artifacts: PhaseArtifacts,
    pub steps: Vec<AuthorizedPhaseStepV1>,
    pub spec_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct AuthorizedPhaseSpecDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: uuid::Uuid,
    request_id: uuid::Uuid,
    project_id: &'a ProjectId,
    operation_kind: OperationKind,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    intent_digest: &'a EvidenceDigest,
    executor_authorization_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    release_bundle_digest: &'a Option<EvidenceDigest>,
    deployment_plan_digest: &'a Option<EvidenceDigest>,
    timeouts: RimgTimeoutPolicyV1,
    proposed_release_class: Option<ReleaseClass>,
    effective_release_class: Option<ReleaseClass>,
    classification_evidence_digest: &'a Option<EvidenceDigest>,
    migration_id: &'a Option<String>,
    backup: &'a Option<AuthorizedBackupSpecV1>,
    verified_base_backup_chain_digest: &'a Option<EvidenceDigest>,
    verified_cutover_backup_chain_digest: &'a Option<EvidenceDigest>,
    trusted_clock_evidence_digest: &'a Option<EvidenceDigest>,
    boundary_now_ms: Option<i64>,
    prerequisites_valid_through_ms: Option<i64>,
    fencing_epoch: Option<u64>,
    fence_receipt_digest: &'a Option<EvidenceDigest>,
    mutation_grant_id: Option<uuid::Uuid>,
    mutation_grant_digest: &'a Option<EvidenceDigest>,
    runtime_release_state: &'a Option<RuntimeReleaseStateV1>,
    runtime_release_state_evidence_digest: &'a Option<EvidenceDigest>,
    expected_observation_artifacts: &'a PhaseArtifacts,
    steps: &'a [AuthorizedPhaseStepV1],
}

#[derive(Default)]
struct ResolvedPhasePrerequisitesV1 {
    verified_base_backup_chain_digest: Option<EvidenceDigest>,
    verified_cutover_backup_chain_digest: Option<EvidenceDigest>,
    trusted_clock_evidence_digest: Option<EvidenceDigest>,
    boundary_now_ms: Option<i64>,
    prerequisites_valid_through_ms: Option<i64>,
    fencing_epoch: Option<u64>,
    fence_receipt_digest: Option<EvidenceDigest>,
    mutation_grant_id: Option<uuid::Uuid>,
    mutation_grant_digest: Option<EvidenceDigest>,
    runtime_release_state: Option<RuntimeReleaseStateV1>,
    runtime_release_state_evidence_digest: Option<EvidenceDigest>,
}

#[derive(Default)]
struct ResolvedMutationGrantV1 {
    grant_id: Option<uuid::Uuid>,
    digest: Option<EvidenceDigest>,
    valid_through_ms: Option<i64>,
}

#[derive(Default)]
struct ResolvedRuntimeStateV1 {
    state: Option<RuntimeReleaseStateV1>,
    evidence_digest: Option<EvidenceDigest>,
    valid_through_ms: Option<i64>,
}

impl AuthorizedPhaseSpecV1 {
    pub fn resolve(input: AuthorizedPhaseSpecInputV1<'_>) -> Result<Self, Phase6ContractError> {
        let intent = input.intent;
        let policy = input.policy;
        if !intent.has_valid_digest()?
            || !policy.has_valid_digest()?
            || intent.project_id != *policy.project_id()
            || intent.payload.installed_policy.as_ref() != Some(policy.installed_policy())
        {
            return Err(Phase6ContractError::AuthorizationMismatch);
        }
        let classification = validate_classification(intent, policy, input.classification)?;
        let classification_evidence = input
            .classification
            .map(ReleaseClassificationAuthorityV1::evidence);
        if intent.payload.release_class != classification.effective_class {
            return Err(Phase6ContractError::ClassificationPlanMismatch);
        }
        if !policy.protocols.production_ready() {
            return Err(Phase6ContractError::RimgProtocolUnavailable);
        }
        if let Some(backup) = input.backup.as_ref() {
            policy.authorizes_backup_spec(intent, backup)?;
        }
        let prerequisites = resolve_prerequisites(
            intent,
            policy,
            classification.effective_class,
            classification_evidence,
            &input.prerequisites,
        )?;
        validate_phase_authority(
            intent,
            policy,
            classification.effective_class,
            input.backup.as_ref(),
            &prerequisites,
        )?;
        let installed_policy = intent
            .payload
            .installed_policy
            .clone()
            .ok_or(Phase6ContractError::AuthorizationMismatch)?;
        let expected_observation_artifacts = expected_observation_artifacts(
            intent,
            classification.candidate_schema_version.as_deref(),
        )?;
        let (release_bundle_digest, deployment_plan_digest) = if matches!(
            intent.phase,
            OperationPhase::Deploying
                | OperationPhase::HealthChecking
                | OperationPhase::Soaking
                | OperationPhase::Rollback
        ) {
            (
                intent.payload.release_bundle_digest.clone(),
                intent.payload.deployment_plan_digest.clone(),
            )
        } else {
            (None, None)
        };
        let mut spec = Self {
            schema_version: AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION,
            attempt_id: intent.attempt_id,
            request_id: intent.payload.request_id,
            project_id: intent.project_id.clone(),
            operation_kind: intent.payload.operation_kind,
            phase: intent.phase,
            branch: intent.branch,
            intent_digest: intent.digest.clone(),
            executor_authorization_digest: intent.payload.executor_authorization_digest.clone(),
            installed_policy,
            installed_rimg_policy_digest: policy.policy_digest.clone(),
            release_bundle_digest,
            deployment_plan_digest,
            timeouts: policy.timeouts,
            proposed_release_class: intent.payload.release_class,
            effective_release_class: classification.effective_class,
            classification_evidence_digest: classification.evidence_digest,
            migration_id: classification.migration_id,
            backup: input.backup,
            verified_base_backup_chain_digest: prerequisites.verified_base_backup_chain_digest,
            verified_cutover_backup_chain_digest: prerequisites
                .verified_cutover_backup_chain_digest,
            trusted_clock_evidence_digest: prerequisites.trusted_clock_evidence_digest,
            boundary_now_ms: prerequisites.boundary_now_ms,
            prerequisites_valid_through_ms: prerequisites.prerequisites_valid_through_ms,
            fencing_epoch: prerequisites.fencing_epoch,
            fence_receipt_digest: prerequisites.fence_receipt_digest,
            mutation_grant_id: prerequisites.mutation_grant_id,
            mutation_grant_digest: prerequisites.mutation_grant_digest,
            runtime_release_state: prerequisites.runtime_release_state,
            runtime_release_state_evidence_digest: prerequisites
                .runtime_release_state_evidence_digest,
            expected_observation_artifacts,
            steps: Vec::new(),
            spec_digest: EvidenceDigest::sha256([]),
        };
        spec.steps = spec.expected_steps()?;
        spec.spec_digest = spec.calculate_digest()?;
        Ok(spec)
    }

    pub fn has_valid_digest(&self) -> Result<bool, Phase6ContractError> {
        if self.schema_version != AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION
            || self.attempt_id.is_nil()
            || self.request_id.is_nil()
            || self.installed_policy.version == 0
            || !valid_timeouts(self.timeouts)
            || self.steps.is_empty()
            || self.proposed_release_class != self.effective_release_class
            || !valid_expected_observation_artifacts(
                self.phase,
                &self.expected_observation_artifacts,
            )
            || self.expected_steps().is_err()
        {
            return Ok(false);
        }
        Ok(self.steps == self.expected_steps()? && self.spec_digest == self.calculate_digest()?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Phase6ContractError> {
        if !self.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn fixed_adapter_request(
        &self,
        sequence: u16,
    ) -> Result<FixedAdapterRequestV1, Phase6ContractError> {
        if !self.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        let step = self
            .steps
            .iter()
            .find(|step| step.sequence == sequence)
            .ok_or(Phase6ContractError::UnknownAdapterStep(sequence))?;
        let request = self.build_adapter_request(
            step.sequence,
            step.profile,
            step.result_schema,
            step.timeout_ms,
        );
        if request.digest()? != step.request_document_digest {
            return Err(Phase6ContractError::AdapterRequestMismatch);
        }
        Ok(request)
    }

    pub fn bind_artifacts(
        &self,
        mut artifacts: PhaseArtifacts,
    ) -> Result<PhaseArtifacts, Phase6ContractError> {
        if !self.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        artifacts.authorized_phase_spec_digest = Some(self.spec_digest.clone());
        self.validate_observed_artifacts(&artifacts)?;
        Ok(artifacts)
    }

    pub fn validate_observed_artifacts(
        &self,
        artifacts: &PhaseArtifacts,
    ) -> Result<(), Phase6ContractError> {
        if !self.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        artifacts
            .validate_for_phase(self.phase)
            .map_err(|_| Phase6ContractError::ObservedArtifactMismatch)?;
        if observed_artifacts_match_expected(&self.expected_observation_artifacts, artifacts) {
            Ok(())
        } else {
            Err(Phase6ContractError::ObservedArtifactMismatch)
        }
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Phase6ContractError> {
        let spec: Self = decode_canonical(bytes)?;
        if !spec.has_valid_digest()? {
            return Err(Phase6ContractError::DigestMismatch);
        }
        Ok(spec)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, Phase6ContractError> {
        digest_jcs(&AuthorizedPhaseSpecDigestPayload {
            purpose: "rdashboard.authorized-phase-spec.v1",
            schema_version: self.schema_version,
            attempt_id: self.attempt_id,
            request_id: self.request_id,
            project_id: &self.project_id,
            operation_kind: self.operation_kind,
            phase: self.phase,
            branch: self.branch,
            intent_digest: &self.intent_digest,
            executor_authorization_digest: &self.executor_authorization_digest,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            release_bundle_digest: &self.release_bundle_digest,
            deployment_plan_digest: &self.deployment_plan_digest,
            timeouts: self.timeouts,
            proposed_release_class: self.proposed_release_class,
            effective_release_class: self.effective_release_class,
            classification_evidence_digest: &self.classification_evidence_digest,
            migration_id: &self.migration_id,
            backup: &self.backup,
            verified_base_backup_chain_digest: &self.verified_base_backup_chain_digest,
            verified_cutover_backup_chain_digest: &self.verified_cutover_backup_chain_digest,
            trusted_clock_evidence_digest: &self.trusted_clock_evidence_digest,
            boundary_now_ms: self.boundary_now_ms,
            prerequisites_valid_through_ms: self.prerequisites_valid_through_ms,
            fencing_epoch: self.fencing_epoch,
            fence_receipt_digest: &self.fence_receipt_digest,
            mutation_grant_id: self.mutation_grant_id,
            mutation_grant_digest: &self.mutation_grant_digest,
            runtime_release_state: &self.runtime_release_state,
            runtime_release_state_evidence_digest: &self.runtime_release_state_evidence_digest,
            expected_observation_artifacts: &self.expected_observation_artifacts,
            steps: &self.steps,
        })
    }

    fn expected_steps(&self) -> Result<Vec<AuthorizedPhaseStepV1>, Phase6ContractError> {
        let profiles = expected_profiles(self)?;
        let mut seen = BTreeSet::new();
        profiles
            .into_iter()
            .enumerate()
            .map(|(index, (profile, result_schema))| {
                if !seen.insert(profile) {
                    return Err(Phase6ContractError::DuplicateAdapterStep);
                }
                let sequence = u16::try_from(index + 1)
                    .map_err(|_| Phase6ContractError::DuplicateAdapterStep)?;
                let timeout_ms = self.timeouts.for_profile(profile);
                let request_document_digest = self
                    .build_adapter_request(sequence, profile, result_schema, timeout_ms)
                    .digest()?;
                Ok(AuthorizedPhaseStepV1 {
                    sequence,
                    profile,
                    timeout_ms,
                    request_document_digest,
                    result_schema,
                })
            })
            .collect()
    }

    fn build_adapter_request(
        &self,
        sequence: u16,
        profile: FixedAdapterProfileV1,
        result_schema: AdapterResultSchemaV1,
        timeout_ms: u64,
    ) -> FixedAdapterRequestV1 {
        FixedAdapterRequestV1 {
            purpose: FIXED_ADAPTER_REQUEST_PURPOSE.to_owned(),
            schema_version: FIXED_ADAPTER_REQUEST_SCHEMA_VERSION,
            attempt_id: self.attempt_id,
            request_id: self.request_id,
            project_id: self.project_id.clone(),
            operation_kind: self.operation_kind,
            phase: self.phase,
            branch: self.branch,
            sequence,
            profile,
            result_schema,
            timeout_ms,
            intent_digest: self.intent_digest.clone(),
            executor_authorization_digest: self.executor_authorization_digest.clone(),
            installed_policy: self.installed_policy.clone(),
            installed_rimg_policy_digest: self.installed_rimg_policy_digest.clone(),
            release_bundle_digest: self.release_bundle_digest.clone(),
            deployment_plan_digest: self.deployment_plan_digest.clone(),
            proposed_release_class: self.proposed_release_class,
            effective_release_class: self.effective_release_class,
            classification_evidence_digest: self.classification_evidence_digest.clone(),
            migration_id: self.migration_id.clone(),
            backup: self.backup.clone(),
            verified_base_backup_chain_digest: self.verified_base_backup_chain_digest.clone(),
            verified_cutover_backup_chain_digest: self.verified_cutover_backup_chain_digest.clone(),
            trusted_clock_evidence_digest: self.trusted_clock_evidence_digest.clone(),
            boundary_now_ms: self.boundary_now_ms,
            prerequisites_valid_through_ms: self.prerequisites_valid_through_ms,
            fencing_epoch: self.fencing_epoch,
            fence_receipt_digest: self.fence_receipt_digest.clone(),
            mutation_grant_id: self.mutation_grant_id,
            mutation_grant_digest: self.mutation_grant_digest.clone(),
            runtime_release_state: self.runtime_release_state.clone(),
            runtime_release_state_evidence_digest: self
                .runtime_release_state_evidence_digest
                .clone(),
            expected_observation_artifacts: self.expected_observation_artifacts.clone(),
        }
    }
}

struct ValidatedClassificationV1 {
    effective_class: Option<ReleaseClass>,
    evidence_digest: Option<EvidenceDigest>,
    migration_id: Option<String>,
    candidate_schema_version: Option<String>,
}

fn validate_classification(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    classification: Option<&ReleaseClassificationAuthorityV1<'_>>,
) -> Result<ValidatedClassificationV1, Phase6ContractError> {
    match intent.payload.operation_kind {
        OperationKind::BackupOnly => {
            if classification.is_some() || intent.payload.release_class.is_some() {
                return Err(Phase6ContractError::InvalidClassification);
            }
            Ok(ValidatedClassificationV1 {
                effective_class: None,
                evidence_digest: None,
                migration_id: None,
                candidate_schema_version: None,
            })
        }
        OperationKind::Deploy | OperationKind::CodeRollback => {
            let evidence = classification
                .ok_or(Phase6ContractError::InvalidClassification)?
                .revalidate(intent, policy)?;
            if !evidence.has_valid_digest()?
                || evidence.phase_intent_digest != intent.digest
                || evidence.installed_rimg_policy_digest != *policy.digest()
            {
                return Err(Phase6ContractError::InvalidClassification);
            }
            Ok(ValidatedClassificationV1 {
                effective_class: Some(evidence.effective_class),
                evidence_digest: Some(evidence.evidence_digest.clone()),
                migration_id: evidence.migration_id.clone(),
                candidate_schema_version: Some(evidence.candidate_schema_version.clone()),
            })
        }
    }
}

fn resolve_prerequisites(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    effective_class: Option<ReleaseClass>,
    classification: Option<&ReleaseClassificationEvidenceV1>,
    input: &AuthorizedPhasePrerequisitesV1<'_>,
) -> Result<ResolvedPhasePrerequisitesV1, Phase6ContractError> {
    let (clock, boundary_now_ms) = resolve_boundary_clock(input)?;
    let (verified_base_backup_chain_digest, base_backup_valid_through_ms) =
        resolve_base_backup_chain(
            intent,
            policy,
            effective_class,
            input.base_backup_chain,
            clock,
            boundary_now_ms,
        )?;
    let (fencing_epoch, fence_receipt_digest) =
        resolve_fence_receipt(intent, input.fence_receipt, boundary_now_ms)?;
    let verified_cutover_backup_chain_digest = resolve_cutover_backup_chain(
        intent,
        policy,
        input.cutover_backup_chain,
        input.fence_receipt,
    )?;
    let mutation_grant = resolve_mutation_grant(
        intent,
        policy,
        classification,
        input.mutation_grant,
        clock,
        boundary_now_ms,
    )?;
    let runtime_state = resolve_runtime_state(
        intent,
        policy,
        input.runtime_release_state,
        clock,
        boundary_now_ms,
    )?;
    let clock_valid_through_ms = clock
        .map(|value| {
            value
                .observed_at_ms
                .checked_add(MAX_TRUSTED_CLOCK_EVIDENCE_AGE_MS)
                .ok_or(Phase6ContractError::UntrustedBoundaryTime)
        })
        .transpose()?;
    let prerequisites_valid_through_ms = [
        clock_valid_through_ms,
        base_backup_valid_through_ms,
        mutation_grant.valid_through_ms,
        runtime_state.valid_through_ms,
    ]
    .into_iter()
    .flatten()
    .min();

    Ok(ResolvedPhasePrerequisitesV1 {
        verified_base_backup_chain_digest,
        verified_cutover_backup_chain_digest,
        trusted_clock_evidence_digest: clock.map(|value| value.evidence_digest.clone()),
        boundary_now_ms,
        prerequisites_valid_through_ms,
        fencing_epoch,
        fence_receipt_digest,
        mutation_grant_id: mutation_grant.grant_id,
        mutation_grant_digest: mutation_grant.digest,
        runtime_release_state: runtime_state.state,
        runtime_release_state_evidence_digest: runtime_state.evidence_digest,
    })
}

fn resolve_boundary_clock<'a>(
    input: &AuthorizedPhasePrerequisitesV1<'a>,
) -> Result<(Option<&'a TrustedClockEvidenceV1>, Option<i64>), Phase6ContractError> {
    let needs_clock = input.base_backup_chain.is_some()
        || input.mutation_grant.is_some()
        || input.runtime_release_state.is_some();
    if !needs_clock {
        if input.trusted_clock.is_some() || input.boundary_now_ms.is_some() {
            return Err(Phase6ContractError::MissingPhasePrerequisite);
        }
        return Ok((None, None));
    }
    let clock = input
        .trusted_clock
        .ok_or(Phase6ContractError::MissingPhasePrerequisite)?;
    let boundary_now_ms = input
        .boundary_now_ms
        .ok_or(Phase6ContractError::MissingPhasePrerequisite)?;
    clock.require_synchronized()?;
    if boundary_now_ms != clock.observed_at_ms {
        return Err(Phase6ContractError::UntrustedBoundaryTime);
    }
    Ok((Some(clock), Some(boundary_now_ms)))
}

fn resolve_base_backup_chain(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    effective_class: Option<ReleaseClass>,
    chain: Option<&VerifiedBackupChainV1>,
    clock: Option<&TrustedClockEvidenceV1>,
    boundary_now_ms: Option<i64>,
) -> Result<(Option<EvidenceDigest>, Option<i64>), Phase6ContractError> {
    let Some(chain) = chain else {
        return Ok((None, None));
    };
    chain.require_verified()?;
    let spec = chain.authorized_spec();
    let offsite = chain
        .offsite()
        .ok_or(Phase6ContractError::MissingPhasePrerequisite)?;
    let clock = clock.ok_or(Phase6ContractError::MissingPhasePrerequisite)?;
    let now = boundary_now_ms.ok_or(Phase6ContractError::MissingPhasePrerequisite)?;
    let max_age_ms = if matches!(
        effective_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    ) {
        policy.migration_backup_max_age_ms
    } else {
        policy.code_only_backup_max_age_ms
    };
    let verification_completed_at_ms = chain.verification_completed_at_ms()?;
    let snapshot_completed_at_ms = chain.local().completed_at_ms;
    let matches = chain.snapshot_kind() == BackupSnapshotKindV1::Base
        && spec.project_id == intent.project_id
        && spec.installed_policy == *policy.installed_policy()
        && spec.installed_rimg_policy_digest == *policy.digest()
        && intent.payload.backup_set_id == Some(spec.backup_set_id)
        && intent.payload.base_backup_id == Some(spec.backup_id)
        && intent.payload.base_backup_manifest_digest.as_ref()
            == Some(&chain.manifest().manifest_digest)
        && intent.payload.base_backup_evidence_digest.as_ref()
            == Some(&chain.local().evidence_digest)
        && intent.payload.base_backup_offsite_evidence_digest.as_ref()
            == Some(&offsite.evidence_digest)
        && intent.payload.base_backup_verification_digest.as_ref() == Some(chain.chain_digest())
        && chain.upload_receipt().is_some()
        && verification_completed_at_ms <= now
        && snapshot_completed_at_ms <= now
        && now - snapshot_completed_at_ms <= max_age_ms
        && clock.observed_at_ms == now;
    if !matches {
        return Err(Phase6ContractError::InvalidVerifiedBackupChain);
    }
    let valid_through_ms = chain
        .local()
        .completed_at_ms
        .checked_add(max_age_ms)
        .ok_or(Phase6ContractError::InvalidVerifiedBackupChain)?;
    Ok((Some(chain.chain_digest().clone()), Some(valid_through_ms)))
}

fn resolve_cutover_backup_chain(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    chain: Option<&VerifiedBackupChainV1>,
    fence_receipt: Option<&FenceAcquisitionReceiptV1>,
) -> Result<Option<EvidenceDigest>, Phase6ContractError> {
    let Some(chain) = chain else {
        return Ok(None);
    };
    chain.require_verified()?;
    let spec = chain.authorized_spec();
    let receipt = fence_receipt.ok_or(Phase6ContractError::InvalidFenceReceipt)?;
    let matches = chain.snapshot_kind() == BackupSnapshotKindV1::Cutover
        && spec.attempt_id == intent.attempt_id
        && spec.project_id == intent.project_id
        && spec.installed_policy == *policy.installed_policy()
        && spec.installed_rimg_policy_digest == *policy.digest()
        && intent.payload.backup_set_id == Some(spec.backup_set_id)
        && intent.payload.cutover_backup_id == Some(spec.backup_id)
        && intent.payload.cutover_backup_manifest_digest.as_ref()
            == Some(&chain.manifest().manifest_digest)
        && intent.payload.cutover_backup_evidence_digest.as_ref()
            == Some(&chain.local().evidence_digest)
        && intent.payload.cutover_backup_verification_digest.as_ref() == Some(chain.chain_digest())
        && spec.fencing_epoch == Some(receipt.epoch)
        && spec.fence_receipt_digest.as_ref() == Some(&receipt.receipt_digest)
        && chain.upload_receipt().is_none()
        && chain.offsite().is_none();
    if !matches {
        return Err(Phase6ContractError::InvalidVerifiedBackupChain);
    }
    Ok(Some(chain.chain_digest().clone()))
}

fn resolve_fence_receipt(
    intent: &PhaseIntent,
    receipt: Option<&FenceAcquisitionReceiptV1>,
    boundary_now_ms: Option<i64>,
) -> Result<(Option<u64>, Option<EvidenceDigest>), Phase6ContractError> {
    let Some(receipt) = receipt else {
        return Ok((None, None));
    };
    if !receipt.has_valid_digest()?
        || receipt.attempt_id != intent.attempt_id
        || receipt.project_id != intent.project_id
        || Some(receipt.epoch) != intent.payload.fencing_epoch
        || intent.payload.fence_acquisition_receipt_digest.as_ref() != Some(&receipt.receipt_digest)
        || boundary_now_ms.is_some_and(|now| receipt.acquired_at_ms > now)
    {
        return Err(Phase6ContractError::InvalidFenceReceipt);
    }
    Ok((Some(receipt.epoch), Some(receipt.receipt_digest.clone())))
}

fn resolve_mutation_grant(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    classification: Option<&ReleaseClassificationEvidenceV1>,
    grant: Option<&StatefulBreakingMutationGrantV1>,
    clock: Option<&TrustedClockEvidenceV1>,
    boundary_now_ms: Option<i64>,
) -> Result<ResolvedMutationGrantV1, Phase6ContractError> {
    let Some(grant) = grant else {
        return Ok(ResolvedMutationGrantV1::default());
    };
    grant.require_current(
        intent,
        policy,
        classification.ok_or(Phase6ContractError::InvalidMutationGrant)?,
        clock.ok_or(Phase6ContractError::UntrustedBoundaryTime)?,
        boundary_now_ms.ok_or(Phase6ContractError::UntrustedBoundaryTime)?,
    )?;
    Ok(ResolvedMutationGrantV1 {
        grant_id: Some(grant.grant_id),
        digest: Some(grant.grant_digest.clone()),
        valid_through_ms: Some(grant.valid_until_ms),
    })
}

fn resolve_runtime_state(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    evidence: Option<&RuntimeReleaseStateEvidenceV1>,
    clock: Option<&TrustedClockEvidenceV1>,
    boundary_now_ms: Option<i64>,
) -> Result<ResolvedRuntimeStateV1, Phase6ContractError> {
    let Some(evidence) = evidence else {
        return Ok(ResolvedRuntimeStateV1::default());
    };
    evidence.require_current(
        intent,
        policy,
        clock.ok_or(Phase6ContractError::UntrustedBoundaryTime)?,
        boundary_now_ms.ok_or(Phase6ContractError::UntrustedBoundaryTime)?,
    )?;
    Ok(ResolvedRuntimeStateV1 {
        state: Some(evidence.state.clone()),
        evidence_digest: Some(evidence.evidence_digest.clone()),
        valid_through_ms: Some(evidence.valid_until_ms),
    })
}

fn validate_phase_authority(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    effective_class: Option<ReleaseClass>,
    backup: Option<&AuthorizedBackupSpecV1>,
    prerequisites: &ResolvedPhasePrerequisitesV1,
) -> Result<(), Phase6ContractError> {
    let shape = PhaseAuthorityShape {
        stateful: matches!(
            effective_class,
            Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
        ),
        backup: PrerequisitePresence::from_present(backup.is_some()),
        base: PrerequisitePresence::from_present(
            prerequisites.verified_base_backup_chain_digest.is_some(),
        ),
        cutover: PrerequisitePresence::from_present(
            prerequisites.verified_cutover_backup_chain_digest.is_some(),
        ),
        fence: PrerequisitePresence::from_present(prerequisites.fence_receipt_digest.is_some()),
        grant: PrerequisitePresence::from_present(prerequisites.mutation_grant_digest.is_some()),
        runtime: PrerequisitePresence::from_present(
            prerequisites.runtime_release_state.is_some()
                || prerequisites
                    .runtime_release_state_evidence_digest
                    .is_some(),
        ),
        intent_requires_fence: match (
            intent.payload.fencing_epoch,
            intent.payload.fence_acquisition_receipt_digest.as_ref(),
        ) {
            (Some(_), Some(_)) => true,
            (None, None) => false,
            _ => return Err(Phase6ContractError::InvalidFenceReceipt),
        },
    };
    match intent.phase {
        OperationPhase::BackingUp
        | OperationPhase::Draining
        | OperationPhase::CutoverSnapshotting
        | OperationPhase::Migrating => {
            validate_mutation_phase_authority(intent, effective_class, backup, prerequisites, shape)
        }
        OperationPhase::Deploying
        | OperationPhase::HealthChecking
        | OperationPhase::Soaking
        | OperationPhase::Rollback => {
            validate_release_phase_authority(intent, policy, effective_class, prerequisites, shape)
        }
        _ => Err(Phase6ContractError::UnsupportedPrivilegedPhase),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PrerequisitePresence {
    Missing,
    Present,
}

impl PrerequisitePresence {
    const fn from_present(present: bool) -> Self {
        if present {
            Self::Present
        } else {
            Self::Missing
        }
    }

    const fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }
}

#[derive(Clone, Copy)]
struct PhaseAuthorityShape {
    stateful: bool,
    backup: PrerequisitePresence,
    base: PrerequisitePresence,
    cutover: PrerequisitePresence,
    fence: PrerequisitePresence,
    grant: PrerequisitePresence,
    runtime: PrerequisitePresence,
    intent_requires_fence: bool,
}

fn validate_mutation_phase_authority(
    intent: &PhaseIntent,
    effective_class: Option<ReleaseClass>,
    backup: Option<&AuthorizedBackupSpecV1>,
    prerequisites: &ResolvedPhasePrerequisitesV1,
    shape: PhaseAuthorityShape,
) -> Result<(), Phase6ContractError> {
    let invalid = match intent.phase {
        OperationPhase::BackingUp => {
            backup.is_none_or(|value| value.snapshot_kind != BackupSnapshotKindV1::Base)
                || !shape.base.is_missing()
                || !shape.cutover.is_missing()
                || !shape.fence.is_missing()
                || !shape.grant.is_missing()
                || !shape.runtime.is_missing()
        }
        OperationPhase::Draining => {
            !shape.stateful
                || !shape.backup.is_missing()
                || shape.base.is_missing()
                || !shape.cutover.is_missing()
                || !shape.fence.is_missing()
                || !shape.grant.is_missing()
                || !shape.runtime.is_missing()
        }
        OperationPhase::CutoverSnapshotting => {
            let backup = backup.ok_or(Phase6ContractError::UnauthorizedBackupSpec)?;
            !shape.stateful
                || shape.base.is_missing()
                || !shape.cutover.is_missing()
                || shape.fence.is_missing()
                || !shape.grant.is_missing()
                || !shape.runtime.is_missing()
                || backup.snapshot_kind != BackupSnapshotKindV1::Cutover
                || backup.fence_receipt_digest != prerequisites.fence_receipt_digest
                || backup.fencing_epoch != intent.payload.fencing_epoch
        }
        OperationPhase::Migrating => {
            !shape.stateful
                || !shape.backup.is_missing()
                || shape.base.is_missing()
                || shape.cutover.is_missing()
                || shape.fence.is_missing()
                || !shape.runtime.is_missing()
                || (effective_class == Some(ReleaseClass::StatefulBreaking))
                    == shape.grant.is_missing()
                || intent.payload.cutover_backup_verification_digest.is_none()
        }
        _ => return Err(Phase6ContractError::UnsupportedPrivilegedPhase),
    };
    if invalid
        && intent.phase == OperationPhase::Migrating
        && effective_class == Some(ReleaseClass::StatefulBreaking)
        && shape.grant.is_missing()
    {
        Err(Phase6ContractError::InteractiveGrantRequired)
    } else if invalid {
        Err(Phase6ContractError::MissingPhasePrerequisite)
    } else {
        Ok(())
    }
}

fn validate_release_phase_authority(
    intent: &PhaseIntent,
    policy: &InstalledRimgPolicyV1,
    effective_class: Option<ReleaseClass>,
    prerequisites: &ResolvedPhasePrerequisitesV1,
    shape: PhaseAuthorityShape,
) -> Result<(), Phase6ContractError> {
    match intent.phase {
        OperationPhase::Deploying => {
            if !shape.backup.is_missing()
                || !shape.cutover.is_missing()
                || !shape.grant.is_missing()
                || shape.runtime.is_missing()
                || intent.payload.release_bundle_digest.is_none()
                || intent.payload.deployment_plan_digest.is_none()
            {
                return Err(Phase6ContractError::MissingPhasePrerequisite);
            }
            match prerequisites.runtime_release_state.as_ref() {
                Some(RuntimeReleaseStateV1::NeverInstalled)
                    if policy.capabilities.bootstrap_with_declared_downtime
                        && shape.base.is_missing()
                        && shape.fence.is_missing() =>
                {
                    Ok(())
                }
                Some(RuntimeReleaseStateV1::Installed { .. })
                    if policy.capabilities.stable_routing
                        && !shape.base.is_missing()
                        && shape.stateful != shape.fence.is_missing() =>
                {
                    Ok(())
                }
                _ => Err(Phase6ContractError::DeploymentCapabilityUnavailable),
            }
        }
        OperationPhase::HealthChecking | OperationPhase::Soaking => {
            if shape.backup.is_missing()
                && shape.base.is_missing()
                && shape.cutover.is_missing()
                && shape.grant.is_missing()
                && shape.runtime.is_missing()
                && shape.intent_requires_fence != shape.fence.is_missing()
            {
                Ok(())
            } else {
                Err(Phase6ContractError::MissingPhasePrerequisite)
            }
        }
        OperationPhase::Rollback => {
            if effective_class == Some(ReleaseClass::Rollback)
                && policy.capabilities.automatic_code_rollback
                && intent.payload.previous_release_bundle_digest.is_some()
                && shape.backup.is_missing()
                && shape.base.is_missing()
                && shape.cutover.is_missing()
                && shape.intent_requires_fence != shape.fence.is_missing()
                && shape.grant.is_missing()
                && shape.runtime.is_missing()
            {
                Ok(())
            } else {
                Err(Phase6ContractError::DeploymentCapabilityUnavailable)
            }
        }
        _ => Err(Phase6ContractError::UnsupportedPrivilegedPhase),
    }
}

fn expected_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    validate_spec_bindings(spec)?;
    match spec.phase {
        OperationPhase::BackingUp => expected_backup_profiles(spec),
        OperationPhase::Draining => expected_drain_profiles(spec),
        OperationPhase::CutoverSnapshotting => expected_cutover_profiles(spec),
        OperationPhase::Migrating => expected_migration_profiles(spec),
        OperationPhase::Deploying => expected_deployment_profiles(spec),
        OperationPhase::HealthChecking => expected_health_profiles(spec),
        OperationPhase::Soaking => expected_soak_profiles(spec),
        OperationPhase::Rollback => expected_rollback_profiles(spec),
        _ => Err(Phase6ContractError::UnsupportedPrivilegedPhase),
    }
}

fn validate_spec_bindings(spec: &AuthorizedPhaseSpecV1) -> Result<(), Phase6ContractError> {
    let classification_valid = match spec.operation_kind {
        OperationKind::BackupOnly => {
            spec.effective_release_class.is_none()
                && spec.classification_evidence_digest.is_none()
                && spec.migration_id.is_none()
        }
        OperationKind::Deploy => {
            matches!(
                spec.effective_release_class,
                Some(
                    ReleaseClass::CodeOnlyCompatible
                        | ReleaseClass::StatefulCompatible
                        | ReleaseClass::StatefulBreaking
                )
            ) && spec.classification_evidence_digest.is_some()
                && matches!(
                    spec.effective_release_class,
                    Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
                ) == spec.migration_id.is_some()
        }
        OperationKind::CodeRollback => {
            spec.effective_release_class == Some(ReleaseClass::Rollback)
                && spec.classification_evidence_digest.is_some()
                && spec.migration_id.is_none()
        }
    };
    let clock_binding_valid = (spec.verified_base_backup_chain_digest.is_some()
        || spec.mutation_grant_digest.is_some()
        || spec.runtime_release_state_evidence_digest.is_some())
        == (spec.trusted_clock_evidence_digest.is_some()
            && spec.boundary_now_ms.is_some()
            && spec.prerequisites_valid_through_ms.is_some());
    let time_binding_valid = match (spec.boundary_now_ms, spec.prerequisites_valid_through_ms) {
        (Some(boundary), Some(valid_through)) => boundary <= valid_through,
        (None, None) => true,
        _ => false,
    };
    let fence_binding_valid = spec.fencing_epoch.is_some() == spec.fence_receipt_digest.is_some();
    let grant_binding_valid =
        spec.mutation_grant_id.is_some() == spec.mutation_grant_digest.is_some();
    let release_binding_valid = if matches!(
        spec.phase,
        OperationPhase::Deploying
            | OperationPhase::HealthChecking
            | OperationPhase::Soaking
            | OperationPhase::Rollback
    ) {
        spec.release_bundle_digest.is_some() && spec.deployment_plan_digest.is_some()
    } else {
        spec.release_bundle_digest.is_none() && spec.deployment_plan_digest.is_none()
    };
    if !classification_valid
        || !clock_binding_valid
        || !time_binding_valid
        || !fence_binding_valid
        || !grant_binding_valid
        || !release_binding_valid
    {
        return Err(Phase6ContractError::DigestMismatch);
    }
    if spec.backup.as_ref().is_some_and(|backup| {
        !backup.has_valid_digest().unwrap_or(false)
            || backup.attempt_id != spec.attempt_id
            || backup.project_id != spec.project_id
            || backup.installed_policy != spec.installed_policy
            || backup.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
            || backup.phase_intent_digest != spec.intent_digest
    }) {
        return Err(Phase6ContractError::UnauthorizedBackupSpec);
    }
    Ok(())
}

fn has_no_runtime_state(spec: &AuthorizedPhaseSpecV1) -> bool {
    spec.runtime_release_state.is_none() && spec.runtime_release_state_evidence_digest.is_none()
}

fn expected_backup_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    let valid = spec
        .backup
        .as_ref()
        .is_some_and(|value| value.snapshot_kind == BackupSnapshotKindV1::Base)
        && spec.verified_base_backup_chain_digest.is_none()
        && spec.verified_cutover_backup_chain_digest.is_none()
        && spec.fence_receipt_digest.is_none()
        && spec.mutation_grant_digest.is_none()
        && has_no_runtime_state(spec);
    if !valid {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    Ok(vec![
        (
            FixedAdapterProfileV1::BackupCapture,
            AdapterResultSchemaV1::BackupManifest,
        ),
        (
            FixedAdapterProfileV1::BackupEncryptAge,
            AdapterResultSchemaV1::LocalBackupEvidence,
        ),
        (
            FixedAdapterProfileV1::BackupUploadGoogleDrive,
            AdapterResultSchemaV1::ProviderUploadReceipt,
        ),
        (
            FixedAdapterProfileV1::BackupReadbackVerify,
            AdapterResultSchemaV1::OffsiteVerificationEvidence,
        ),
    ])
}

fn expected_drain_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    let valid = matches!(
        spec.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    ) && spec.backup.is_none()
        && spec.verified_base_backup_chain_digest.is_some()
        && spec.verified_cutover_backup_chain_digest.is_none()
        && spec.fence_receipt_digest.is_none()
        && spec.mutation_grant_digest.is_none()
        && has_no_runtime_state(spec);
    if !valid {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    Ok(vec![(
        FixedAdapterProfileV1::RimgDrain,
        AdapterResultSchemaV1::DrainEvidence,
    )])
}

fn expected_cutover_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    let valid = matches!(
        spec.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    ) && spec.verified_base_backup_chain_digest.is_some()
        && spec.verified_cutover_backup_chain_digest.is_none()
        && spec.fence_receipt_digest.is_some()
        && spec.mutation_grant_digest.is_none()
        && has_no_runtime_state(spec)
        && spec.backup.as_ref().is_some_and(|backup| {
            backup.snapshot_kind == BackupSnapshotKindV1::Cutover
                && backup.fence_receipt_digest == spec.fence_receipt_digest
        });
    if !valid {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    Ok(vec![
        (
            FixedAdapterProfileV1::BackupCapture,
            AdapterResultSchemaV1::BackupManifest,
        ),
        (
            FixedAdapterProfileV1::BackupEncryptAge,
            AdapterResultSchemaV1::LocalBackupEvidence,
        ),
    ])
}

fn expected_migration_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    let valid = matches!(
        spec.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    ) && spec.backup.is_none()
        && spec.verified_base_backup_chain_digest.is_some()
        && spec.verified_cutover_backup_chain_digest.is_some()
        && spec.fence_receipt_digest.is_some()
        && (spec.effective_release_class == Some(ReleaseClass::StatefulBreaking))
            == spec.mutation_grant_id.is_some()
        && has_no_runtime_state(spec);
    if !valid {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    Ok(vec![
        (
            FixedAdapterProfileV1::RimgSchemaInspect,
            AdapterResultSchemaV1::SchemaInspectionEvidence,
        ),
        (
            FixedAdapterProfileV1::RimgMigrate,
            AdapterResultSchemaV1::MigrationEvidence,
        ),
    ])
}

fn expected_deployment_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    let stateful = matches!(
        spec.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    );
    let valid = spec.backup.is_none()
        && spec.verified_cutover_backup_chain_digest.is_none()
        && spec.mutation_grant_digest.is_none()
        && spec.runtime_release_state_evidence_digest.is_some();
    if !valid {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    let profile = match spec.runtime_release_state.as_ref() {
        Some(RuntimeReleaseStateV1::NeverInstalled)
            if spec.verified_base_backup_chain_digest.is_none()
                && spec.fence_receipt_digest.is_none() =>
        {
            FixedAdapterProfileV1::KamalBootstrapDeploy
        }
        Some(RuntimeReleaseStateV1::Installed { .. }) => {
            if spec.verified_base_backup_chain_digest.is_none()
                || stateful != spec.fence_receipt_digest.is_some()
            {
                return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
            }
            FixedAdapterProfileV1::KamalCandidateDeploy
        }
        Some(RuntimeReleaseStateV1::NeverInstalled) => {
            return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
        }
        None => return Err(Phase6ContractError::InvalidRuntimeReleaseState),
    };
    Ok(vec![(profile, AdapterResultSchemaV1::DeploymentEvidence)])
}

fn expected_health_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    require_observation_phase_prerequisites(spec)?;
    Ok(vec![
        (
            FixedAdapterProfileV1::RimgReadiness,
            AdapterResultSchemaV1::ReadinessEvidence,
        ),
        (
            FixedAdapterProfileV1::RimgConsumerSmoke,
            AdapterResultSchemaV1::ConsumerSmokeEvidence,
        ),
    ])
}

fn expected_soak_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    require_observation_phase_prerequisites(spec)?;
    Ok(vec![(
        FixedAdapterProfileV1::RimgSoakObserve,
        AdapterResultSchemaV1::SoakEvidence,
    )])
}

fn expected_rollback_profiles(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<(FixedAdapterProfileV1, AdapterResultSchemaV1)>, Phase6ContractError> {
    if spec.effective_release_class != Some(ReleaseClass::Rollback) {
        return Err(Phase6ContractError::UnsupportedPrivilegedPhase);
    }
    require_observation_phase_prerequisites(spec)?;
    Ok(vec![(
        FixedAdapterProfileV1::KamalCodeRollback,
        AdapterResultSchemaV1::RollbackEvidence,
    )])
}

fn require_observation_phase_prerequisites(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<(), Phase6ContractError> {
    if spec.backup.is_none()
        && spec.verified_base_backup_chain_digest.is_none()
        && spec.verified_cutover_backup_chain_digest.is_none()
        && spec.mutation_grant_digest.is_none()
        && has_no_runtime_state(spec)
    {
        Ok(())
    } else {
        Err(Phase6ContractError::UnsupportedPrivilegedPhase)
    }
}

fn expected_observation_artifacts(
    intent: &PhaseIntent,
    candidate_schema_version: Option<&str>,
) -> Result<PhaseArtifacts, Phase6ContractError> {
    let artifacts = match intent.phase {
        OperationPhase::Building => PhaseArtifacts {
            build_context_digest: intent.payload.build_context_digest.clone(),
            base_image_digests: intent.payload.base_image_digests.clone(),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Preflight => PhaseArtifacts {
            resource_reservation_digest: intent.payload.resource_reservation_digest.clone(),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Draining => PhaseArtifacts {
            source_gate_proof_digest: intent.payload.source_gate_proof_digest.clone(),
            ..PhaseArtifacts::default()
        },
        OperationPhase::CutoverSnapshotting => PhaseArtifacts {
            backup_set_id: intent.payload.backup_set_id,
            fencing_epoch: intent.payload.fencing_epoch,
            ..PhaseArtifacts::default()
        },
        OperationPhase::Deploying => PhaseArtifacts {
            deployment_plan_digest: intent.payload.deployment_plan_digest.clone(),
            release_bundle_digest: intent.payload.release_bundle_digest.clone(),
            previous_release_bundle_digest: intent.payload.previous_release_bundle_digest.clone(),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Rollback => PhaseArtifacts {
            previous_release_bundle_digest: intent.payload.previous_release_bundle_digest.clone(),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Migrating => PhaseArtifacts {
            schema_version: Some(
                candidate_schema_version
                    .ok_or(Phase6ContractError::InvalidClassification)?
                    .to_owned(),
            ),
            ..PhaseArtifacts::default()
        },
        _ => PhaseArtifacts::default(),
    };
    Ok(artifacts)
}

fn valid_expected_observation_artifacts(phase: OperationPhase, expected: &PhaseArtifacts) -> bool {
    let mut remainder = expected.clone();
    let required = match phase {
        OperationPhase::Building => {
            remainder.build_context_digest = None;
            remainder.base_image_digests.clear();
            expected.build_context_digest.is_some() && !expected.base_image_digests.is_empty()
        }
        OperationPhase::Preflight => {
            remainder.resource_reservation_digest = None;
            expected.resource_reservation_digest.is_some()
        }
        OperationPhase::Draining => {
            remainder.source_gate_proof_digest = None;
            expected.source_gate_proof_digest.is_some()
        }
        OperationPhase::CutoverSnapshotting => {
            remainder.backup_set_id = None;
            remainder.fencing_epoch = None;
            expected.backup_set_id.is_some() && expected.fencing_epoch.is_some()
        }
        OperationPhase::Deploying => {
            remainder.deployment_plan_digest = None;
            remainder.release_bundle_digest = None;
            remainder.previous_release_bundle_digest = None;
            expected.deployment_plan_digest.is_some() && expected.release_bundle_digest.is_some()
        }
        OperationPhase::Rollback => {
            remainder.previous_release_bundle_digest = None;
            expected.previous_release_bundle_digest.is_some()
        }
        OperationPhase::Migrating => {
            remainder.schema_version = None;
            expected.schema_version.is_some()
        }
        _ => true,
    };
    required && remainder == PhaseArtifacts::default()
}

fn observed_artifacts_match_expected(expected: &PhaseArtifacts, observed: &PhaseArtifacts) -> bool {
    expected
        .build_context_digest
        .as_ref()
        .is_none_or(|value| observed.build_context_digest.as_ref() == Some(value))
        && (expected.base_image_digests.is_empty()
            || observed.base_image_digests == expected.base_image_digests)
        && expected
            .resource_reservation_digest
            .as_ref()
            .is_none_or(|value| observed.resource_reservation_digest.as_ref() == Some(value))
        && expected
            .source_gate_proof_digest
            .as_ref()
            .is_none_or(|value| observed.source_gate_proof_digest.as_ref() == Some(value))
        && expected
            .backup_set_id
            .is_none_or(|value| observed.backup_set_id == Some(value))
        && expected
            .fencing_epoch
            .is_none_or(|value| observed.fencing_epoch == Some(value))
        && expected
            .deployment_plan_digest
            .as_ref()
            .is_none_or(|value| observed.deployment_plan_digest.as_ref() == Some(value))
        && expected
            .release_bundle_digest
            .as_ref()
            .is_none_or(|value| observed.release_bundle_digest.as_ref() == Some(value))
        && expected
            .schema_version
            .as_ref()
            .is_none_or(|value| observed.schema_version.as_ref() == Some(value))
        && observed.previous_release_bundle_digest == expected.previous_release_bundle_digest
}

fn valid_timeouts(timeouts: RimgTimeoutPolicyV1) -> bool {
    [
        timeouts.backup_ms,
        timeouts.drain_ms,
        timeouts.migration_ms,
        timeouts.deploy_ms,
        timeouts.readiness_ms,
        timeouts.smoke_ms,
        timeouts.soak_ms,
    ]
    .into_iter()
    .all(|timeout| (1..=MAX_TIMEOUT_MS).contains(&timeout))
        && timeouts.deploy_ms >= 60_000
        && timeouts.smoke_ms >= 180_000
        && timeouts.soak_ms >= 60_000
}

fn valid_schema_version(value: &str) -> bool {
    valid_application_schema_version(value)
}

fn valid_migration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, Phase6ContractError>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(bytes)?;
    if serde_jcs::to_vec(&value)? != bytes {
        return Err(Phase6ContractError::NonCanonicalDocument);
    }
    Ok(value)
}

fn digest_jcs<T: Serialize>(value: &T) -> Result<EvidenceDigest, Phase6ContractError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(value)?))
}

#[derive(Debug, thiserror::Error)]
pub enum Phase6ContractError {
    #[error("installed rimg policy is incomplete, inconsistent or not bound to Kamal policy")]
    InvalidInstalledPolicy,
    #[error("phase intent, installed policy or executor authorization does not match")]
    AuthorizationMismatch,
    #[error("executor release classification evidence is invalid")]
    InvalidClassification,
    #[error("executor classification does not match the admitted operation phase plan")]
    ClassificationPlanMismatch,
    #[error("the rimg machine-readable admin protocols are not installed")]
    RimgProtocolUnavailable,
    #[error("backup specification is not authorized by installed rimg policy")]
    UnauthorizedBackupSpec,
    #[error("a required prior evidence document is missing or mismatched")]
    MissingPhasePrerequisite,
    #[error("the verified base-backup chain is invalid, stale or not bound to this operation")]
    InvalidVerifiedBackupChain,
    #[error("the persisted fence receipt is invalid or not bound to this operation epoch")]
    InvalidFenceReceipt,
    #[error("the trusted boundary time is absent, stale or inconsistent")]
    UntrustedBoundaryTime,
    #[error("the executor-owned runtime release-state evidence is invalid or stale")]
    InvalidRuntimeReleaseState,
    #[error("the stateful-breaking mutation grant is invalid, stale or mismatched")]
    InvalidMutationGrant,
    #[error("stateful-breaking migration requires an operation-bound interactive grant")]
    InteractiveGrantRequired,
    #[error("bootstrap, stable routing or rollback capability is unavailable")]
    DeploymentCapabilityUnavailable,
    #[error("phase is not handled by the privileged Phase 6 adapter family")]
    UnsupportedPrivilegedPhase,
    #[error("authorized phase contains a duplicate or invalid adapter step")]
    DuplicateAdapterStep,
    #[error("authorized phase specification digest is invalid")]
    DigestMismatch,
    #[error("fixed adapter request exceeds its canonical document bound")]
    AdapterRequestTooLarge,
    #[error("fixed adapter request does not exactly match its authorized phase step")]
    AdapterRequestMismatch,
    #[error("authorized phase has no fixed adapter step with sequence {0}")]
    UnknownAdapterStep(u16),
    #[error("observed phase artifacts do not match the authorized phase specification")]
    ObservedArtifactMismatch,
    #[error("authorized phase specification is not canonical JCS")]
    NonCanonicalDocument,
    #[error("canonical Phase 6 encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupContractError),
    #[error(transparent)]
    Build(#[from] crate::build::BuildContractError),
    #[error(transparent)]
    Fence(#[from] crate::domain::FenceAcquisitionReceiptError),
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr;

    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use crate::{
        backup::{
            AuthorizedBackupSpecInputV1, BackupCapturePurposeV1, BackupCheckKindV1,
            BackupCheckSpecV1, BackupConsistencyMechanismV1, BackupObjectKindV1,
            BackupUnitSpecInputV1, ExpectedBackupObjectV1,
        },
        build::{
            InstalledKamalPolicyInputV1, InstalledKamalPolicyV1, KamalClearEnvironmentV1,
            KamalContainerPath, KamalEnvironmentKey, KamalEnvironmentValue, KamalHostPath,
            KamalImageName, KamalLoggingDriverV1, KamalLoggingPolicyV1, KamalMountAccessV1,
            KamalMountV1, KamalNetworkAlias, KamalNetworkName, KamalPortBindingV1,
            KamalPortProtocolV1, KamalSecretBindingV1, KamalSecretName, KamalServiceName,
            KamalSshUser, KamalTargetHost, KamalUnixIdentityV1,
        },
        domain::RelativePolicyPath,
        store::{
            AuthorizedPhaseSpecBinding, ExecutorAuthorization, ExecutorPhasePlan,
            ObservationAcceptance, PhaseIntentRequest, SecurityStore, SourceGateProofRecord,
            StoreError,
        },
    };

    fn test_digest(label: impl AsRef<[u8]>) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    fn test_backup_unit() -> BackupUnitSpecV1 {
        let object = |path: &str, kind: BackupObjectKindV1| ExpectedBackupObjectV1 {
            path: RelativePolicyPath::from_str(path)
                .unwrap_or_else(|error| panic!("backup path: {error}")),
            kind,
            uid: 10_001,
            gid: 10_001,
            mode: 0o600,
        };
        BackupUnitSpecV1::new(BackupUnitSpecInputV1 {
            unit_id: "rimg-primary".to_owned(),
            consistency: BackupConsistencyMechanismV1::SqliteOnlineBackupV1,
            expected_objects: vec![
                object("data/masters", BackupObjectKindV1::Master),
                object("data/rimg.sqlite3", BackupObjectKindV1::SqliteDatabase),
            ],
            primary_sqlite_path: RelativePolicyPath::from_str("data/rimg.sqlite3")
                .unwrap_or_else(|error| panic!("SQLite path: {error}")),
            required_checks: [
                ("staged_smoke", BackupCheckKindV1::StagedReadSmoke),
                ("integrity", BackupCheckKindV1::SqliteIntegrity),
                ("foreign_keys", BackupCheckKindV1::ForeignKeys),
                ("domain_masters", BackupCheckKindV1::DomainInvariant),
                ("database_files", BackupCheckKindV1::DatabaseToFiles),
            ]
            .into_iter()
            .map(|(name, kind)| BackupCheckSpecV1 {
                name: name.to_owned(),
                kind,
                definition_digest: test_digest(format!("{name} check")),
            })
            .collect(),
        })
        .unwrap_or_else(|error| panic!("backup unit: {error}"))
    }

    fn test_kamal_policy() -> InstalledKamalPolicyV1 {
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("Kamal project: {error}"));
        InstalledKamalPolicyV1::new(InstalledKamalPolicyInputV1 {
            project_id,
            installed_policy: InstalledPolicyIdentity {
                digest: test_digest("installed policy"),
                version: 1,
            },
            service: KamalServiceName::from_str("rimg")
                .unwrap_or_else(|error| panic!("service: {error}")),
            image: KamalImageName::from_str("mrdenai/rimg")
                .unwrap_or_else(|error| panic!("image: {error}")),
            target_host: KamalTargetHost::from_str("45.151.142.168")
                .unwrap_or_else(|error| panic!("target host: {error}")),
            ssh_user: KamalSshUser::from_str("deploy")
                .unwrap_or_else(|error| panic!("SSH user: {error}")),
            ssh_port: 22,
            network: KamalNetworkName::from_str("kamal")
                .unwrap_or_else(|error| panic!("network: {error}")),
            network_alias: KamalNetworkAlias::from_str("rimg")
                .unwrap_or_else(|error| panic!("network alias: {error}")),
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
                    .unwrap_or_else(|error| panic!("secret environment key: {error}")),
                secret_name: KamalSecretName::from_str("RIMG_DATABASE_KEY")
                    .unwrap_or_else(|error| panic!("secret name: {error}")),
                credential_version: 1,
            }],
            logging: KamalLoggingPolicyV1 {
                driver: KamalLoggingDriverV1::Local,
                max_size_bytes: 16 * 1024 * 1024,
                max_files: 4,
            },
            template_digest: test_digest("Kamal template"),
        })
        .unwrap_or_else(|error| panic!("Kamal policy: {error}"))
    }

    pub(crate) fn test_installed_rimg_policy() -> InstalledRimgPolicyV1 {
        InstalledRimgPolicyV1::new(
            InstalledRimgPolicyInputV1 {
                project_id: ProjectId::from_str("rimg")
                    .unwrap_or_else(|error| panic!("rimg project: {error}")),
                installed_policy: InstalledPolicyIdentity {
                    digest: test_digest("installed policy"),
                    version: 1,
                },
                protocols: RimgProtocolVersionsV1 {
                    schema_inspection: Some(1),
                    explicit_migration: Some(1),
                    persisted_fence: Some(1),
                    persisted_drain: Some(1),
                    truthful_readiness: Some(1),
                    coherent_backup: Some(1),
                },
                timeouts: RimgTimeoutPolicyV1 {
                    backup_ms: 300_000,
                    drain_ms: 60_000,
                    migration_ms: 300_000,
                    deploy_ms: 300_000,
                    readiness_ms: 60_000,
                    smoke_ms: 180_000,
                    soak_ms: 600_000,
                },
                capabilities: RimgDeploymentCapabilitiesV1 {
                    bootstrap_with_declared_downtime: true,
                    stable_routing: false,
                    automatic_code_rollback: false,
                },
                schema_transitions: vec![],
                backup_units: vec![test_backup_unit()],
                backup_recipient_fingerprints: vec![test_digest("age recipient")],
                backup_provider: crate::backup::BackupProviderV1::GoogleDrive,
                backup_provider_credential_version: 1,
                migration_backup_max_age_ms: 60 * 60 * 1_000,
                code_only_backup_max_age_ms: 24 * 60 * 60 * 1_000,
                schema_contract_digest: test_digest("schema contract"),
                readiness_contract_digest: test_digest("readiness contract"),
                consumer_smoke_contract_digest: test_digest("consumer smoke contract"),
            },
            test_kamal_policy(),
        )
        .unwrap_or_else(|error| panic!("installed rimg policy: {error}"))
    }

    fn bootstrap_spec(
        attempt_id: Uuid,
        project_id: ProjectId,
        intent_digest: EvidenceDigest,
        authorization_digest: EvidenceDigest,
        valid_through_ms: i64,
    ) -> AuthorizedPhaseSpecV1 {
        let expected_observation_artifacts = PhaseArtifacts {
            deployment_plan_digest: Some(test_digest("deployment plan")),
            release_bundle_digest: Some(test_digest("release bundle")),
            ..PhaseArtifacts::default()
        };
        let mut spec = AuthorizedPhaseSpecV1 {
            schema_version: AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION,
            attempt_id,
            request_id: Uuid::new_v4(),
            project_id,
            operation_kind: OperationKind::Deploy,
            phase: OperationPhase::Deploying,
            branch: ExecutorPhaseBranch::Primary,
            intent_digest,
            executor_authorization_digest: authorization_digest,
            installed_policy: InstalledPolicyIdentity {
                digest: test_digest("installed policy"),
                version: 1,
            },
            installed_rimg_policy_digest: test_digest("rimg policy"),
            release_bundle_digest: Some(test_digest("release bundle")),
            deployment_plan_digest: Some(test_digest("deployment plan")),
            timeouts: RimgTimeoutPolicyV1 {
                backup_ms: 300_000,
                drain_ms: 60_000,
                migration_ms: 300_000,
                deploy_ms: 300_000,
                readiness_ms: 60_000,
                smoke_ms: 180_000,
                soak_ms: 600_000,
            },
            proposed_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            effective_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            classification_evidence_digest: Some(test_digest("classification")),
            migration_id: None,
            backup: None,
            verified_base_backup_chain_digest: None,
            verified_cutover_backup_chain_digest: None,
            trusted_clock_evidence_digest: Some(test_digest("trusted clock")),
            boundary_now_ms: Some(100),
            prerequisites_valid_through_ms: Some(valid_through_ms),
            fencing_epoch: None,
            fence_receipt_digest: None,
            mutation_grant_id: None,
            mutation_grant_digest: None,
            runtime_release_state: Some(RuntimeReleaseStateV1::NeverInstalled),
            runtime_release_state_evidence_digest: Some(test_digest("runtime state")),
            expected_observation_artifacts,
            steps: Vec::new(),
            spec_digest: EvidenceDigest::sha256([]),
        };
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("bootstrap steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("bootstrap digest: {error}"));
        spec
    }

    pub(crate) fn test_bootstrap_phase_spec() -> AuthorizedPhaseSpecV1 {
        bootstrap_spec(
            Uuid::new_v4(),
            ProjectId::from_str("adapter-test").unwrap_or_else(|error| panic!("project: {error}")),
            test_digest("adapter intent"),
            test_digest("adapter authorization"),
            1_000,
        )
    }

    pub(crate) fn test_health_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_bootstrap_phase_spec();
        spec.phase = OperationPhase::HealthChecking;
        spec.trusted_clock_evidence_digest = None;
        spec.boundary_now_ms = None;
        spec.prerequisites_valid_through_ms = None;
        spec.runtime_release_state = None;
        spec.runtime_release_state_evidence_digest = None;
        spec.expected_observation_artifacts = PhaseArtifacts::default();
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("health steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("health digest: {error}"));
        spec
    }

    pub(crate) fn test_soak_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_health_phase_spec();
        spec.phase = OperationPhase::Soaking;
        spec.timeouts.soak_ms = 60_000;
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("soak steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("soak digest: {error}"));
        spec
    }

    pub(crate) fn test_rollback_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_health_phase_spec();
        spec.operation_kind = OperationKind::CodeRollback;
        spec.phase = OperationPhase::Rollback;
        spec.branch = ExecutorPhaseBranch::RollbackRecovery;
        spec.proposed_release_class = Some(ReleaseClass::Rollback);
        spec.effective_release_class = Some(ReleaseClass::Rollback);
        spec.expected_observation_artifacts = PhaseArtifacts {
            previous_release_bundle_digest: Some(test_digest("previous release bundle")),
            ..PhaseArtifacts::default()
        };
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("rollback steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("rollback digest: {error}"));
        spec
    }

    pub(crate) fn test_base_backup_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_bootstrap_phase_spec();
        spec.operation_kind = OperationKind::BackupOnly;
        spec.phase = OperationPhase::BackingUp;
        spec.release_bundle_digest = None;
        spec.deployment_plan_digest = None;
        spec.proposed_release_class = None;
        spec.effective_release_class = None;
        spec.classification_evidence_digest = None;
        spec.migration_id = None;
        spec.trusted_clock_evidence_digest = None;
        spec.boundary_now_ms = None;
        spec.prerequisites_valid_through_ms = None;
        spec.runtime_release_state = None;
        spec.runtime_release_state_evidence_digest = None;
        spec.expected_observation_artifacts = PhaseArtifacts::default();
        let unit = BackupUnitSpecV1::new(BackupUnitSpecInputV1 {
            unit_id: "rimg-primary".to_owned(),
            consistency: BackupConsistencyMechanismV1::SqliteOnlineBackupV1,
            expected_objects: vec![
                ExpectedBackupObjectV1 {
                    path: RelativePolicyPath::from_str("data/rimg.db")
                        .unwrap_or_else(|error| panic!("database path: {error}")),
                    kind: BackupObjectKindV1::SqliteDatabase,
                    uid: 0,
                    gid: 0,
                    mode: 0o600,
                },
                ExpectedBackupObjectV1 {
                    path: RelativePolicyPath::from_str("data/masters")
                        .unwrap_or_else(|error| panic!("masters path: {error}")),
                    kind: BackupObjectKindV1::Master,
                    uid: 0,
                    gid: 0,
                    mode: 0o600,
                },
            ],
            primary_sqlite_path: RelativePolicyPath::from_str("data/rimg.db")
                .unwrap_or_else(|error| panic!("primary database path: {error}")),
            required_checks: [
                ("database_to_files", BackupCheckKindV1::DatabaseToFiles),
                ("domain_invariant", BackupCheckKindV1::DomainInvariant),
                ("foreign_keys", BackupCheckKindV1::ForeignKeys),
                ("sqlite_integrity", BackupCheckKindV1::SqliteIntegrity),
                ("staged_read_smoke", BackupCheckKindV1::StagedReadSmoke),
            ]
            .into_iter()
            .map(|(name, kind)| BackupCheckSpecV1 {
                name: name.to_owned(),
                kind,
                definition_digest: test_digest(format!("{name} definition")),
            })
            .collect(),
        })
        .unwrap_or_else(|error| panic!("backup unit: {error}"));
        spec.backup = Some(
            AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
                attempt_id: spec.attempt_id,
                project_id: spec.project_id.clone(),
                installed_policy: spec.installed_policy.clone(),
                installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
                phase_intent_digest: spec.intent_digest.clone(),
                backup_set_id: Uuid::new_v4(),
                backup_id: Uuid::new_v4(),
                snapshot_kind: BackupSnapshotKindV1::Base,
                capture_purpose: BackupCapturePurposeV1::DeploymentBase,
                unit,
                recipient_fingerprint: crate::backup::age_x25519_recipient_fingerprint(&format!(
                    "age1{}",
                    "q".repeat(58)
                )),
                provider: BackupProviderV1::GoogleDrive,
                provider_credential_version: 1,
                capture_deadline_ms: 10_000,
                fencing_epoch: None,
                fence_receipt_digest: None,
            })
            .unwrap_or_else(|error| panic!("backup authorization: {error}")),
        );
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("backup steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("backup digest: {error}"));
        spec
    }

    pub(crate) fn test_cutover_backup_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_base_backup_phase_spec();
        spec.operation_kind = OperationKind::Deploy;
        spec.phase = OperationPhase::CutoverSnapshotting;
        spec.proposed_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.effective_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.classification_evidence_digest = Some(test_digest("classification"));
        spec.migration_id = Some("rimg-schema-v4".to_owned());
        spec.verified_base_backup_chain_digest = Some(test_digest("base backup chain"));
        spec.trusted_clock_evidence_digest = Some(test_digest("trusted clock"));
        spec.boundary_now_ms = Some(100);
        spec.prerequisites_valid_through_ms = Some(10_000);
        spec.fencing_epoch = Some(7);
        spec.fence_receipt_digest = Some(test_digest("fence receipt"));
        let base = spec
            .backup
            .take()
            .unwrap_or_else(|| panic!("base backup authorization"));
        let cutover = AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
            attempt_id: spec.attempt_id,
            project_id: spec.project_id.clone(),
            installed_policy: spec.installed_policy.clone(),
            installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
            phase_intent_digest: spec.intent_digest.clone(),
            backup_set_id: base.backup_set_id,
            backup_id: Uuid::new_v4(),
            snapshot_kind: BackupSnapshotKindV1::Cutover,
            capture_purpose: BackupCapturePurposeV1::DeploymentCutover,
            unit: base.unit,
            recipient_fingerprint: base.recipient_fingerprint,
            provider: base.provider,
            provider_credential_version: base.provider_credential_version,
            capture_deadline_ms: base.capture_deadline_ms,
            fencing_epoch: spec.fencing_epoch,
            fence_receipt_digest: spec.fence_receipt_digest.clone(),
        })
        .unwrap_or_else(|error| panic!("cutover authorization: {error}"));
        spec.expected_observation_artifacts = PhaseArtifacts {
            backup_set_id: Some(cutover.backup_set_id),
            fencing_epoch: spec.fencing_epoch,
            ..PhaseArtifacts::default()
        };
        spec.backup = Some(cutover);
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("cutover steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("cutover digest: {error}"));
        spec
    }

    pub(crate) fn test_migration_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_bootstrap_phase_spec();
        spec.phase = OperationPhase::Migrating;
        spec.proposed_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.effective_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.migration_id = Some("rimg-schema-v2".to_owned());
        spec.release_bundle_digest = None;
        spec.deployment_plan_digest = None;
        spec.verified_base_backup_chain_digest = Some(test_digest("base backup chain"));
        spec.verified_cutover_backup_chain_digest = Some(test_digest("cutover backup chain"));
        spec.fencing_epoch = Some(7);
        spec.fence_receipt_digest = Some(test_digest("fence receipt"));
        spec.runtime_release_state = None;
        spec.runtime_release_state_evidence_digest = None;
        spec.expected_observation_artifacts = PhaseArtifacts {
            schema_version: Some("2".to_owned()),
            ..PhaseArtifacts::default()
        };
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("migration steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("migration digest: {error}"));
        spec
    }

    pub(crate) fn test_drain_phase_spec() -> AuthorizedPhaseSpecV1 {
        let mut spec = test_bootstrap_phase_spec();
        spec.phase = OperationPhase::Draining;
        spec.proposed_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.effective_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.migration_id = Some("rimg-schema-v2".to_owned());
        spec.release_bundle_digest = None;
        spec.deployment_plan_digest = None;
        spec.verified_base_backup_chain_digest = Some(test_digest("base backup chain"));
        spec.runtime_release_state = None;
        spec.runtime_release_state_evidence_digest = None;
        spec.expected_observation_artifacts = PhaseArtifacts {
            source_gate_proof_digest: Some(test_digest("drain source proof")),
            ..PhaseArtifacts::default()
        };
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("drain steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("drain digest: {error}"));
        spec
    }

    fn prepare_bootstrap(
        security: &SecurityStore,
        project_id: &ProjectId,
        attempt_id: Uuid,
        valid_through_ms: i64,
    ) -> AuthorizedPhaseSpecV1 {
        let authorization_digest = test_digest(format!("authorization:{attempt_id}"));
        security
            .authorize_attempt(
                &ExecutorAuthorization {
                    authorization_id: Uuid::new_v4(),
                    digest: authorization_digest.clone(),
                    attempt_id,
                    project_id: project_id.clone(),
                    expires_at_ms: 1_000,
                    disk_reservation: None,
                },
                10,
            )
            .unwrap_or_else(|error| panic!("authorize bootstrap: {error}"));
        let intent_digest = test_digest(format!("intent:{attempt_id}"));
        let phases = [OperationPhase::Deploying];
        security
            .begin_phase_intent(PhaseIntentRequest {
                attempt_id,
                project_id,
                phase: OperationPhase::Deploying,
                branch: ExecutorPhaseBranch::Primary,
                phase_plan: ExecutorPhasePlan::new(&phases, false),
                intent_digest: &intent_digest,
                authorization_digest: &authorization_digest,
                started_at_ms: 20,
            })
            .unwrap_or_else(|error| panic!("begin bootstrap: {error}"));
        let spec = bootstrap_spec(
            attempt_id,
            project_id.clone(),
            intent_digest.clone(),
            authorization_digest,
            valid_through_ms,
        );
        let canonical = spec
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("canonical bootstrap: {error}"));
        security
            .bind_authorized_phase_spec(AuthorizedPhaseSpecBinding {
                attempt_id,
                project_id,
                phase: OperationPhase::Deploying,
                branch: ExecutorPhaseBranch::Primary,
                intent_digest: &intent_digest,
                spec_digest: &spec.spec_digest,
                canonical_json: &canonical,
                persisted_at_ms: 30,
            })
            .unwrap_or_else(|error| panic!("bind bootstrap: {error}"));
        security
            .record_source_gate_proof(&SourceGateProofRecord {
                attempt_id,
                phase: OperationPhase::Deploying,
                proof_digest: test_digest(format!("source proof:{attempt_id}")),
                project_id: project_id.clone(),
                source_sequence: 1,
                attestation_digest: test_digest(format!("source attestation:{project_id}")),
                checked_at_ms: 31,
            })
            .unwrap_or_else(|error| panic!("record bootstrap source proof: {error}"));
        spec
    }

    fn commit_bootstrap(security: &SecurityStore, spec: &AuthorizedPhaseSpecV1) {
        let mut artifacts = spec
            .bind_artifacts(spec.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bootstrap artifacts: {error}"));
        artifacts.source_gate_proof_digest = security
            .source_gate_proof(spec.attempt_id, spec.phase)
            .unwrap_or_else(|error| panic!("load bootstrap source proof: {error}"));
        assert_eq!(
            security
                .record_phase_observation(
                    spec.attempt_id,
                    spec.phase,
                    &spec.intent_digest,
                    &test_digest("bootstrap observation"),
                    &artifacts,
                    111,
                )
                .unwrap_or_else(|error| panic!("observe bootstrap: {error}")),
            ObservationAcceptance::Accepted
        );
        security
            .mark_phase_verified(spec.attempt_id, spec.phase, 112)
            .unwrap_or_else(|error| panic!("verify bootstrap: {error}"));
        security
            .commit_phase_receipt(spec.attempt_id, spec.phase, 113)
            .unwrap_or_else(|error| panic!("commit bootstrap: {error}"));
    }

    #[test]
    fn bootstrap_permit_is_single_project_claim_and_expires_before_effect() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let security = SecurityStore::open(directory.path().join("security.sqlite"))
            .unwrap_or_else(|error| panic!("security: {error}"));
        let project_id = ProjectId::from_str("bootstrap-test")
            .unwrap_or_else(|error| panic!("project: {error}"));
        let first = prepare_bootstrap(&security, &project_id, Uuid::new_v4(), 130);
        for _ in 0..2 {
            security
                .authorize_bound_phase_spec(first.attempt_id, first.phase, first.branch, 110)
                .unwrap_or_else(|error| panic!("idempotent bootstrap permit: {error}"));
        }
        let missing_source_proof = first
            .bind_artifacts(first.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bind bootstrap without dynamic proof: {error}"));
        assert!(matches!(
            security.record_phase_observation(
                first.attempt_id,
                first.phase,
                &first.intent_digest,
                &test_digest("missing source proof observation"),
                &missing_source_proof,
                111,
            ),
            Err(StoreError::SourceGateProofMismatch)
        ));
        let mut forged_artifacts = first.expected_observation_artifacts.clone();
        forged_artifacts.deployment_plan_digest = Some(test_digest("substituted plan"));
        assert!(matches!(
            first.bind_artifacts(forged_artifacts.clone()),
            Err(Phase6ContractError::ObservedArtifactMismatch)
        ));
        forged_artifacts.authorized_phase_spec_digest = Some(first.spec_digest.clone());
        assert!(matches!(
            security.record_phase_observation(
                first.attempt_id,
                first.phase,
                &first.intent_digest,
                &test_digest("forged bootstrap observation"),
                &forged_artifacts,
                111,
            ),
            Err(StoreError::AuthorizedPhaseArtifactMismatch)
        ));
        commit_bootstrap(&security, &first);

        let second = prepare_bootstrap(&security, &project_id, Uuid::new_v4(), 130);
        assert!(matches!(
            security.authorize_bound_phase_spec(
                second.attempt_id,
                second.phase,
                second.branch,
                110,
            ),
            Err(StoreError::BootstrapAlreadyClaimed)
        ));

        let expiring_project = ProjectId::from_str("expiring-bootstrap")
            .unwrap_or_else(|error| panic!("expiring project: {error}"));
        let expiring = prepare_bootstrap(&security, &expiring_project, Uuid::new_v4(), 130);
        assert!(matches!(
            security.authorize_bound_phase_spec(
                expiring.attempt_id,
                expiring.phase,
                expiring.branch,
                131,
            ),
            Err(StoreError::PhaseAuthorityExpired)
        ));
    }

    #[test]
    fn migration_observation_is_bound_to_the_classified_candidate_schema() {
        let attempt_id = Uuid::new_v4();
        let project_id = ProjectId::from_str("migration-schema-binding")
            .unwrap_or_else(|error| panic!("project: {error}"));
        let mut spec = bootstrap_spec(
            attempt_id,
            project_id,
            test_digest("migration intent"),
            test_digest("migration authorization"),
            200,
        );
        spec.phase = OperationPhase::Migrating;
        spec.proposed_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.effective_release_class = Some(ReleaseClass::StatefulCompatible);
        spec.migration_id = Some("rimg-schema-v2".to_owned());
        spec.release_bundle_digest = None;
        spec.deployment_plan_digest = None;
        spec.verified_base_backup_chain_digest = Some(test_digest("base backup chain"));
        spec.verified_cutover_backup_chain_digest = Some(test_digest("cutover backup chain"));
        spec.fencing_epoch = Some(7);
        spec.fence_receipt_digest = Some(test_digest("fence receipt"));
        spec.runtime_release_state = None;
        spec.runtime_release_state_evidence_digest = None;
        spec.expected_observation_artifacts = PhaseArtifacts {
            schema_version: Some("2".to_owned()),
            ..PhaseArtifacts::default()
        };
        spec.steps = spec
            .expected_steps()
            .unwrap_or_else(|error| panic!("migration steps: {error}"));
        spec.spec_digest = spec
            .calculate_digest()
            .unwrap_or_else(|error| panic!("migration digest: {error}"));

        let accepted = spec
            .bind_artifacts(spec.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bind exact migration schema: {error}"));
        assert_eq!(accepted.schema_version.as_deref(), Some("2"));

        let mut substituted = spec.expected_observation_artifacts.clone();
        substituted.schema_version = Some("3".to_owned());
        assert!(matches!(
            spec.bind_artifacts(substituted),
            Err(Phase6ContractError::ObservedArtifactMismatch)
        ));
    }

    #[test]
    fn schema_contract_evidence_is_typed_and_bound_to_the_installed_contract() {
        let project_id = ProjectId::from_str("schema-contract-binding")
            .unwrap_or_else(|error| panic!("project: {error}"));
        let phase_intent_digest = test_digest("schema phase intent");
        let installed_policy = InstalledPolicyIdentity {
            digest: test_digest("installed policy"),
            version: 1,
        };
        let installed_rimg_policy_digest = test_digest("installed rimg policy");
        let approved_contract = test_digest("approved migration plan contract");
        let substituted_contract = test_digest("unreviewed migration plan contract");
        let mut evidence = SchemaContractEvaluationEvidenceV1 {
            schema_version: SCHEMA_CONTRACT_EVALUATION_SCHEMA_VERSION,
            kind: SchemaContractKindV1::MigrationPlan,
            phase_intent_digest: phase_intent_digest.clone(),
            project_id: project_id.clone(),
            installed_policy: installed_policy.clone(),
            installed_rimg_policy_digest: installed_rimg_policy_digest.clone(),
            current_schema_version: Some("1".to_owned()),
            candidate_schema_version: "2".to_owned(),
            migration_id: Some("schema-v2".to_owned()),
            contract_digest: approved_contract.clone(),
            verdict: SchemaContractVerdictV1::Satisfied,
            observation_digest: test_digest("migration plan evaluation"),
            evaluated_at_ms: 100,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence
            .calculate_digest()
            .unwrap_or_else(|error| panic!("contract evidence digest: {error}"));
        let expected = |contract_digest| SchemaContractBindingContext {
            kind: SchemaContractKindV1::MigrationPlan,
            phase_intent_digest: &phase_intent_digest,
            project_id: &project_id,
            installed_policy: &installed_policy,
            installed_rimg_policy_digest: &installed_rimg_policy_digest,
            current_schema_version: Some("1"),
            candidate_schema_version: "2",
            migration_id: Some("schema-v2"),
            contract_digest,
            inspected_at_ms: 101,
        };

        assert!(
            evidence
                .matches_bindings(&expected(&approved_contract))
                .unwrap_or_else(|error| panic!("match approved contract: {error}"))
        );
        assert!(
            !evidence
                .matches_bindings(&expected(&substituted_contract))
                .unwrap_or_else(|error| panic!("reject substituted contract: {error}"))
        );

        evidence.contract_digest = substituted_contract;
        assert!(
            !evidence
                .has_valid_digest()
                .unwrap_or_else(|error| panic!("detect tampered contract evidence: {error}"))
        );
    }
}
