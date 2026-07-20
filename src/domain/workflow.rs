use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use uuid::Uuid;

use super::{EvidenceDigest, GitCommitId, ProjectId};

pub const WORKFLOW_POLICY_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_LEASE_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_NODE_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_REDUCTION_RECEIPT_SCHEMA_VERSION: u16 = 1;

const MAX_WORKFLOW_NODES: usize = 64;
const MAX_WORKFLOW_PROFILES: usize = 32;
const MAX_IDENTITY_BYTES: usize = 96;
const MIN_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

macro_rules! workflow_token {
    ($name:ident, $error:literal) => {
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = WorkflowContractError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if valid_workflow_token(value, 64) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(WorkflowContractError::InvalidIdentifier($error))
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }
    };
}

workflow_token!(WorkflowNodeId, "workflow node ID");
workflow_token!(WorkflowProfileId, "workflow profile ID");

pub fn valid_workflow_identity(value: &str) -> bool {
    valid_workflow_token(value, MAX_IDENTITY_BYTES)
}

fn valid_workflow_token(value: &str, maximum: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=maximum).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'-' | b'.' | b'_')
        })
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowNodeKindV1 {
    SourceAdmission,
    HostPrepare,
    Verification,
    ReleaseBuild,
    DeterministicReduce,
    ResourceReservation,
    Backup,
    Migration,
    CandidateHealth,
    Cutover,
    ReleasedObservation,
    Rollback,
}

impl WorkflowNodeKindV1 {
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Backup
                | Self::Migration
                | Self::CandidateHealth
                | Self::Cutover
                | Self::ReleasedObservation
                | Self::Rollback
        )
    }

    pub const fn is_controller_managed(self) -> bool {
        matches!(self, Self::SourceAdmission | Self::DeterministicReduce)
    }

    const fn expected_output(self) -> WorkflowArtifactKindV1 {
        match self {
            Self::SourceAdmission => WorkflowArtifactKindV1::SourceSnapshot,
            Self::HostPrepare => WorkflowArtifactKindV1::PreparedRun,
            Self::Verification => WorkflowArtifactKindV1::VerificationReceipt,
            Self::ReleaseBuild => WorkflowArtifactKindV1::ReleaseBundle,
            Self::DeterministicReduce => WorkflowArtifactKindV1::ReductionReceipt,
            Self::ResourceReservation => WorkflowArtifactKindV1::ResourceReservation,
            Self::Backup => WorkflowArtifactKindV1::BackupReceipt,
            Self::Migration => WorkflowArtifactKindV1::MigrationReceipt,
            Self::CandidateHealth => WorkflowArtifactKindV1::CandidateHealthReceipt,
            Self::Cutover => WorkflowArtifactKindV1::CutoverReceipt,
            Self::ReleasedObservation => WorkflowArtifactKindV1::ReleasedObservationReceipt,
            Self::Rollback => WorkflowArtifactKindV1::RollbackReceipt,
        }
    }

    const fn expected_adapter(self) -> &'static [WorkflowAdapterIdV1] {
        match self {
            Self::SourceAdmission => &[WorkflowAdapterIdV1::ControllerSourceAdmissionV1],
            Self::HostPrepare => &[WorkflowAdapterIdV1::WorkerHostPrepareV1],
            Self::Verification => &[WorkflowAdapterIdV1::WorkerBareBinCiV1],
            Self::ReleaseBuild => &[
                WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1,
                WorkflowAdapterIdV1::WorkerOciReleaseBuildV1,
            ],
            Self::DeterministicReduce => &[WorkflowAdapterIdV1::ControllerReduceV1],
            Self::ResourceReservation => &[WorkflowAdapterIdV1::ExecutorResourceReserveV1],
            Self::Backup => &[WorkflowAdapterIdV1::ExecutorBackupV1],
            Self::Migration => &[WorkflowAdapterIdV1::ExecutorMigrationV1],
            Self::CandidateHealth => &[WorkflowAdapterIdV1::ExecutorCandidateHealthV1],
            Self::Cutover => &[WorkflowAdapterIdV1::ExecutorCutoverV1],
            Self::ReleasedObservation => &[WorkflowAdapterIdV1::ExecutorReleasedObserveV1],
            Self::Rollback => &[WorkflowAdapterIdV1::ExecutorRollbackV1],
        }
    }

    const fn expected_pool(self) -> WorkflowWorkerPoolV1 {
        match self {
            Self::SourceAdmission | Self::DeterministicReduce => WorkflowWorkerPoolV1::Controller,
            Self::HostPrepare | Self::ReleaseBuild => WorkflowWorkerPoolV1::VpsRequired,
            Self::Verification => WorkflowWorkerPoolV1::BuildCompute,
            Self::ResourceReservation
            | Self::Backup
            | Self::Migration
            | Self::CandidateHealth
            | Self::Cutover
            | Self::ReleasedObservation
            | Self::Rollback => WorkflowWorkerPoolV1::PrivilegedExecutor,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowNodeActivationV1 {
    Always,
    OnMutationFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowAdapterIdV1 {
    ControllerSourceAdmissionV1,
    WorkerHostPrepareV1,
    WorkerBareBinCiV1,
    WorkerNativeReleaseBuildV1,
    WorkerOciReleaseBuildV1,
    ControllerReduceV1,
    ExecutorResourceReserveV1,
    ExecutorBackupV1,
    ExecutorMigrationV1,
    ExecutorCandidateHealthV1,
    ExecutorCutoverV1,
    ExecutorReleasedObserveV1,
    ExecutorRollbackV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowWorkerPoolV1 {
    Controller,
    VpsRequired,
    BuildCompute,
    PrivilegedExecutor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowNetworkClassV1 {
    Offline,
    DependencyEgress,
    LocalHealthOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCacheClassV1 {
    None,
    Dependency,
    PreparedRun,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowArtifactKindV1 {
    SourceSnapshot,
    PreparedRun,
    VerificationReceipt,
    ReleaseBundle,
    ReductionReceipt,
    ResourceReservation,
    BackupReceipt,
    MigrationReceipt,
    CandidateHealthReceipt,
    CutoverReceipt,
    ReleasedObservationReceipt,
    RollbackReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowResourceEnvelopeV1 {
    pub cpu_millicores: u32,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub scratch_max_bytes: u64,
    pub scratch_max_inodes: u64,
    pub output_max_bytes: u64,
}

impl WorkflowResourceEnvelopeV1 {
    fn validate(&self) -> Result<(), WorkflowContractError> {
        if !(100..=32_000).contains(&self.cpu_millicores)
            || !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&self.memory_max_bytes)
            || !(8..=4_096).contains(&self.tasks_max)
            || !(1024 * 1024..=MAX_SCRATCH_BYTES).contains(&self.scratch_max_bytes)
            || !(1_024..=100_000_000).contains(&self.scratch_max_inodes)
            || !(1_024..=MAX_OUTPUT_BYTES).contains(&self.output_max_bytes)
        {
            return Err(WorkflowContractError::InvalidResourceEnvelope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowExecutionProfileV1 {
    pub profile_id: WorkflowProfileId,
    pub adapter_id: WorkflowAdapterIdV1,
    pub worker_pool: WorkflowWorkerPoolV1,
    pub network_class: WorkflowNetworkClassV1,
    pub cache_class: WorkflowCacheClassV1,
    pub timeout_ms: u64,
    pub resources: Option<WorkflowResourceEnvelopeV1>,
}

impl WorkflowExecutionProfileV1 {
    fn validate(&self) -> Result<(), WorkflowContractError> {
        if !(100..=10_800_000).contains(&self.timeout_ms) {
            return Err(WorkflowContractError::InvalidTimeout);
        }
        match self.worker_pool {
            WorkflowWorkerPoolV1::Controller => {
                if self.resources.is_some()
                    || self.network_class != WorkflowNetworkClassV1::Offline
                    || self.cache_class != WorkflowCacheClassV1::None
                {
                    return Err(WorkflowContractError::InvalidExecutionProfile);
                }
            }
            WorkflowWorkerPoolV1::VpsRequired
            | WorkflowWorkerPoolV1::BuildCompute
            | WorkflowWorkerPoolV1::PrivilegedExecutor => self
                .resources
                .as_ref()
                .ok_or(WorkflowContractError::InvalidResourceEnvelope)?
                .validate()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeV1 {
    pub node_id: WorkflowNodeId,
    pub display_name: String,
    pub kind: WorkflowNodeKindV1,
    pub activation: WorkflowNodeActivationV1,
    pub profile_id: WorkflowProfileId,
    pub depends_on: Vec<WorkflowNodeId>,
    pub input_contracts: Vec<WorkflowArtifactKindV1>,
    pub output_contract: WorkflowArtifactKindV1,
}

impl WorkflowNodeV1 {
    fn validate_local(&self) -> Result<(), WorkflowContractError> {
        let display_name = self.display_name.trim();
        if display_name.is_empty() || display_name.len() > 96 {
            return Err(WorkflowContractError::InvalidDisplayName);
        }
        if self.output_contract != self.kind.expected_output() {
            return Err(WorkflowContractError::ArtifactContractMismatch(
                self.node_id.clone(),
            ));
        }
        if self.kind == WorkflowNodeKindV1::Rollback {
            if self.activation != WorkflowNodeActivationV1::OnMutationFailure {
                return Err(WorkflowContractError::InvalidActivation(
                    self.node_id.clone(),
                ));
            }
        } else if self.activation != WorkflowNodeActivationV1::Always {
            return Err(WorkflowContractError::InvalidActivation(
                self.node_id.clone(),
            ));
        }
        if !strictly_sorted_unique(&self.depends_on)
            || self.depends_on.contains(&self.node_id)
            || !strictly_sorted_unique(&self.input_contracts)
        {
            return Err(WorkflowContractError::InvalidDependencies(
                self.node_id.clone(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPolicyV1 {
    pub schema_version: u16,
    pub fairness_weight: u16,
    pub execution_profiles: Vec<WorkflowExecutionProfileV1>,
    pub nodes: Vec<WorkflowNodeV1>,
}

impl WorkflowPolicyV1 {
    pub fn validate(&self) -> Result<(), WorkflowContractError> {
        if self.schema_version != WORKFLOW_POLICY_SCHEMA_VERSION {
            return Err(WorkflowContractError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if !(1..=16).contains(&self.fairness_weight)
            || self.execution_profiles.is_empty()
            || self.execution_profiles.len() > MAX_WORKFLOW_PROFILES
            || self.nodes.is_empty()
            || self.nodes.len() > MAX_WORKFLOW_NODES
        {
            return Err(WorkflowContractError::InvalidWorkflowBounds);
        }

        let mut profiles = BTreeMap::new();
        for profile in &self.execution_profiles {
            profile.validate()?;
            if profiles.insert(&profile.profile_id, profile).is_some() {
                return Err(WorkflowContractError::DuplicateProfile(
                    profile.profile_id.clone(),
                ));
            }
        }

        let mut nodes = BTreeMap::new();
        for node in &self.nodes {
            node.validate_local()?;
            let profile = profiles
                .get(&node.profile_id)
                .ok_or_else(|| WorkflowContractError::MissingProfile(node.profile_id.clone()))?;
            if !node.kind.expected_adapter().contains(&profile.adapter_id)
                || node.kind.expected_pool() != profile.worker_pool
                || !profile_matches_kind(profile, node.kind)
            {
                return Err(WorkflowContractError::ProfileKindMismatch(
                    node.node_id.clone(),
                ));
            }
            if nodes.insert(&node.node_id, node).is_some() {
                return Err(WorkflowContractError::DuplicateNode(node.node_id.clone()));
            }
        }

        for node in &self.nodes {
            let mut expected_inputs = BTreeSet::new();
            for dependency in &node.depends_on {
                let dependency = nodes.get(dependency).ok_or_else(|| {
                    WorkflowContractError::MissingDependency {
                        node: node.node_id.clone(),
                        dependency: dependency.clone(),
                    }
                })?;
                expected_inputs.insert(dependency.output_contract);
            }
            if node
                .input_contracts
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_inputs
            {
                return Err(WorkflowContractError::ArtifactContractMismatch(
                    node.node_id.clone(),
                ));
            }
        }

        validate_topology(&nodes)?;
        validate_standard_graph(&nodes)?;
        Ok(())
    }

    pub fn node(&self, node_id: &WorkflowNodeId) -> Option<&WorkflowNodeV1> {
        self.nodes.iter().find(|node| &node.node_id == node_id)
    }

    pub fn profile(&self, profile_id: &WorkflowProfileId) -> Option<&WorkflowExecutionProfileV1> {
        self.execution_profiles
            .iter()
            .find(|profile| &profile.profile_id == profile_id)
    }

    pub fn ordered_nodes(&self) -> Result<Vec<&WorkflowNodeV1>, WorkflowContractError> {
        self.validate()?;
        let by_id = self
            .nodes
            .iter()
            .map(|node| (&node.node_id, node))
            .collect::<BTreeMap<_, _>>();
        let mut ordered = Vec::with_capacity(self.nodes.len());
        let mut emitted = BTreeSet::new();
        while ordered.len() < self.nodes.len() {
            let Some(node) = by_id.values().find(|node| {
                !emitted.contains(&node.node_id)
                    && node
                        .depends_on
                        .iter()
                        .all(|dependency| emitted.contains(dependency))
            }) else {
                return Err(WorkflowContractError::CyclicGraph);
            };
            emitted.insert(node.node_id.clone());
            ordered.push(*node);
        }
        Ok(ordered)
    }
}

fn profile_matches_kind(profile: &WorkflowExecutionProfileV1, kind: WorkflowNodeKindV1) -> bool {
    match kind {
        WorkflowNodeKindV1::HostPrepare => {
            profile.network_class == WorkflowNetworkClassV1::DependencyEgress
                && profile.cache_class == WorkflowCacheClassV1::Dependency
        }
        WorkflowNodeKindV1::Verification | WorkflowNodeKindV1::ReleaseBuild => {
            profile.network_class == WorkflowNetworkClassV1::Offline
                && profile.cache_class == WorkflowCacheClassV1::PreparedRun
        }
        WorkflowNodeKindV1::CandidateHealth | WorkflowNodeKindV1::ReleasedObservation => {
            profile.network_class == WorkflowNetworkClassV1::LocalHealthOnly
                && profile.cache_class == WorkflowCacheClassV1::None
        }
        WorkflowNodeKindV1::SourceAdmission
        | WorkflowNodeKindV1::DeterministicReduce
        | WorkflowNodeKindV1::ResourceReservation
        | WorkflowNodeKindV1::Backup
        | WorkflowNodeKindV1::Migration
        | WorkflowNodeKindV1::Cutover
        | WorkflowNodeKindV1::Rollback => {
            profile.network_class == WorkflowNetworkClassV1::Offline
                && profile.cache_class == WorkflowCacheClassV1::None
        }
    }
}

fn validate_topology(
    nodes: &BTreeMap<&WorkflowNodeId, &WorkflowNodeV1>,
) -> Result<(), WorkflowContractError> {
    let mut emitted = BTreeSet::new();
    while emitted.len() < nodes.len() {
        let before = emitted.len();
        for node in nodes.values() {
            if !emitted.contains(&node.node_id)
                && node
                    .depends_on
                    .iter()
                    .all(|dependency| emitted.contains(dependency))
            {
                emitted.insert(node.node_id.clone());
            }
        }
        if emitted.len() == before {
            return Err(WorkflowContractError::CyclicGraph);
        }
    }
    Ok(())
}

fn validate_standard_graph(
    nodes: &BTreeMap<&WorkflowNodeId, &WorkflowNodeV1>,
) -> Result<(), WorkflowContractError> {
    let by_kind = |kind| {
        nodes
            .values()
            .copied()
            .filter(|node| node.kind == kind)
            .collect::<Vec<_>>()
    };
    let exactly_one = |kind| {
        let matches = by_kind(kind);
        if matches.len() == 1 {
            Ok(matches[0])
        } else {
            Err(WorkflowContractError::InvalidNodeCardinality(kind))
        }
    };

    let source = exactly_one(WorkflowNodeKindV1::SourceAdmission)?;
    let prepare = exactly_one(WorkflowNodeKindV1::HostPrepare)?;
    let build = exactly_one(WorkflowNodeKindV1::ReleaseBuild)?;
    let reduce = exactly_one(WorkflowNodeKindV1::DeterministicReduce)?;
    let reserve = exactly_one(WorkflowNodeKindV1::ResourceReservation)?;
    let candidate = exactly_one(WorkflowNodeKindV1::CandidateHealth)?;
    let cutover = exactly_one(WorkflowNodeKindV1::Cutover)?;
    let observe = exactly_one(WorkflowNodeKindV1::ReleasedObservation)?;
    let rollback = exactly_one(WorkflowNodeKindV1::Rollback)?;
    let verification = by_kind(WorkflowNodeKindV1::Verification);
    if verification.is_empty() {
        return Err(WorkflowContractError::InvalidNodeCardinality(
            WorkflowNodeKindV1::Verification,
        ));
    }

    require_dependencies(source, &[])?;
    require_dependencies(prepare, std::slice::from_ref(&source.node_id))?;
    require_dependencies(build, std::slice::from_ref(&prepare.node_id))?;
    for node in &verification {
        require_dependencies(node, std::slice::from_ref(&prepare.node_id))?;
    }
    let mut reduce_dependencies = verification
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    reduce_dependencies.push(build.node_id.clone());
    reduce_dependencies.sort();
    require_dependencies(reduce, &reduce_dependencies)?;
    require_dependencies(reserve, std::slice::from_ref(&reduce.node_id))?;

    let backup = by_kind(WorkflowNodeKindV1::Backup);
    if backup.len() > 1 {
        return Err(WorkflowContractError::InvalidNodeCardinality(
            WorkflowNodeKindV1::Backup,
        ));
    }
    let migration = by_kind(WorkflowNodeKindV1::Migration);
    if migration.len() > 1 {
        return Err(WorkflowContractError::InvalidNodeCardinality(
            WorkflowNodeKindV1::Migration,
        ));
    }
    let mut previous = reserve;
    if let Some(backup) = backup.first() {
        require_dependencies(backup, std::slice::from_ref(&previous.node_id))?;
        previous = backup;
    }
    if let Some(migration) = migration.first() {
        require_dependencies(migration, std::slice::from_ref(&previous.node_id))?;
        previous = migration;
    }
    require_dependencies(candidate, std::slice::from_ref(&previous.node_id))?;
    require_dependencies(cutover, std::slice::from_ref(&candidate.node_id))?;
    require_dependencies(observe, std::slice::from_ref(&cutover.node_id))?;
    require_dependencies(rollback, std::slice::from_ref(&cutover.node_id))?;
    Ok(())
}

fn require_dependencies(
    node: &WorkflowNodeV1,
    dependencies: &[WorkflowNodeId],
) -> Result<(), WorkflowContractError> {
    if node.depends_on == dependencies {
        Ok(())
    } else {
        Err(WorkflowContractError::InvalidDependencies(
            node.node_id.clone(),
        ))
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLeaseV1 {
    pub schema_version: u16,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub workflow_policy_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub node_id: WorkflowNodeId,
    pub node_kind: WorkflowNodeKindV1,
    pub profile_id: WorkflowProfileId,
    pub adapter_id: WorkflowAdapterIdV1,
    pub worker_pool: WorkflowWorkerPoolV1,
    pub network_class: WorkflowNetworkClassV1,
    pub cache_class: WorkflowCacheClassV1,
    pub timeout_ms: u64,
    pub resources: Option<WorkflowResourceEnvelopeV1>,
    pub input_contracts: Vec<WorkflowArtifactKindV1>,
    pub output_contract: WorkflowArtifactKindV1,
    pub expected_input_digest: EvidenceDigest,
    pub worker_id: String,
    pub host_id: String,
    pub leased_at_ms: i64,
    pub expires_at_ms: i64,
    pub lease_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowLeaseDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lease_id: Uuid,
    lease_generation: u32,
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    node_id: &'a WorkflowNodeId,
    node_kind: WorkflowNodeKindV1,
    profile_id: &'a WorkflowProfileId,
    adapter_id: WorkflowAdapterIdV1,
    worker_pool: WorkflowWorkerPoolV1,
    network_class: WorkflowNetworkClassV1,
    cache_class: WorkflowCacheClassV1,
    timeout_ms: u64,
    resources: &'a Option<WorkflowResourceEnvelopeV1>,
    input_contracts: &'a [WorkflowArtifactKindV1],
    output_contract: WorkflowArtifactKindV1,
    expected_input_digest: &'a EvidenceDigest,
    worker_id: &'a str,
    host_id: &'a str,
    leased_at_ms: i64,
    expires_at_ms: i64,
}

impl WorkflowLeaseV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: Uuid,
        lease_generation: u32,
        request_id: Uuid,
        attempt_id: Uuid,
        project_id: ProjectId,
        source_sha: GitCommitId,
        workflow_policy_digest: EvidenceDigest,
        preparation_key: EvidenceDigest,
        node: &WorkflowNodeV1,
        profile: &WorkflowExecutionProfileV1,
        expected_input_digest: EvidenceDigest,
        worker_id: String,
        host_id: String,
        leased_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<Self, WorkflowContractError> {
        let mut lease = Self {
            schema_version: WORKFLOW_LEASE_SCHEMA_VERSION,
            lease_id,
            lease_generation,
            request_id,
            attempt_id,
            project_id,
            source_sha,
            workflow_policy_digest,
            preparation_key,
            node_id: node.node_id.clone(),
            node_kind: node.kind,
            profile_id: profile.profile_id.clone(),
            adapter_id: profile.adapter_id,
            worker_pool: profile.worker_pool,
            network_class: profile.network_class,
            cache_class: profile.cache_class,
            timeout_ms: profile.timeout_ms,
            resources: profile.resources.clone(),
            input_contracts: node.input_contracts.clone(),
            output_contract: node.output_contract,
            expected_input_digest,
            worker_id,
            host_id,
            leased_at_ms,
            expires_at_ms,
            lease_digest: EvidenceDigest::sha256([]),
        };
        lease.lease_digest = lease.calculate_digest()?;
        lease.validate()?;
        Ok(lease)
    }

    pub fn validate(&self) -> Result<(), WorkflowContractError> {
        let profile = WorkflowExecutionProfileV1 {
            profile_id: self.profile_id.clone(),
            adapter_id: self.adapter_id,
            worker_pool: self.worker_pool,
            network_class: self.network_class,
            cache_class: self.cache_class,
            timeout_ms: self.timeout_ms,
            resources: self.resources.clone(),
        };
        if self.schema_version != WORKFLOW_LEASE_SCHEMA_VERSION
            || self.lease_id.is_nil()
            || self.request_id.is_nil()
            || self.attempt_id.is_nil()
            || self.lease_generation == 0
            || self.leased_at_ms < 0
            || self.expires_at_ms <= self.leased_at_ms
            || !valid_workflow_identity(&self.worker_id)
            || !valid_workflow_identity(&self.host_id)
            || self.node_kind.is_controller_managed()
            || !self.node_kind.expected_adapter().contains(&self.adapter_id)
            || self.node_kind.expected_pool() != self.worker_pool
            || !profile_matches_kind(&profile, self.node_kind)
            || profile.validate().is_err()
            || !strictly_sorted_unique(&self.input_contracts)
            || self.output_contract != self.node_kind.expected_output()
            || self.lease_digest != self.calculate_digest()?
        {
            return Err(WorkflowContractError::InvalidLease);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowContractError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowContractError> {
        let lease: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&lease)? != bytes {
            return Err(WorkflowContractError::NoncanonicalDocument);
        }
        lease.validate()?;
        Ok(lease)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, WorkflowContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowLeaseDigestPayload {
                purpose: "rdashboard.workflow-lease.v1",
                schema_version: self.schema_version,
                lease_id: self.lease_id,
                lease_generation: self.lease_generation,
                request_id: self.request_id,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                node_id: &self.node_id,
                node_kind: self.node_kind,
                profile_id: &self.profile_id,
                adapter_id: self.adapter_id,
                worker_pool: self.worker_pool,
                network_class: self.network_class,
                cache_class: self.cache_class,
                timeout_ms: self.timeout_ms,
                resources: &self.resources,
                input_contracts: &self.input_contracts,
                output_contract: self.output_contract,
                expected_input_digest: &self.expected_input_digest,
                worker_id: &self.worker_id,
                host_id: &self.host_id,
                leased_at_ms: self.leased_at_ms,
                expires_at_ms: self.expires_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowNodeOutcomeV1 {
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCleanupResultV1 {
    Complete,
    Pending,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeReceiptV1 {
    pub schema_version: u16,
    pub lease_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub workflow_policy_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub node_id: WorkflowNodeId,
    pub node_kind: WorkflowNodeKindV1,
    pub worker_id: String,
    pub host_id: String,
    pub expected_input_digest: EvidenceDigest,
    pub outcome: WorkflowNodeOutcomeV1,
    pub output_digest: Option<EvidenceDigest>,
    pub execution_receipt_digest: EvidenceDigest,
    pub cleanup_receipt_digest: EvidenceDigest,
    pub cleanup_result: WorkflowCleanupResultV1,
    pub completed_at_ms: i64,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowNodeReceiptDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lease_digest: &'a EvidenceDigest,
    lease_id: Uuid,
    lease_generation: u32,
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    node_id: &'a WorkflowNodeId,
    node_kind: WorkflowNodeKindV1,
    worker_id: &'a str,
    host_id: &'a str,
    expected_input_digest: &'a EvidenceDigest,
    outcome: WorkflowNodeOutcomeV1,
    output_digest: &'a Option<EvidenceDigest>,
    execution_receipt_digest: &'a EvidenceDigest,
    cleanup_receipt_digest: &'a EvidenceDigest,
    cleanup_result: WorkflowCleanupResultV1,
    completed_at_ms: i64,
}

impl WorkflowNodeReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease: &WorkflowLeaseV1,
        outcome: WorkflowNodeOutcomeV1,
        output_digest: Option<EvidenceDigest>,
        execution_receipt_digest: EvidenceDigest,
        cleanup_receipt_digest: EvidenceDigest,
        cleanup_result: WorkflowCleanupResultV1,
        completed_at_ms: i64,
    ) -> Result<Self, WorkflowContractError> {
        lease.validate()?;
        let mut receipt = Self {
            schema_version: WORKFLOW_NODE_RECEIPT_SCHEMA_VERSION,
            lease_digest: lease.lease_digest.clone(),
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            request_id: lease.request_id,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            source_sha: lease.source_sha.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
            preparation_key: lease.preparation_key.clone(),
            node_id: lease.node_id.clone(),
            node_kind: lease.node_kind,
            worker_id: lease.worker_id.clone(),
            host_id: lease.host_id.clone(),
            expected_input_digest: lease.expected_input_digest.clone(),
            outcome,
            output_digest,
            execution_receipt_digest,
            cleanup_receipt_digest,
            cleanup_result,
            completed_at_ms,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), WorkflowContractError> {
        let output_matches = match self.outcome {
            WorkflowNodeOutcomeV1::Succeeded => self.output_digest.is_some(),
            WorkflowNodeOutcomeV1::Failed => self.output_digest.is_none(),
        };
        let cleanup_matches = self.outcome != WorkflowNodeOutcomeV1::Succeeded
            || self.cleanup_result == WorkflowCleanupResultV1::Complete;
        if self.schema_version != WORKFLOW_NODE_RECEIPT_SCHEMA_VERSION
            || self.lease_id.is_nil()
            || self.request_id.is_nil()
            || self.attempt_id.is_nil()
            || self.lease_generation == 0
            || self.completed_at_ms < 0
            || !valid_workflow_identity(&self.worker_id)
            || !valid_workflow_identity(&self.host_id)
            || !output_matches
            || !cleanup_matches
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(WorkflowContractError::InvalidNodeReceipt);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowContractError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowContractError> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(WorkflowContractError::NoncanonicalDocument);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, WorkflowContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowNodeReceiptDigestPayload {
                purpose: "rdashboard.workflow-node-receipt.v1",
                schema_version: self.schema_version,
                lease_digest: &self.lease_digest,
                lease_id: self.lease_id,
                lease_generation: self.lease_generation,
                request_id: self.request_id,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                node_id: &self.node_id,
                node_kind: self.node_kind,
                worker_id: &self.worker_id,
                host_id: &self.host_id,
                expected_input_digest: &self.expected_input_digest,
                outcome: self.outcome,
                output_digest: &self.output_digest,
                execution_receipt_digest: &self.execution_receipt_digest,
                cleanup_receipt_digest: &self.cleanup_receipt_digest,
                cleanup_result: self.cleanup_result,
                completed_at_ms: self.completed_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReductionInputV1 {
    pub node_id: WorkflowNodeId,
    pub node_kind: WorkflowNodeKindV1,
    pub receipt_digest: EvidenceDigest,
    pub output_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReductionReceiptV1 {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub workflow_policy_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub reduce_node_id: WorkflowNodeId,
    pub inputs: Vec<WorkflowReductionInputV1>,
    pub reduced_at_ms: i64,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowReductionDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    reduce_node_id: &'a WorkflowNodeId,
    inputs: &'a [WorkflowReductionInputV1],
    reduced_at_ms: i64,
}

impl WorkflowReductionReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        attempt_id: Uuid,
        project_id: ProjectId,
        source_sha: GitCommitId,
        workflow_policy_digest: EvidenceDigest,
        preparation_key: EvidenceDigest,
        reduce_node_id: WorkflowNodeId,
        mut inputs: Vec<WorkflowReductionInputV1>,
        reduced_at_ms: i64,
    ) -> Result<Self, WorkflowContractError> {
        inputs.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let mut receipt = Self {
            schema_version: WORKFLOW_REDUCTION_RECEIPT_SCHEMA_VERSION,
            request_id,
            attempt_id,
            project_id,
            source_sha,
            workflow_policy_digest,
            preparation_key,
            reduce_node_id,
            inputs,
            reduced_at_ms,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), WorkflowContractError> {
        if self.schema_version != WORKFLOW_REDUCTION_RECEIPT_SCHEMA_VERSION
            || self.request_id.is_nil()
            || self.attempt_id.is_nil()
            || self.reduced_at_ms < 0
            || self.inputs.is_empty()
            || !self
                .inputs
                .windows(2)
                .all(|pair| pair[0].node_id < pair[1].node_id)
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(WorkflowContractError::InvalidReductionReceipt);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowContractError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowContractError> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(WorkflowContractError::NoncanonicalDocument);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, WorkflowContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowReductionDigestPayload {
                purpose: "rdashboard.workflow-reduction-receipt.v1",
                schema_version: self.schema_version,
                request_id: self.request_id,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                reduce_node_id: &self.reduce_node_id,
                inputs: &self.inputs,
                reduced_at_ms: self.reduced_at_ms,
            },
        )?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowContractError {
    #[error("unsupported workflow schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("{0} is invalid")]
    InvalidIdentifier(&'static str),
    #[error("workflow display name is empty or too large")]
    InvalidDisplayName,
    #[error("workflow node/profile count or fairness weight is outside policy bounds")]
    InvalidWorkflowBounds,
    #[error("duplicate workflow profile {0}")]
    DuplicateProfile(WorkflowProfileId),
    #[error("workflow profile {0} is missing")]
    MissingProfile(WorkflowProfileId),
    #[error("duplicate workflow node {0}")]
    DuplicateNode(WorkflowNodeId),
    #[error("workflow node {node} references missing dependency {dependency}")]
    MissingDependency {
        node: WorkflowNodeId,
        dependency: WorkflowNodeId,
    },
    #[error("workflow node {0} has invalid dependencies")]
    InvalidDependencies(WorkflowNodeId),
    #[error("workflow graph contains a dependency cycle")]
    CyclicGraph,
    #[error("workflow node kind {0:?} has an invalid cardinality")]
    InvalidNodeCardinality(WorkflowNodeKindV1),
    #[error("workflow node {0} uses an execution profile for another node kind")]
    ProfileKindMismatch(WorkflowNodeId),
    #[error("workflow node {0} has mismatched input/output contracts")]
    ArtifactContractMismatch(WorkflowNodeId),
    #[error("workflow node {0} has an invalid activation rule")]
    InvalidActivation(WorkflowNodeId),
    #[error("workflow execution timeout is outside policy bounds")]
    InvalidTimeout,
    #[error("workflow execution profile violates its worker/network/cache boundary")]
    InvalidExecutionProfile,
    #[error("workflow resource envelope is outside policy bounds")]
    InvalidResourceEnvelope,
    #[error("workflow lease is structurally invalid or has a mismatched digest")]
    InvalidLease,
    #[error("workflow node receipt is structurally invalid or has a mismatched digest")]
    InvalidNodeReceipt,
    #[error("workflow reduction receipt is structurally invalid or has a mismatched digest")]
    InvalidReductionReceipt,
    #[error("workflow document is not canonical JCS")]
    NoncanonicalDocument,
    #[error("workflow canonical encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
}
