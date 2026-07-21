use std::{
    collections::HashSet,
    fmt,
    path::{Component, PathBuf},
    str::FromStr,
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use url::Url;

use super::{
    EvidenceDigest, ProjectId, WorkflowDeliveryModeV1, WorkflowHostPreparationPolicyV1,
    WorkflowNodeKindV1, WorkflowPolicyV1,
};

pub const PROJECT_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const PROJECT_MANIFEST_V2_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectManifestV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub display_name: String,
    pub source: SourcePolicy,
    pub ci: CiPolicy,
    pub build: BuildPolicy,
    pub health_checks: Vec<HealthCheckPolicy>,
    pub data_volumes: Vec<DataVolumePolicy>,
    pub migration: MigrationPolicy,
    pub rollback: RollbackPolicy,
    pub notifications: NotificationPolicy,
}

impl ProjectManifestV1 {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != PROJECT_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchemaVersion(self.schema_version));
        }
        validate_common_manifest(
            &self.display_name,
            &self.source,
            &self.build,
            &self.health_checks,
            &self.data_volumes,
            &self.rollback,
        )?;
        if self.build.kind != BuildKind::Oci {
            return Err(ManifestError::BuildWorkflowMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectManifestV2 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub display_name: String,
    pub source: SourcePolicy,
    pub ci: CiPolicy,
    pub build: BuildPolicy,
    pub workflow: WorkflowPolicyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_preparation: Option<WorkflowHostPreparationPolicyV1>,
    pub health_checks: Vec<HealthCheckPolicy>,
    pub data_volumes: Vec<DataVolumePolicy>,
    pub migration: MigrationPolicy,
    pub rollback: RollbackPolicy,
    pub notifications: NotificationPolicy,
}

#[derive(Serialize)]
struct ProjectManifestV2DigestPayload<'a> {
    purpose: &'static str,
    manifest: &'a ProjectManifestV2,
}

impl ProjectManifestV2 {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != PROJECT_MANIFEST_V2_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchemaVersion(self.schema_version));
        }
        validate_common_manifest(
            &self.display_name,
            &self.source,
            &self.build,
            &self.health_checks,
            &self.data_volumes,
            &self.rollback,
        )?;
        self.workflow
            .validate()
            .map_err(|_| ManifestError::WorkflowInvalid)?;
        if self.workflow.delivery_mode == WorkflowDeliveryModeV1::SelfUpdateHandoff
            && (self.project_id.as_str() != "rdashboard"
                || self.build.kind != BuildKind::Native
                || !self.data_volumes.is_empty()
                || self.migration.entrypoint != MigrationEntrypoint::None
                || self.migration.write_fence != WriteFencePolicy::Unsupported
                || !self.rollback.code_rollback)
        {
            return Err(ManifestError::SelfUpdateWorkflowMismatch);
        }
        let release_adapter = self
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
            .and_then(|node| self.workflow.profile(&node.profile_id))
            .map(|profile| profile.adapter_id)
            .ok_or(ManifestError::BuildWorkflowMismatch)?;
        let build_matches_release = matches!(
            (self.build.kind, release_adapter),
            (
                BuildKind::Oci,
                super::WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
            ) | (
                BuildKind::Native,
                super::WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
            )
        );
        if !build_matches_release {
            return Err(ManifestError::BuildWorkflowMismatch);
        }
        if let Some(policy) = self.host_preparation.as_ref() {
            let preparation_profile = self
                .workflow
                .nodes
                .iter()
                .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
                .and_then(|node| self.workflow.profile(&node.profile_id));
            if policy.validate().is_err()
                || preparation_profile
                    .is_none_or(|profile| profile.network_class != policy.required_network_class())
            {
                return Err(ManifestError::WorkflowInvalid);
            }
        }

        let has_backup = self
            .workflow
            .nodes
            .iter()
            .any(|node| node.kind == WorkflowNodeKindV1::Backup);
        let backup_required = self
            .data_volumes
            .iter()
            .any(|volume| volume.backup_required);
        if has_backup != backup_required {
            return Err(ManifestError::WorkflowBackupMismatch);
        }
        let has_migration = self
            .workflow
            .nodes
            .iter()
            .any(|node| node.kind == WorkflowNodeKindV1::Migration);
        let migration_required = self.migration.entrypoint != MigrationEntrypoint::None;
        if has_migration != migration_required {
            return Err(ManifestError::WorkflowMigrationMismatch);
        }
        Ok(())
    }

    pub fn workflow_policy_digest(&self) -> Result<EvidenceDigest, ManifestError> {
        self.validate()?;
        Ok(EvidenceDigest::sha256(
            serde_jcs::to_vec(&ProjectManifestV2DigestPayload {
                purpose: "rdashboard.project-workflow-policy.v2",
                manifest: self,
            })
            .map_err(|_| ManifestError::CanonicalEncoding)?,
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|_| ManifestError::CanonicalEncoding)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| ManifestError::InvalidManifestJson)?;
        if serde_jcs::to_vec(&manifest).map_err(|_| ManifestError::CanonicalEncoding)? != bytes {
            return Err(ManifestError::NoncanonicalManifest);
        }
        manifest.validate()?;
        Ok(manifest)
    }
}

fn validate_common_manifest(
    display_name: &str,
    source: &SourcePolicy,
    build: &BuildPolicy,
    health_checks: &[HealthCheckPolicy],
    data_volumes: &[DataVolumePolicy],
    rollback: &RollbackPolicy,
) -> Result<(), ManifestError> {
    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.len() > 96 {
        return Err(ManifestError::InvalidDisplayName);
    }
    source.validate()?;
    build.validate()?;
    if health_checks.is_empty() {
        return Err(ManifestError::MissingHealthCheck);
    }

    let mut health_names = HashSet::new();
    for check in health_checks {
        check.validate()?;
        if !health_names.insert(check.name.as_str()) {
            return Err(ManifestError::DuplicateHealthCheck(check.name.clone()));
        }
    }

    let mut volume_paths = HashSet::new();
    for volume in data_volumes {
        if volume.path.as_str() == "/" {
            return Err(ManifestError::UnsafeDataPath(volume.path.to_string()));
        }
        if !volume_paths.insert(volume.path.as_str()) {
            return Err(ManifestError::DuplicateDataPath(volume.path.to_string()));
        }
    }

    if !(10..=86_400).contains(&rollback.soak_seconds) {
        return Err(ManifestError::InvalidSoakDuration);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicy {
    pub remote_url: RemoteUrl,
    pub branch: CanonicalBranch,
}

impl SourcePolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.branch != CanonicalBranch::Main {
            return Err(ManifestError::UnsupportedBranch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalBranch {
    Main,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiPolicy {
    BinCi,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildKind {
    #[default]
    Oci,
    Native,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn build_kind_is_default(kind: &BuildKind) -> bool {
    *kind == BuildKind::Oci
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPolicy {
    pub context: BuildContext,
    #[serde(default, skip_serializing_if = "build_kind_is_default")]
    pub kind: BuildKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<RelativePolicyPath>,
}

impl BuildPolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        let valid = match (&self.kind, &self.dockerfile) {
            (BuildKind::Oci, Some(dockerfile)) => {
                std::path::Path::new(dockerfile.as_str()).file_name()
                    == Some(std::ffi::OsStr::new("Dockerfile"))
            }
            (BuildKind::Native, None) => true,
            (BuildKind::Oci, None) | (BuildKind::Native, Some(_)) => false,
        };
        if !valid {
            return Err(ManifestError::InvalidDockerfilePath);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildContext {
    RepositoryRoot,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckPolicy {
    pub name: String,
    pub endpoint: HttpEndpoint,
    pub expected_status: u16,
    pub timeout_seconds: u16,
}

impl HealthCheckPolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        let name = self.name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(ManifestError::InvalidHealthCheckName);
        }
        if !(100..=599).contains(&self.expected_status) {
            return Err(ManifestError::InvalidExpectedStatus);
        }
        if !(1..=120).contains(&self.timeout_seconds) {
            return Err(ManifestError::InvalidHealthTimeout);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataVolumePolicy {
    pub path: AbsolutePolicyPath,
    pub class: DataClass,
    pub backup_required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Stateful,
    Derived,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPolicy {
    pub entrypoint: MigrationEntrypoint,
    pub write_fence: WriteFencePolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEntrypoint {
    None,
    ApplicationMigrate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteFencePolicy {
    Unsupported,
    ApplicationProtocolV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPolicy {
    pub code_rollback: bool,
    pub soak_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPolicy {
    pub route: NotificationRoute,
    pub maintenance_suppression: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRoute {
    TelegramDefault,
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RemoteUrl(String);

impl RemoteUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RemoteUrl {
    type Err = ManifestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Url::parse(value).map_err(|_| ManifestError::InvalidRemoteUrl)?;
        let scheme = parsed.scheme();
        let has_credentials =
            parsed.password().is_some() || (scheme == "https" && !parsed.username().is_empty());
        if !matches!(scheme, "https" | "ssh")
            || parsed.host_str().is_none()
            || has_credentials
            || matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ManifestError::InvalidRemoteUrl);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for RemoteUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct HttpEndpoint(String);

impl HttpEndpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for HttpEndpoint {
    type Err = ManifestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Url::parse(value).map_err(|_| ManifestError::InvalidHealthEndpoint)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ManifestError::InvalidHealthEndpoint);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for HttpEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

macro_rules! policy_path {
    ($name:ident, $absolute:literal, $error:ident) => {
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
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
            type Err = ManifestError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let path = std::path::Path::new(value);
                let absolute_ok = path.is_absolute() == $absolute;
                let normalized = path.components().collect::<PathBuf>();
                let components_ok = !value.is_empty()
                    && value.len() <= 512
                    && !value.contains('\0')
                    && normalized.as_os_str() == path.as_os_str()
                    && path.components().all(|component| {
                        matches!(component, Component::RootDir | Component::Normal(_))
                    });
                if absolute_ok && components_ok {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(ManifestError::$error)
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

policy_path!(AbsolutePolicyPath, true, InvalidAbsolutePath);
policy_path!(RelativePolicyPath, false, InvalidRelativePath);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported project manifest schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("display name must contain 1-96 non-whitespace bytes")]
    InvalidDisplayName,
    #[error("only the canonical main branch is supported")]
    UnsupportedBranch,
    #[error(
        "remote URL must identify a repository over https or ssh without embedded credentials/query/fragment"
    )]
    InvalidRemoteUrl,
    #[error("at least one health check is required")]
    MissingHealthCheck,
    #[error("health check name must contain 1-64 non-whitespace bytes")]
    InvalidHealthCheckName,
    #[error("duplicate health check {0}")]
    DuplicateHealthCheck(String),
    #[error("health endpoint must be an http(s) URL without credentials or fragment")]
    InvalidHealthEndpoint,
    #[error("expected HTTP status must be between 100 and 599")]
    InvalidExpectedStatus,
    #[error("health timeout must be between 1 and 120 seconds")]
    InvalidHealthTimeout,
    #[error("policy path must be absolute, normalized, and bounded")]
    InvalidAbsolutePath,
    #[error("policy path must be relative, normalized, and bounded")]
    InvalidRelativePath,
    #[error("duplicate data path {0}")]
    DuplicateDataPath(String),
    #[error("data path {0} is too broad for a managed project")]
    UnsafeDataPath(String),
    #[error("Dockerfile path must end in Dockerfile")]
    InvalidDockerfilePath,
    #[error("build kind does not match the workflow release adapter")]
    BuildWorkflowMismatch,
    #[error("self-update handoff workflow is not a native rdashboard release contract")]
    SelfUpdateWorkflowMismatch,
    #[error("soak duration must be between 10 seconds and 24 hours")]
    InvalidSoakDuration,
    #[error("workflow backup node does not match backup-required data")]
    WorkflowBackupMismatch,
    #[error("workflow migration node does not match the declared migration entrypoint")]
    WorkflowMigrationMismatch,
    #[error("project manifest is not canonical JCS")]
    NoncanonicalManifest,
    #[error("workflow contract is invalid")]
    WorkflowInvalid,
    #[error("project manifest JSON is invalid")]
    InvalidManifestJson,
    #[error("project manifest canonical encoding failed")]
    CanonicalEncoding,
}
