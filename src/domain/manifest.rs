use std::{
    collections::HashSet,
    fmt,
    path::{Component, PathBuf},
    str::FromStr,
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use url::Url;

use super::ProjectId;

pub const PROJECT_MANIFEST_SCHEMA_VERSION: u16 = 1;

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
        let display_name = self.display_name.trim();
        if display_name.is_empty() || display_name.len() > 96 {
            return Err(ManifestError::InvalidDisplayName);
        }
        self.source.validate()?;
        self.build.validate()?;
        if self.health_checks.is_empty() {
            return Err(ManifestError::MissingHealthCheck);
        }

        let mut health_names = HashSet::new();
        for check in &self.health_checks {
            check.validate()?;
            if !health_names.insert(check.name.as_str()) {
                return Err(ManifestError::DuplicateHealthCheck(check.name.clone()));
            }
        }

        let mut volume_paths = HashSet::new();
        for volume in &self.data_volumes {
            if volume.path.as_str() == "/" {
                return Err(ManifestError::UnsafeDataPath(volume.path.to_string()));
            }
            if !volume_paths.insert(volume.path.as_str()) {
                return Err(ManifestError::DuplicateDataPath(volume.path.to_string()));
            }
        }

        if !(10..=86_400).contains(&self.rollback.soak_seconds) {
            return Err(ManifestError::InvalidSoakDuration);
        }
        Ok(())
    }
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPolicy {
    pub context: BuildContext,
    pub dockerfile: RelativePolicyPath,
}

impl BuildPolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        if std::path::Path::new(self.dockerfile.as_str()).file_name()
            != Some(std::ffi::OsStr::new("Dockerfile"))
        {
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
    #[error("soak duration must be between 10 seconds and 24 hours")]
    InvalidSoakDuration,
}
