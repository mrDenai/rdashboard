use std::{collections::BTreeSet, fmt, path::Path, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use uuid::Uuid;

use crate::domain::{
    AuthorizedDiskReservation, DiskReservation, DiskReservationError, EvidenceDigest, GitCommitId,
    InstalledPolicyIdentity, PhaseArtifacts, ProjectId, valid_application_schema_version,
};

mod release_bundle_store;

pub use release_bundle_store::*;

const MAX_SOURCE_FILES: usize = 100_000;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GENERATED_FILES: usize = 2_000;
const MAX_GENERATED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GENERATED_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DOCKERFILE_BYTES: usize = 256 * 1024;
const MAX_OCI_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OCI_INDEX_MANIFESTS: usize = 1_024;
pub const RELEASE_BUNDLE_SCHEMA_VERSION: u32 = 3;
pub const FIXED_KAMAL_NETWORK_NAME: &str = "kamal";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BuildPath(String);

impl BuildPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BuildPath {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 240
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\0')
            || value.contains('\\')
            || value
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(BuildContractError::InvalidPath(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for BuildPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportedFileKind {
    Regular,
    Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedFileV1 {
    pub path: BuildPath,
    pub kind: ExportedFileKind,
    pub bytes: u64,
    pub digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedReleaseIdentityInputV1 {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_head: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub executor_authorization_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedReleaseIdentityV1 {
    attempt_id: Uuid,
    project_id: ProjectId,
    source_head: GitCommitId,
    source_sequence: u64,
    source_attestation_digest: EvidenceDigest,
    installed_policy: InstalledPolicyIdentity,
    executor_authorization_digest: EvidenceDigest,
    identity_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ReleaseIdentityDigestPayload<'a> {
    purpose: &'static str,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_head: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
    executor_authorization_digest: &'a EvidenceDigest,
}

impl AuthorizedReleaseIdentityV1 {
    pub fn new(input: AuthorizedReleaseIdentityInputV1) -> Result<Self, BuildContractError> {
        if input.attempt_id.is_nil()
            || input.source_sequence == 0
            || input.installed_policy.version == 0
        {
            return Err(BuildContractError::InvalidReleaseIdentity);
        }
        let identity_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&ReleaseIdentityDigestPayload {
                purpose: "rdashboard.authorized-release-identity.v1",
                attempt_id: input.attempt_id,
                project_id: &input.project_id,
                source_head: &input.source_head,
                source_sequence: input.source_sequence,
                source_attestation_digest: &input.source_attestation_digest,
                installed_policy: &input.installed_policy,
                executor_authorization_digest: &input.executor_authorization_digest,
            })?);
        Ok(Self {
            attempt_id: input.attempt_id,
            project_id: input.project_id,
            source_head: input.source_head,
            source_sequence: input.source_sequence,
            source_attestation_digest: input.source_attestation_digest,
            installed_policy: input.installed_policy,
            executor_authorization_digest: input.executor_authorization_digest,
            identity_digest,
        })
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.identity_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableSourceExportV1 {
    release_identity: AuthorizedReleaseIdentityV1,
    files: Vec<ExportedFileV1>,
    digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SourceExportDigestPayload<'a> {
    purpose: &'static str,
    release_identity: &'a AuthorizedReleaseIdentityV1,
    files: &'a [ExportedFileV1],
}

impl ImmutableSourceExportV1 {
    pub fn new(
        release_identity: AuthorizedReleaseIdentityV1,
        mut files: Vec<ExportedFileV1>,
    ) -> Result<Self, BuildContractError> {
        if files.is_empty() || files.len() > MAX_SOURCE_FILES {
            return Err(BuildContractError::SourceFileLimit);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut total = 0_u64;
        for pair in files.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(BuildContractError::DuplicatePath(
                    pair[0].path.as_str().to_owned(),
                ));
            }
        }
        for file in &files {
            total = total
                .checked_add(file.bytes)
                .ok_or(BuildContractError::SizeOverflow)?;
        }
        if total > MAX_SOURCE_BYTES {
            return Err(BuildContractError::SourceByteLimit);
        }
        let digest = EvidenceDigest::sha256(serde_jcs::to_vec(&SourceExportDigestPayload {
            purpose: "rdashboard.immutable-source-export.v1",
            release_identity: &release_identity,
            files: &files,
        })?);
        Ok(Self {
            release_identity,
            files,
            digest,
        })
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.release_identity.project_id
    }

    pub const fn head(&self) -> &GitCommitId {
        &self.release_identity.source_head
    }

    pub const fn release_identity(&self) -> &AuthorizedReleaseIdentityV1 {
        &self.release_identity
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }

    fn file(&self, path: &BuildPath) -> Option<&ExportedFileV1> {
        self.files
            .binary_search_by(|file| file.path.cmp(path))
            .ok()
            .map(|index| &self.files[index])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchAdapterV1 {
    CargoLockedV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryConfigurationPolicyV1 {
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptExecutionPolicyV1 {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretExposureV1 {
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateNetworkAccessV1 {
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefetchEvidenceV1 {
    adapter: PrefetchAdapterV1,
    source_export_digest: EvidenceDigest,
    lockfile_path: BuildPath,
    lockfile_digest: EvidenceDigest,
    cache_digest: EvidenceDigest,
    allowed_registries: Vec<RegistryHost>,
    repository_configuration: RepositoryConfigurationPolicyV1,
    script_execution: ScriptExecutionPolicyV1,
    secret_exposure: SecretExposureV1,
    private_network_access: PrivateNetworkAccessV1,
    digest: EvidenceDigest,
}

#[derive(Serialize)]
struct PrefetchDigestPayload<'a> {
    purpose: &'static str,
    adapter: PrefetchAdapterV1,
    source_export_digest: &'a EvidenceDigest,
    lockfile_path: &'a BuildPath,
    lockfile_digest: &'a EvidenceDigest,
    cache_digest: &'a EvidenceDigest,
    allowed_registries: &'a [RegistryHost],
    repository_configuration: RepositoryConfigurationPolicyV1,
    script_execution: ScriptExecutionPolicyV1,
    secret_exposure: SecretExposureV1,
    private_network_access: PrivateNetworkAccessV1,
}

impl PrefetchEvidenceV1 {
    pub fn cargo_locked(
        source: &ImmutableSourceExportV1,
        cache_digest: EvidenceDigest,
        mut allowed_registries: Vec<RegistryHost>,
    ) -> Result<Self, BuildContractError> {
        let lockfile_path = BuildPath::from_str("Cargo.lock")?;
        let lockfile = source
            .file(&lockfile_path)
            .ok_or(BuildContractError::MissingReviewedLockfile)?;
        if allowed_registries.is_empty() {
            return Err(BuildContractError::RegistryAllowlistEmpty);
        }
        allowed_registries.sort();
        allowed_registries.dedup();
        let payload = PrefetchDigestPayload {
            purpose: "rdashboard.prefetch-evidence.v1",
            adapter: PrefetchAdapterV1::CargoLockedV1,
            source_export_digest: source.digest(),
            lockfile_path: &lockfile_path,
            lockfile_digest: &lockfile.digest,
            cache_digest: &cache_digest,
            allowed_registries: &allowed_registries,
            repository_configuration: RepositoryConfigurationPolicyV1::Ignored,
            script_execution: ScriptExecutionPolicyV1::Disabled,
            secret_exposure: SecretExposureV1::Absent,
            private_network_access: PrivateNetworkAccessV1::Denied,
        };
        let digest = EvidenceDigest::sha256(serde_jcs::to_vec(&payload)?);
        Ok(Self {
            adapter: PrefetchAdapterV1::CargoLockedV1,
            source_export_digest: source.digest().clone(),
            lockfile_path,
            lockfile_digest: lockfile.digest.clone(),
            cache_digest,
            allowed_registries,
            repository_configuration: RepositoryConfigurationPolicyV1::Ignored,
            script_execution: ScriptExecutionPolicyV1::Disabled,
            secret_exposure: SecretExposureV1::Absent,
            private_network_access: PrivateNetworkAccessV1::Denied,
            digest,
        })
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RegistryHost(String);

impl RegistryHost {
    pub fn parse(value: &str) -> Result<Self, BuildContractError> {
        let normalized = value.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > 253
            || normalized == "localhost"
            || Path::new(&normalized)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("local"))
            || normalized.parse::<std::net::IpAddr>().is_ok()
            || !normalized.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
        {
            return Err(BuildContractError::InvalidRegistry(value.to_owned()));
        }
        Ok(Self(normalized))
    }
}

impl<'de> Deserialize<'de> for RegistryHost {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BaseRegistryHost(String);

impl BaseRegistryHost {
    pub fn parse(value: &str) -> Result<Self, BuildContractError> {
        let normalized = value.to_ascii_lowercase();
        if !valid_public_registry_host(&normalized) {
            return Err(BuildContractError::InvalidBaseRegistry(value.to_owned()));
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BaseRegistryHost {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaseRegistryAllowlistV1 {
    registries: Vec<BaseRegistryHost>,
    digest: EvidenceDigest,
}

#[derive(Serialize)]
struct BaseRegistryAllowlistDigestPayload<'a> {
    purpose: &'static str,
    registries: &'a [BaseRegistryHost],
}

impl BaseRegistryAllowlistV1 {
    pub fn new(mut registries: Vec<BaseRegistryHost>) -> Result<Self, BuildContractError> {
        if registries.is_empty() {
            return Err(BuildContractError::BaseRegistryAllowlistEmpty);
        }
        registries.sort();
        registries.dedup();
        let digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&BaseRegistryAllowlistDigestPayload {
                purpose: "rdashboard.base-registry-allowlist.v1",
                registries: &registries,
            })?);
        Ok(Self { registries, digest })
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }

    pub fn registries(&self) -> &[BaseRegistryHost] {
        &self.registries
    }

    fn permits(&self, registry: &BaseRegistryHost) -> bool {
        self.registries.binary_search(registry).is_ok()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OciDigest(String);

impl OciDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for OciDigest {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(BuildContractError::InvalidOciDigest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BuildContractError::InvalidOciDigest);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for OciDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBaseV1 {
    stage: String,
    requested: String,
    registry_manifest: OciDigest,
    platform_manifest: OciDigest,
    platform: String,
}

impl ResolvedBaseV1 {
    /// Builds resolution evidence from the exact registry response bodies.
    ///
    /// The registry document may be an OCI index/Docker manifest list or a single image
    /// manifest. The selected manifest and its configuration must be supplied verbatim so the
    /// complete requested-digest -> platform-descriptor -> manifest -> configuration chain can
    /// be verified before the compact evidence is frozen.
    pub fn from_registry_documents(
        stage: impl Into<String>,
        requested: impl Into<String>,
        platform: impl Into<String>,
        registry_document: &[u8],
        platform_manifest_document: &[u8],
        platform_configuration_document: &[u8],
    ) -> Result<Self, BuildContractError> {
        let stage = stage.into();
        let requested = requested.into();
        let platform = platform.into();
        if !valid_base_stage(&stage) || !valid_base_platform(&platform) {
            return Err(BuildContractError::InvalidBaseImage);
        }
        let reference = parse_base_image_reference(&requested)
            .map_err(|_| BuildContractError::InvalidBaseImage)?;
        let (registry_manifest, platform_manifest) = verify_base_resolution_documents(
            &reference.manifest,
            &platform,
            registry_document,
            platform_manifest_document,
            platform_configuration_document,
        )?;
        Ok(Self {
            stage,
            requested,
            registry_manifest,
            platform_manifest,
            platform,
        })
    }

    pub fn requested(&self) -> &str {
        &self.requested
    }

    pub const fn registry_manifest(&self) -> &OciDigest {
        &self.registry_manifest
    }

    pub const fn platform_manifest(&self) -> &OciDigest {
        &self.platform_manifest
    }

    pub fn platform(&self) -> &str {
        &self.platform
    }

    fn validate(
        &self,
        allowed_registries: &BaseRegistryAllowlistV1,
    ) -> Result<(), BuildContractError> {
        let reference = parse_base_image_reference(&self.requested)
            .map_err(|_| BuildContractError::InvalidBaseImage)?;
        if !valid_base_stage(&self.stage)
            || reference.manifest != self.registry_manifest
            || !valid_base_platform(&self.platform)
        {
            return Err(BuildContractError::InvalidBaseImage);
        }
        if !allowed_registries.permits(&reference.registry) {
            return Err(BuildContractError::BaseRegistryNotAllowed(
                reference.registry.0,
            ));
        }
        Ok(())
    }

    fn evidence_digest(&self) -> Result<EvidenceDigest, BuildContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(self)?))
    }
}

#[derive(Deserialize)]
struct OciRegistryDocumentV2 {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(default)]
    manifests: Option<Vec<OciDescriptorV1>>,
    #[serde(default)]
    config: Option<OciDescriptorV1>,
    #[serde(default)]
    layers: Option<Vec<OciDescriptorV1>>,
}

#[derive(Deserialize)]
struct OciDescriptorV1 {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: OciDigest,
    size: u64,
    #[serde(default)]
    platform: Option<OciPlatformV1>,
}

#[derive(Deserialize)]
struct OciPlatformV1 {
    os: String,
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
struct OciImageConfigurationV1 {
    os: String,
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

fn verify_base_resolution_documents(
    requested_manifest: &OciDigest,
    platform: &str,
    registry_document: &[u8],
    platform_manifest_document: &[u8],
    platform_configuration_document: &[u8],
) -> Result<(OciDigest, OciDigest), BuildContractError> {
    validate_oci_document_size(registry_document)?;
    validate_oci_document_size(platform_manifest_document)?;
    validate_oci_document_size(platform_configuration_document)?;

    let registry_manifest = oci_sha256(registry_document);
    if registry_manifest != *requested_manifest {
        return Err(BuildContractError::InvalidBaseImage);
    }
    let platform_manifest = oci_sha256(platform_manifest_document);
    let platform_manifest_bytes = u64::try_from(platform_manifest_document.len())
        .map_err(|_| BuildContractError::InvalidBaseImage)?;
    let registry = parse_oci_registry_document(registry_document)?;
    match (
        registry.manifests.as_deref(),
        registry.config.as_ref(),
        registry.layers.as_deref(),
    ) {
        (Some(manifests), None, None)
            if valid_index_media_type(&registry.media_type)
                && !manifests.is_empty()
                && manifests.len() <= MAX_OCI_INDEX_MANIFESTS =>
        {
            if !manifests.iter().any(|descriptor| {
                descriptor.digest == platform_manifest
                    && descriptor.size == platform_manifest_bytes
                    && valid_image_manifest_media_type(&descriptor.media_type)
                    && descriptor
                        .platform
                        .as_ref()
                        .is_some_and(|candidate| candidate.matches(platform))
            }) {
                return Err(BuildContractError::InvalidBaseImage);
            }
        }
        (None, Some(_), Some(_)) if valid_image_manifest_media_type(&registry.media_type) => {
            if registry_manifest != platform_manifest {
                return Err(BuildContractError::InvalidBaseImage);
            }
        }
        _ => return Err(BuildContractError::InvalidBaseImage),
    }

    let selected = parse_oci_registry_document(platform_manifest_document)?;
    let config = match (
        selected.manifests.as_deref(),
        selected.config.as_ref(),
        selected.layers.as_deref(),
    ) {
        (None, Some(config), Some(_)) if valid_image_manifest_media_type(&selected.media_type) => {
            config
        }
        _ => return Err(BuildContractError::InvalidBaseImage),
    };
    let platform_configuration_bytes = u64::try_from(platform_configuration_document.len())
        .map_err(|_| BuildContractError::InvalidBaseImage)?;
    if !valid_image_config_media_type(&config.media_type)
        || config.digest != oci_sha256(platform_configuration_document)
        || config.size != platform_configuration_bytes
    {
        return Err(BuildContractError::InvalidBaseImage);
    }
    let configuration: OciImageConfigurationV1 =
        serde_json::from_slice(platform_configuration_document)
            .map_err(|_| BuildContractError::InvalidBaseImage)?;
    if !platform_components_match(
        &configuration.os,
        &configuration.architecture,
        configuration.variant.as_deref(),
        platform,
    ) {
        return Err(BuildContractError::InvalidBaseImage);
    }
    Ok((registry_manifest, platform_manifest))
}

fn validate_oci_document_size(document: &[u8]) -> Result<(), BuildContractError> {
    if document.is_empty() || document.len() > MAX_OCI_DOCUMENT_BYTES {
        return Err(BuildContractError::InvalidBaseImage);
    }
    Ok(())
}

fn parse_oci_registry_document(
    document: &[u8],
) -> Result<OciRegistryDocumentV2, BuildContractError> {
    let parsed: OciRegistryDocumentV2 =
        serde_json::from_slice(document).map_err(|_| BuildContractError::InvalidBaseImage)?;
    if parsed.schema_version != 2 {
        return Err(BuildContractError::InvalidBaseImage);
    }
    Ok(parsed)
}

fn oci_sha256(document: &[u8]) -> OciDigest {
    OciDigest(format!(
        "sha256:{}",
        EvidenceDigest::sha256(document).as_str()
    ))
}

fn valid_base_stage(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_base_platform(value: &str) -> bool {
    matches!(value, "linux/amd64" | "linux/arm64")
}

impl OciPlatformV1 {
    fn matches(&self, platform: &str) -> bool {
        platform_components_match(
            &self.os,
            &self.architecture,
            self.variant.as_deref(),
            platform,
        )
    }
}

fn platform_components_match(
    os: &str,
    architecture: &str,
    variant: Option<&str>,
    platform: &str,
) -> bool {
    match platform {
        "linux/amd64" => {
            os == "linux" && architecture == "amd64" && variant.is_none_or(str::is_empty)
        }
        "linux/arm64" => {
            os == "linux"
                && architecture == "arm64"
                && variant.is_none_or(|value| value.is_empty() || value == "v8")
        }
        _ => false,
    }
}

fn valid_index_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

fn valid_image_manifest_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
    )
}

fn valid_image_config_media_type(value: &str) -> bool {
    matches!(
        value,
        "application/vnd.oci.image.config.v1+json"
            | "application/vnd.docker.container.image.v1+json"
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedFileEvidenceV1 {
    pub path: BuildPath,
    pub kind: ExportedFileKind,
    pub bytes: u64,
    pub digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenBuildContextV1 {
    release_identity: AuthorizedReleaseIdentityV1,
    source_export_digest: EvidenceDigest,
    prefetch_evidence_digest: EvidenceDigest,
    dockerfile_path: BuildPath,
    base_registry_allowlist: BaseRegistryAllowlistV1,
    generated_files: Vec<GeneratedFileEvidenceV1>,
    resolved_bases: Vec<ResolvedBaseV1>,
    dockerfile_digest: EvidenceDigest,
    context_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct FrozenContextDigestPayload<'a> {
    purpose: &'static str,
    release_identity_digest: &'a EvidenceDigest,
    source_export_digest: &'a EvidenceDigest,
    prefetch_evidence_digest: &'a EvidenceDigest,
    dockerfile_path: &'a BuildPath,
    base_registries: &'a [BaseRegistryHost],
    generated_files: &'a [GeneratedFileEvidenceV1],
    resolved_bases: &'a [ResolvedBaseV1],
    dockerfile_digest: &'a EvidenceDigest,
}

impl FrozenBuildContextV1 {
    pub const fn digest(&self) -> &EvidenceDigest {
        &self.context_digest
    }

    pub const fn dockerfile_path(&self) -> &BuildPath {
        &self.dockerfile_path
    }

    pub const fn base_registry_allowlist(&self) -> &BaseRegistryAllowlistV1 {
        &self.base_registry_allowlist
    }
}

pub struct BuildContextFreezeRequest<'a> {
    dockerfile_path: &'a BuildPath,
    dockerfile_contents: &'a str,
    prefetch: &'a PrefetchEvidenceV1,
    base_registry_allowlist: &'a BaseRegistryAllowlistV1,
    generated_files: Vec<GeneratedFileEvidenceV1>,
    declared_generated_paths: &'a [BuildPath],
    resolved_bases: Vec<ResolvedBaseV1>,
}

impl<'a> BuildContextFreezeRequest<'a> {
    pub fn new(
        dockerfile_path: &'a BuildPath,
        dockerfile_contents: &'a str,
        prefetch: &'a PrefetchEvidenceV1,
        base_registry_allowlist: &'a BaseRegistryAllowlistV1,
        generated_files: Vec<GeneratedFileEvidenceV1>,
        declared_generated_paths: &'a [BuildPath],
        resolved_bases: Vec<ResolvedBaseV1>,
    ) -> Self {
        Self {
            dockerfile_path,
            dockerfile_contents,
            prefetch,
            base_registry_allowlist,
            generated_files,
            declared_generated_paths,
            resolved_bases,
        }
    }
}

pub struct BuildContextFreezer;

impl BuildContextFreezer {
    pub fn freeze(
        source: &ImmutableSourceExportV1,
        request: BuildContextFreezeRequest<'_>,
    ) -> Result<FrozenBuildContextV1, BuildContractError> {
        let BuildContextFreezeRequest {
            dockerfile_path,
            dockerfile_contents,
            prefetch,
            base_registry_allowlist,
            mut generated_files,
            declared_generated_paths,
            mut resolved_bases,
        } = request;
        let dockerfile = source
            .file(dockerfile_path)
            .ok_or(BuildContractError::MissingDockerfile)?;
        validate_prefetch_source_binding(source, prefetch)?;
        let dockerfile_bytes = u64::try_from(dockerfile_contents.len())
            .map_err(|_| BuildContractError::SizeOverflow)?;
        if dockerfile.bytes != dockerfile_bytes
            || dockerfile.digest != EvidenceDigest::sha256(dockerfile_contents)
        {
            return Err(BuildContractError::DockerfileEvidenceMismatch);
        }
        let mut required_bases = inspect_repository_dockerfile(dockerfile_contents)?;
        if generated_files.len() > MAX_GENERATED_FILES {
            return Err(BuildContractError::GeneratedFileLimit);
        }
        let declared = declared_generated_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if declared.len() != declared_generated_paths.len() {
            return Err(BuildContractError::DuplicateGeneratedDeclaration);
        }
        generated_files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut generated_total = 0_u64;
        for (index, file) in generated_files.iter().enumerate() {
            if file.bytes > MAX_GENERATED_FILE_BYTES
                || !declared.contains(&file.path)
                || source.file(&file.path).is_some()
                || &file.path == dockerfile_path
                || index > 0 && generated_files[index - 1].path == file.path
            {
                return Err(BuildContractError::GeneratedOutputRejected(
                    file.path.as_str().to_owned(),
                ));
            }
            generated_total = generated_total
                .checked_add(file.bytes)
                .ok_or(BuildContractError::SizeOverflow)?;
        }
        if generated_total > MAX_GENERATED_TOTAL_BYTES {
            return Err(BuildContractError::GeneratedByteLimit);
        }
        if generated_files.len() != declared.len() {
            return Err(BuildContractError::MissingGeneratedOutput);
        }
        resolved_bases.sort_by(|left, right| left.stage.cmp(&right.stage));
        for (index, base) in resolved_bases.iter().enumerate() {
            base.validate(base_registry_allowlist)?;
            if index > 0 && resolved_bases[index - 1].stage == base.stage {
                return Err(BuildContractError::DuplicateBaseStage(base.stage.clone()));
            }
        }
        required_bases.sort();
        if required_bases.len() != resolved_bases.len()
            || required_bases
                .iter()
                .zip(&resolved_bases)
                .any(|(required, resolved)| {
                    required.stage != resolved.stage || required.requested != resolved.requested
                })
        {
            return Err(BuildContractError::ResolvedBaseMismatch);
        }
        let payload = FrozenContextDigestPayload {
            purpose: "rdashboard.frozen-build-context.v1",
            release_identity_digest: source.release_identity().digest(),
            source_export_digest: source.digest(),
            prefetch_evidence_digest: prefetch.digest(),
            dockerfile_path,
            base_registries: base_registry_allowlist.registries(),
            generated_files: &generated_files,
            resolved_bases: &resolved_bases,
            dockerfile_digest: &dockerfile.digest,
        };
        let context_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&payload)?);
        Ok(FrozenBuildContextV1 {
            release_identity: source.release_identity().clone(),
            source_export_digest: source.digest().clone(),
            prefetch_evidence_digest: prefetch.digest().clone(),
            dockerfile_path: dockerfile_path.clone(),
            base_registry_allowlist: base_registry_allowlist.clone(),
            generated_files,
            resolved_bases,
            dockerfile_digest: dockerfile.digest.clone(),
            context_digest,
        })
    }

    pub fn testing_artifacts(
        context: &FrozenBuildContextV1,
        ci: &CiGateEvidenceV1,
        reservation: &ResourceReservationEvidenceV1,
    ) -> Result<PhaseArtifacts, BuildContractError> {
        if ci.context_digest != context.context_digest
            || reservation.operation_digest
                != context.release_identity.executor_authorization_digest
        {
            return Err(BuildContractError::ContextIdentityMismatch);
        }
        Ok(PhaseArtifacts {
            source_export_digest: Some(context.source_export_digest.clone()),
            prefetch_evidence_digest: Some(context.prefetch_evidence_digest.clone()),
            ci_evidence_digest: Some(ci.digest.clone()),
            build_context_digest: Some(context.context_digest.clone()),
            resource_reservation_digest: Some(reservation.reservation_digest.clone()),
            generated_output_digests: context
                .generated_files
                .iter()
                .map(|file| file.digest.clone())
                .collect(),
            base_image_digests: context
                .resolved_bases
                .iter()
                .map(ResolvedBaseV1::evidence_digest)
                .collect::<Result<_, _>>()?,
            ..PhaseArtifacts::default()
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfileV1 {
    DenyAll,
    ArtifactBrokerOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiInvocationV1 {
    FixedBinCi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketExposureV1 {
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityV1 {
    Unchanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiOutcomeV1 {
    Passed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CiIsolationV1 {
    network: NetworkProfileV1,
    production_secrets: SecretExposureV1,
    docker_socket: SocketExposureV1,
    executor_sockets: SocketExposureV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobLimitsV1 {
    pub wall_time_seconds: u32,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub scratch_max_bytes: u64,
    pub cache_max_bytes: u64,
    pub output_max_bytes: u64,
}

impl JobLimitsV1 {
    pub fn validate(self) -> Result<(), BuildContractError> {
        if !(30..=7_200).contains(&self.wall_time_seconds)
            || !(128 * 1024 * 1024..=32 * 1024 * 1024 * 1024).contains(&self.memory_max_bytes)
            || !(8..=4_096).contains(&self.tasks_max)
            || self.scratch_max_bytes == 0
            || self.cache_max_bytes == 0
            || self.output_max_bytes == 0
        {
            return Err(BuildContractError::InvalidJobLimits);
        }
        Ok(())
    }
}

fn validate_prefetch_source_binding(
    source: &ImmutableSourceExportV1,
    prefetch: &PrefetchEvidenceV1,
) -> Result<(), BuildContractError> {
    let current_lockfile = source
        .file(&prefetch.lockfile_path)
        .ok_or(BuildContractError::PrefetchEvidenceMismatch)?;
    if prefetch.source_export_digest == *source.digest()
        && current_lockfile.digest == prefetch.lockfile_digest
    {
        Ok(())
    } else {
        Err(BuildContractError::PrefetchEvidenceMismatch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CiGateEvidenceV1 {
    context_digest: EvidenceDigest,
    limits: JobLimitsV1,
    invocation: CiInvocationV1,
    isolation: CiIsolationV1,
    context_integrity: ContextIntegrityV1,
    outcome: CiOutcomeV1,
    digest: EvidenceDigest,
}

impl CiGateEvidenceV1 {
    pub fn passed(
        context: &FrozenBuildContextV1,
        limits: JobLimitsV1,
    ) -> Result<Self, BuildContractError> {
        limits.validate()?;
        let mut evidence = Self {
            context_digest: context.context_digest.clone(),
            limits,
            invocation: CiInvocationV1::FixedBinCi,
            isolation: CiIsolationV1 {
                network: NetworkProfileV1::DenyAll,
                production_secrets: SecretExposureV1::Absent,
                docker_socket: SocketExposureV1::Absent,
                executor_sockets: SocketExposureV1::Absent,
            },
            context_integrity: ContextIntegrityV1::Unchanged,
            outcome: CiOutcomeV1::Passed,
            digest: EvidenceDigest::sha256([]),
        };
        evidence.digest = EvidenceDigest::sha256(serde_jcs::to_vec(&evidence)?);
        Ok(evidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageBuildEvidenceV1 {
    release_identity_digest: EvidenceDigest,
    context_digest: EvidenceDigest,
    dockerfile_path: BuildPath,
    base_registry_allowlist_digest: EvidenceDigest,
    build_plan_digest: EvidenceDigest,
    source_tag: String,
    registry_digest: OciDigest,
    local_image_id: OciDigest,
    image_archive_digest: EvidenceDigest,
    rootless_buildkit: bool,
    network: NetworkProfileV1,
}

#[derive(Serialize)]
struct ImageBuildPlanDigestPayload<'a> {
    purpose: &'static str,
    release_identity_digest: &'a EvidenceDigest,
    context_digest: &'a EvidenceDigest,
    dockerfile_path: &'a BuildPath,
    base_registry_allowlist_digest: &'a EvidenceDigest,
    source_tag: &'a str,
    image_archive_digest: &'a EvidenceDigest,
    network: NetworkProfileV1,
}

impl ImageBuildEvidenceV1 {
    pub fn rootless(
        context: &FrozenBuildContextV1,
        registry_digest: OciDigest,
        local_image_id: OciDigest,
        image_archive_digest: EvidenceDigest,
    ) -> Result<Self, BuildContractError> {
        let source_tag = context.release_identity.source_head.to_string();
        if !matches!(source_tag.len(), 40 | 64) {
            return Err(BuildContractError::AbbreviatedImageTag);
        }
        let build_plan_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&ImageBuildPlanDigestPayload {
                purpose: "rdashboard.rootless-buildkit-plan.v1",
                release_identity_digest: context.release_identity.digest(),
                context_digest: &context.context_digest,
                dockerfile_path: &context.dockerfile_path,
                base_registry_allowlist_digest: context.base_registry_allowlist.digest(),
                source_tag: &source_tag,
                image_archive_digest: &image_archive_digest,
                network: NetworkProfileV1::DenyAll,
            })?);
        Ok(Self {
            release_identity_digest: context.release_identity.digest().clone(),
            context_digest: context.context_digest.clone(),
            dockerfile_path: context.dockerfile_path.clone(),
            base_registry_allowlist_digest: context.base_registry_allowlist.digest().clone(),
            build_plan_digest,
            source_tag,
            registry_digest,
            local_image_id,
            image_archive_digest,
            rootless_buildkit: true,
            network: NetworkProfileV1::DenyAll,
        })
    }

    pub fn phase_artifacts(
        &self,
        context: &FrozenBuildContextV1,
    ) -> Result<PhaseArtifacts, BuildContractError> {
        self.validate_for_context(context)?;
        Ok(PhaseArtifacts {
            build_context_digest: Some(context.context_digest.clone()),
            build_plan_digest: Some(self.build_plan_digest.clone()),
            image_digest: Some(EvidenceDigest::sha256(self.registry_digest.as_str())),
            image_id_digest: Some(EvidenceDigest::sha256(self.local_image_id.as_str())),
            base_image_digests: context
                .resolved_bases
                .iter()
                .map(ResolvedBaseV1::evidence_digest)
                .collect::<Result<_, _>>()?,
            ..PhaseArtifacts::default()
        })
    }

    fn validate_for_context(
        &self,
        context: &FrozenBuildContextV1,
    ) -> Result<(), BuildContractError> {
        let expected = Self::rootless(
            context,
            self.registry_digest.clone(),
            self.local_image_id.clone(),
            self.image_archive_digest.clone(),
        )?;
        if *self == expected {
            Ok(())
        } else {
            Err(BuildContractError::ContextIdentityMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReservationEvidenceV1 {
    operation_digest: EvidenceDigest,
    required_bytes: u64,
    available_bytes: u64,
    emergency_reserve_bytes: u64,
    filesystem_identity: EvidenceDigest,
    observed_at_ms: i64,
    reservation_digest: EvidenceDigest,
}

impl ResourceReservationEvidenceV1 {
    pub fn reserve(
        operation_digest: EvidenceDigest,
        reservation: DiskReservation,
    ) -> Result<Self, BuildContractError> {
        reservation.evaluate()?;
        let required_bytes = reservation
            .required_bytes()
            .ok_or(BuildContractError::Disk(
                DiskReservationError::CalculationOverflow,
            ))?;
        let reservation_digest = AuthorizedDiskReservation::calculate_reservation_digest(
            &operation_digest,
            required_bytes,
            reservation.filesystem_available_bytes,
            reservation.emergency_reserve_bytes(),
            &reservation.filesystem_identity,
            reservation.observed_at_ms,
        )?;
        Ok(Self {
            operation_digest,
            required_bytes,
            available_bytes: reservation.filesystem_available_bytes,
            emergency_reserve_bytes: reservation.emergency_reserve_bytes(),
            filesystem_identity: reservation.filesystem_identity,
            observed_at_ms: reservation.observed_at_ms,
            reservation_digest,
        })
    }

    pub fn phase_artifacts(&self) -> PhaseArtifacts {
        PhaseArtifacts {
            resource_reservation_digest: Some(self.reservation_digest.clone()),
            ..PhaseArtifacts::default()
        }
    }

    pub fn authorization(&self) -> AuthorizedDiskReservation {
        AuthorizedDiskReservation {
            operation_digest: self.operation_digest.clone(),
            reservation_digest: self.reservation_digest.clone(),
            required_bytes: self.required_bytes,
            available_bytes: self.available_bytes,
            emergency_reserve_bytes: self.emergency_reserve_bytes,
            filesystem_identity: self.filesystem_identity.clone(),
            observed_at_ms: self.observed_at_ms,
        }
    }

    fn validate(&self) -> Result<(), BuildContractError> {
        if self.required_bytes == 0
            || self.emergency_reserve_bytes == 0
            || self.emergency_reserve_bytes >= self.required_bytes
            || self.available_bytes < self.required_bytes
            || self.observed_at_ms < 0
            || !self.authorization().has_valid_reservation_digest()?
        {
            Err(BuildContractError::InvalidResourceReservationEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalServiceName(String);

impl KamalServiceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalServiceName {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_kamal_name(value, 63) {
            return Err(BuildContractError::InvalidKamalName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalImageName(String);

impl KamalImageName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalImageName {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 200
            || value.starts_with(['.', '-', '/'])
            || value.ends_with(['.', '-', '/'])
            || value.contains("//")
            || value.bytes().any(|byte| {
                !(byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/'))
            })
        {
            return Err(BuildContractError::InvalidKamalName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalSshUser(String);

impl KamalSshUser {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalSshUser {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = value.bytes();
        if value.is_empty()
            || value.len() > 32
            || !bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(BuildContractError::InvalidKamalName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalNetworkName(String);

impl KamalNetworkName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalNetworkName {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_kamal_name(value, 63) {
            return Err(BuildContractError::InvalidKamalName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalTargetHost(String);

impl KamalTargetHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalTargetHost {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 253
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-'))
        {
            return Err(BuildContractError::InvalidKamalHost(value.to_owned()));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalEnvironmentKey(String);

impl KamalEnvironmentKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalEnvironmentKey {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_environment_key(value) {
            return Err(BuildContractError::InvalidEnvironmentKey(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalSecretName(String);

impl KamalSecretName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalSecretName {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_environment_key(value) {
            return Err(BuildContractError::InvalidSecretName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalHostPath(String);

impl KamalHostPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl FromStr for KamalHostPath {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_absolute_policy_path(value)?;
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalContainerPath(String);

impl KamalContainerPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalContainerPath {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_absolute_policy_path(value)?;
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalMountAccessV1 {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalMountV1 {
    pub host_path: KamalHostPath,
    pub container_path: KamalContainerPath,
    pub access: KamalMountAccessV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalPortProtocolV1 {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalPortBindingV1 {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: KamalPortProtocolV1,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalNetworkAlias(String);

impl KamalNetworkAlias {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalNetworkAlias {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_kamal_name(value, 63) {
            return Err(BuildContractError::InvalidKamalName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KamalEnvironmentValue(String);

impl KamalEnvironmentValue {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KamalEnvironmentValue {
    type Err = BuildContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 1024
            || value
                .bytes()
                .any(|byte| byte == 0 || (byte.is_ascii_control() && byte != b'\t'))
        {
            return Err(BuildContractError::InvalidEnvironmentValue);
        }
        Ok(Self(value.to_owned()))
    }
}

macro_rules! deserialize_kamal_string {
    ($($type:ty),+ $(,)?) => {
        $(
            impl<'de> Deserialize<'de> for $type {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    let value = String::deserialize(deserializer)?;
                    Self::from_str(&value).map_err(D::Error::custom)
                }
            }
        )+
    };
}

deserialize_kamal_string!(
    KamalServiceName,
    KamalImageName,
    KamalSshUser,
    KamalNetworkName,
    KamalTargetHost,
    KamalEnvironmentKey,
    KamalSecretName,
    KamalHostPath,
    KamalContainerPath,
    KamalNetworkAlias,
    KamalEnvironmentValue,
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalUnixIdentityV1 {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalClearEnvironmentV1 {
    pub key: KamalEnvironmentKey,
    pub value: KamalEnvironmentValue,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalSecretBindingV1 {
    pub environment_key: KamalEnvironmentKey,
    pub secret_name: KamalSecretName,
    pub credential_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalLoggingDriverV1 {
    Local,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalLoggingPolicyV1 {
    pub driver: KamalLoggingDriverV1,
    pub max_size_bytes: u64,
    pub max_files: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledKamalPolicyInputV1 {
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub service: KamalServiceName,
    pub image: KamalImageName,
    pub target_host: KamalTargetHost,
    pub ssh_user: KamalSshUser,
    pub ssh_port: u16,
    pub network: KamalNetworkName,
    pub network_alias: KamalNetworkAlias,
    pub run_as: KamalUnixIdentityV1,
    pub allowed_host_roots: Vec<KamalHostPath>,
    pub mounts: Vec<KamalMountV1>,
    pub ports: Vec<KamalPortBindingV1>,
    pub clear_environment: Vec<KamalClearEnvironmentV1>,
    pub secret_bindings: Vec<KamalSecretBindingV1>,
    pub logging: KamalLoggingPolicyV1,
    pub template_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledKamalPolicyV1 {
    project_id: ProjectId,
    installed_policy: InstalledPolicyIdentity,
    service: KamalServiceName,
    image: KamalImageName,
    target_host: KamalTargetHost,
    ssh_user: KamalSshUser,
    ssh_port: u16,
    network: KamalNetworkName,
    network_alias: KamalNetworkAlias,
    run_as: KamalUnixIdentityV1,
    allowed_host_roots: Vec<KamalHostPath>,
    mounts: Vec<KamalMountV1>,
    ports: Vec<KamalPortBindingV1>,
    clear_environment: Vec<KamalClearEnvironmentV1>,
    secret_bindings: Vec<KamalSecretBindingV1>,
    credential_versions_digest: EvidenceDigest,
    logging: KamalLoggingPolicyV1,
    template_digest: EvidenceDigest,
    policy_digest: EvidenceDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledKamalPolicyWireV1 {
    project_id: ProjectId,
    installed_policy: InstalledPolicyIdentity,
    service: KamalServiceName,
    image: KamalImageName,
    target_host: KamalTargetHost,
    ssh_user: KamalSshUser,
    ssh_port: u16,
    network: KamalNetworkName,
    network_alias: KamalNetworkAlias,
    run_as: KamalUnixIdentityV1,
    allowed_host_roots: Vec<KamalHostPath>,
    mounts: Vec<KamalMountV1>,
    ports: Vec<KamalPortBindingV1>,
    clear_environment: Vec<KamalClearEnvironmentV1>,
    secret_bindings: Vec<KamalSecretBindingV1>,
    credential_versions_digest: EvidenceDigest,
    logging: KamalLoggingPolicyV1,
    template_digest: EvidenceDigest,
    policy_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct InstalledKamalPolicyDigestPayload<'a> {
    purpose: &'static str,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    service: &'a KamalServiceName,
    image: &'a KamalImageName,
    target_host: &'a KamalTargetHost,
    ssh_user: &'a KamalSshUser,
    ssh_port: u16,
    network: &'a KamalNetworkName,
    network_alias: &'a KamalNetworkAlias,
    run_as: KamalUnixIdentityV1,
    allowed_host_roots: &'a [KamalHostPath],
    mounts: &'a [KamalMountV1],
    ports: &'a [KamalPortBindingV1],
    clear_environment: &'a [KamalClearEnvironmentV1],
    secret_bindings: &'a [KamalSecretBindingV1],
    credential_versions_digest: &'a EvidenceDigest,
    logging: KamalLoggingPolicyV1,
    template_digest: &'a EvidenceDigest,
}

impl<'de> Deserialize<'de> for InstalledKamalPolicyV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = InstalledKamalPolicyWireV1::deserialize(deserializer)?;
        let credential_versions_digest = wire.credential_versions_digest.clone();
        let policy_digest = wire.policy_digest.clone();
        let policy = Self::new(InstalledKamalPolicyInputV1 {
            project_id: wire.project_id,
            installed_policy: wire.installed_policy,
            service: wire.service,
            image: wire.image,
            target_host: wire.target_host,
            ssh_user: wire.ssh_user,
            ssh_port: wire.ssh_port,
            network: wire.network,
            network_alias: wire.network_alias,
            run_as: wire.run_as,
            allowed_host_roots: wire.allowed_host_roots,
            mounts: wire.mounts,
            ports: wire.ports,
            clear_environment: wire.clear_environment,
            secret_bindings: wire.secret_bindings,
            logging: wire.logging,
            template_digest: wire.template_digest,
        })
        .map_err(D::Error::custom)?;
        if policy.credential_versions_digest != credential_versions_digest
            || policy.policy_digest != policy_digest
        {
            return Err(D::Error::custom(
                "installed Kamal policy derived digest mismatch",
            ));
        }
        Ok(policy)
    }
}

impl InstalledKamalPolicyV1 {
    pub fn new(mut input: InstalledKamalPolicyInputV1) -> Result<Self, BuildContractError> {
        if input.allowed_host_roots.is_empty() {
            return Err(BuildContractError::HostRootAllowlistEmpty);
        }
        if input.network.as_str() != FIXED_KAMAL_NETWORK_NAME {
            return Err(BuildContractError::InvalidKamalNetwork);
        }
        if input.ssh_port == 0 {
            return Err(BuildContractError::InvalidKamalPort);
        }
        sort_unique(&mut input.allowed_host_roots, "allowed_host_roots")?;
        sort_unique(&mut input.mounts, "mounts")?;
        sort_unique(&mut input.ports, "ports")?;
        sort_unique(&mut input.clear_environment, "clear_environment")?;
        sort_unique(&mut input.secret_bindings, "secret_bindings")?;
        validate_runtime_identity_and_logging(input.run_as, input.logging)?;
        let clear_keys = input
            .clear_environment
            .iter()
            .map(|entry| &entry.key)
            .collect::<BTreeSet<_>>();
        let secret_keys = input
            .secret_bindings
            .iter()
            .map(|entry| &entry.environment_key)
            .collect::<BTreeSet<_>>();
        if clear_keys.len() != input.clear_environment.len()
            || secret_keys.len() != input.secret_bindings.len()
            || !clear_keys.is_disjoint(&secret_keys)
            || input
                .secret_bindings
                .iter()
                .any(|binding| binding.credential_version == 0)
        {
            return Err(BuildContractError::InvalidEnvironmentBinding);
        }
        let mount_targets = input
            .mounts
            .iter()
            .map(|mount| &mount.container_path)
            .collect::<BTreeSet<_>>();
        if mount_targets.len() != input.mounts.len() {
            return Err(BuildContractError::DuplicateKamalField(
                "mount_container_path",
            ));
        }
        let host_ports = input
            .ports
            .iter()
            .map(|port| (port.host_port, port.protocol))
            .collect::<BTreeSet<_>>();
        if host_ports.len() != input.ports.len() {
            return Err(BuildContractError::DuplicateKamalField("host_port"));
        }
        if input.ports.iter().any(|port| {
            port.host_port == 0
                || port.container_port == 0
                || port.host_port == 5555
                || port.container_port == 5555
        }) {
            return Err(BuildContractError::InvalidKamalPort);
        }
        if input.mounts.iter().any(|mount| {
            !input
                .allowed_host_roots
                .iter()
                .any(|root| mount.host_path.path().starts_with(root.path()))
        }) {
            return Err(BuildContractError::HostPathNotAllowlisted);
        }
        let credential_versions_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&input.secret_bindings)?);
        let mut policy = Self {
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            service: input.service,
            image: input.image,
            target_host: input.target_host,
            ssh_user: input.ssh_user,
            ssh_port: input.ssh_port,
            network: input.network,
            network_alias: input.network_alias,
            run_as: input.run_as,
            allowed_host_roots: input.allowed_host_roots,
            mounts: input.mounts,
            ports: input.ports,
            clear_environment: input.clear_environment,
            secret_bindings: input.secret_bindings,
            credential_versions_digest,
            logging: input.logging,
            template_digest: input.template_digest,
            policy_digest: EvidenceDigest::sha256([]),
        };
        policy.policy_digest = policy.calculate_digest()?;
        Ok(policy)
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.policy_digest
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn installed_policy(&self) -> &InstalledPolicyIdentity {
        &self.installed_policy
    }

    pub const fn credential_versions_digest(&self) -> &EvidenceDigest {
        &self.credential_versions_digest
    }

    pub fn has_valid_digest(&self) -> Result<bool, BuildContractError> {
        Ok(self.policy_digest == self.calculate_digest()?)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BuildContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledKamalPolicyDigestPayload {
                purpose: "rdashboard.installed-kamal-policy.v1",
                project_id: &self.project_id,
                installed_policy: &self.installed_policy,
                service: &self.service,
                image: &self.image,
                target_host: &self.target_host,
                ssh_user: &self.ssh_user,
                ssh_port: self.ssh_port,
                network: &self.network,
                network_alias: &self.network_alias,
                run_as: self.run_as,
                allowed_host_roots: &self.allowed_host_roots,
                mounts: &self.mounts,
                ports: &self.ports,
                clear_environment: &self.clear_environment,
                secret_bindings: &self.secret_bindings,
                credential_versions_digest: &self.credential_versions_digest,
                logging: self.logging,
                template_digest: &self.template_digest,
            },
        )?))
    }
}

fn validate_runtime_identity_and_logging(
    run_as: KamalUnixIdentityV1,
    logging: KamalLoggingPolicyV1,
) -> Result<(), BuildContractError> {
    if run_as.uid == 0 || run_as.gid == 0 || run_as.uid == u32::MAX || run_as.gid == u32::MAX {
        return Err(BuildContractError::InvalidRuntimeIdentity);
    }
    let log_budget = logging
        .max_size_bytes
        .checked_mul(u64::from(logging.max_files))
        .ok_or(BuildContractError::InvalidLoggingPolicy)?;
    if logging.max_size_bytes == 0 || logging.max_files == 0 || log_budget > 256 * 1024 * 1024 {
        return Err(BuildContractError::InvalidLoggingPolicy);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRepositoryConfigurationV1 {
    Ignored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalHookPolicyV1 {
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalTemplateEvaluationV1 {
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalRegistryTransportV1 {
    LoopbackPort5555,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalDeploymentPlanV1 {
    project_id: ProjectId,
    source_head: GitCommitId,
    release_identity_digest: EvidenceDigest,
    installed_policy: InstalledPolicyIdentity,
    context_digest: EvidenceDigest,
    image_registry_digest: OciDigest,
    service: KamalServiceName,
    image: KamalImageName,
    target_host: KamalTargetHost,
    ssh_user: KamalSshUser,
    ssh_port: u16,
    network: KamalNetworkName,
    network_alias: KamalNetworkAlias,
    run_as: KamalUnixIdentityV1,
    mounts: Vec<KamalMountV1>,
    ports: Vec<KamalPortBindingV1>,
    clear_environment: Vec<KamalClearEnvironmentV1>,
    secret_bindings: Vec<KamalSecretBindingV1>,
    credential_versions_digest: EvidenceDigest,
    logging: KamalLoggingPolicyV1,
    runtime_policy_digest: EvidenceDigest,
    template_digest: EvidenceDigest,
    sanitized_diff_digest: EvidenceDigest,
    repository_configuration: ManagedRepositoryConfigurationV1,
    hooks: KamalHookPolicyV1,
    template_evaluation: KamalTemplateEvaluationV1,
    registry_transport: KamalRegistryTransportV1,
    plan_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct KamalPlanDigestPayload<'a> {
    purpose: &'static str,
    project_id: &'a ProjectId,
    source_head: &'a GitCommitId,
    release_identity_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
    context_digest: &'a EvidenceDigest,
    image_registry_digest: &'a OciDigest,
    service: &'a KamalServiceName,
    image: &'a KamalImageName,
    target_host: &'a KamalTargetHost,
    ssh_user: &'a KamalSshUser,
    ssh_port: u16,
    network: &'a KamalNetworkName,
    network_alias: &'a KamalNetworkAlias,
    run_as: KamalUnixIdentityV1,
    mounts: &'a [KamalMountV1],
    ports: &'a [KamalPortBindingV1],
    clear_environment: &'a [KamalClearEnvironmentV1],
    secret_bindings: &'a [KamalSecretBindingV1],
    credential_versions_digest: &'a EvidenceDigest,
    logging: KamalLoggingPolicyV1,
    runtime_policy_digest: &'a EvidenceDigest,
    template_digest: &'a EvidenceDigest,
    sanitized_diff_digest: &'a EvidenceDigest,
    repository_configuration: ManagedRepositoryConfigurationV1,
    hooks: KamalHookPolicyV1,
    template_evaluation: KamalTemplateEvaluationV1,
    registry_transport: KamalRegistryTransportV1,
}

impl KamalDeploymentPlanV1 {
    pub fn generate(
        policy: &InstalledKamalPolicyV1,
        context: &FrozenBuildContextV1,
        image: &ImageBuildEvidenceV1,
        sanitized_diff_digest: EvidenceDigest,
    ) -> Result<Self, BuildContractError> {
        image.validate_for_context(context)?;
        if policy.project_id != context.release_identity.project_id
            || policy.installed_policy != context.release_identity.installed_policy
        {
            return Err(BuildContractError::ContextIdentityMismatch);
        }
        let credential_versions_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&policy.secret_bindings)?);
        let mut plan = Self {
            project_id: policy.project_id.clone(),
            source_head: context.release_identity.source_head.clone(),
            release_identity_digest: context.release_identity.digest().clone(),
            installed_policy: context.release_identity.installed_policy.clone(),
            context_digest: context.context_digest.clone(),
            image_registry_digest: image.registry_digest.clone(),
            service: policy.service.clone(),
            image: policy.image.clone(),
            target_host: policy.target_host.clone(),
            ssh_user: policy.ssh_user.clone(),
            ssh_port: policy.ssh_port,
            network: policy.network.clone(),
            network_alias: policy.network_alias.clone(),
            run_as: policy.run_as,
            mounts: policy.mounts.clone(),
            ports: policy.ports.clone(),
            clear_environment: policy.clear_environment.clone(),
            secret_bindings: policy.secret_bindings.clone(),
            credential_versions_digest,
            logging: policy.logging,
            runtime_policy_digest: policy.policy_digest.clone(),
            template_digest: policy.template_digest.clone(),
            sanitized_diff_digest,
            repository_configuration: ManagedRepositoryConfigurationV1::Ignored,
            hooks: KamalHookPolicyV1::Disabled,
            template_evaluation: KamalTemplateEvaluationV1::Disabled,
            registry_transport: KamalRegistryTransportV1::LoopbackPort5555,
            plan_digest: EvidenceDigest::sha256([]),
        };
        plan.plan_digest = plan.calculate_digest()?;
        Ok(plan)
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.plan_digest
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn installed_policy(&self) -> &InstalledPolicyIdentity {
        &self.installed_policy
    }

    pub fn has_valid_digest(&self) -> Result<bool, BuildContractError> {
        Ok(self.plan_digest == self.calculate_digest()?)
    }

    pub const fn source_head(&self) -> &GitCommitId {
        &self.source_head
    }

    pub const fn image_registry_digest(&self) -> &OciDigest {
        &self.image_registry_digest
    }

    pub const fn service(&self) -> &KamalServiceName {
        &self.service
    }

    pub const fn image(&self) -> &KamalImageName {
        &self.image
    }

    pub const fn target_host(&self) -> &KamalTargetHost {
        &self.target_host
    }

    pub const fn ssh_user(&self) -> &KamalSshUser {
        &self.ssh_user
    }

    pub const fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    pub const fn network(&self) -> &KamalNetworkName {
        &self.network
    }

    pub const fn network_alias(&self) -> &KamalNetworkAlias {
        &self.network_alias
    }

    pub const fn run_as(&self) -> KamalUnixIdentityV1 {
        self.run_as
    }

    pub fn mounts(&self) -> &[KamalMountV1] {
        &self.mounts
    }

    pub fn ports(&self) -> &[KamalPortBindingV1] {
        &self.ports
    }

    pub fn clear_environment(&self) -> &[KamalClearEnvironmentV1] {
        &self.clear_environment
    }

    pub fn secret_bindings(&self) -> &[KamalSecretBindingV1] {
        &self.secret_bindings
    }

    pub const fn credential_versions_digest(&self) -> &EvidenceDigest {
        &self.credential_versions_digest
    }

    pub const fn logging(&self) -> KamalLoggingPolicyV1 {
        self.logging
    }

    pub const fn runtime_policy_digest(&self) -> &EvidenceDigest {
        &self.runtime_policy_digest
    }

    pub const fn template_digest(&self) -> &EvidenceDigest {
        &self.template_digest
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BuildContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &KamalPlanDigestPayload {
                purpose: "rdashboard.kamal-deployment-plan.v1",
                project_id: &self.project_id,
                source_head: &self.source_head,
                release_identity_digest: &self.release_identity_digest,
                installed_policy: &self.installed_policy,
                context_digest: &self.context_digest,
                image_registry_digest: &self.image_registry_digest,
                service: &self.service,
                image: &self.image,
                target_host: &self.target_host,
                ssh_user: &self.ssh_user,
                ssh_port: self.ssh_port,
                network: &self.network,
                network_alias: &self.network_alias,
                run_as: self.run_as,
                mounts: &self.mounts,
                ports: &self.ports,
                clear_environment: &self.clear_environment,
                secret_bindings: &self.secret_bindings,
                credential_versions_digest: &self.credential_versions_digest,
                logging: self.logging,
                runtime_policy_digest: &self.runtime_policy_digest,
                template_digest: &self.template_digest,
                sanitized_diff_digest: &self.sanitized_diff_digest,
                repository_configuration: self.repository_configuration,
                hooks: self.hooks,
                template_evaluation: self.template_evaluation,
                registry_transport: self.registry_transport,
            },
        )?))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseRollbackContractV1 {
    BootstrapUnavailable,
    CodeOnlyCompatible,
    BidirectionalStateful,
    StatefulBreakingNoAutomatic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRuntimeContractV1 {
    pub application_schema_version: String,
    pub rollback: ReleaseRollbackContractV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBundleV1 {
    schema_version: u32,
    project_id: ProjectId,
    release_identity_digest: EvidenceDigest,
    source_export_digest: EvidenceDigest,
    prefetch_evidence_digest: EvidenceDigest,
    ci_evidence_digest: EvidenceDigest,
    build_context_digest: EvidenceDigest,
    resource_reservation_digest: EvidenceDigest,
    build_plan_digest: EvidenceDigest,
    image_registry_digest: OciDigest,
    local_image_id: OciDigest,
    image_archive_digest: EvidenceDigest,
    deployment_plan: KamalDeploymentPlanV1,
    runtime_policy_digest: EvidenceDigest,
    credential_versions_digest: EvidenceDigest,
    application_schema_version: String,
    rollback: ReleaseRollbackContractV1,
    bundle_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ReleaseBundleDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u32,
    project_id: &'a ProjectId,
    release_identity_digest: &'a EvidenceDigest,
    source_export_digest: &'a EvidenceDigest,
    prefetch_evidence_digest: &'a EvidenceDigest,
    ci_evidence_digest: &'a EvidenceDigest,
    build_context_digest: &'a EvidenceDigest,
    resource_reservation_digest: &'a EvidenceDigest,
    build_plan_digest: &'a EvidenceDigest,
    image_registry_digest: &'a OciDigest,
    local_image_id: &'a OciDigest,
    image_archive_digest: &'a EvidenceDigest,
    deployment_plan: &'a KamalDeploymentPlanV1,
    runtime_policy_digest: &'a EvidenceDigest,
    credential_versions_digest: &'a EvidenceDigest,
    application_schema_version: &'a str,
    rollback: ReleaseRollbackContractV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBundleDocumentV1 {
    schema_version: u32,
    project_id: ProjectId,
    release_identity_digest: EvidenceDigest,
    source_export_digest: EvidenceDigest,
    prefetch_evidence_digest: EvidenceDigest,
    ci_evidence_digest: EvidenceDigest,
    build_context_digest: EvidenceDigest,
    resource_reservation_digest: EvidenceDigest,
    build_plan_digest: EvidenceDigest,
    image_registry_digest: OciDigest,
    local_image_id: OciDigest,
    image_archive_digest: EvidenceDigest,
    deployment_plan: KamalDeploymentPlanV1,
    runtime_policy_digest: EvidenceDigest,
    credential_versions_digest: EvidenceDigest,
    application_schema_version: String,
    rollback: ReleaseRollbackContractV1,
    bundle_digest: EvidenceDigest,
}

impl ReleaseBundleV1 {
    pub fn seal(
        context: &FrozenBuildContextV1,
        ci: &CiGateEvidenceV1,
        reservation: &ResourceReservationEvidenceV1,
        image: &ImageBuildEvidenceV1,
        plan: &KamalDeploymentPlanV1,
        runtime: ReleaseRuntimeContractV1,
    ) -> Result<Self, BuildContractError> {
        let identity = &context.release_identity;
        reservation.validate()?;
        image.validate_for_context(context)?;
        if ci.context_digest != context.context_digest
            || reservation.operation_digest != identity.executor_authorization_digest
            || plan.release_identity_digest != *identity.digest()
            || plan.installed_policy != identity.installed_policy
            || plan.context_digest != context.context_digest
            || plan.image_registry_digest != image.registry_digest
            || !plan.has_valid_digest()?
        {
            return Err(BuildContractError::ContextIdentityMismatch);
        }
        if !valid_application_schema_version(&runtime.application_schema_version) {
            return Err(BuildContractError::InvalidReleaseRuntime);
        }
        let payload = ReleaseBundleDigestPayload {
            purpose: "rdashboard.release-bundle.v1",
            schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
            project_id: &identity.project_id,
            release_identity_digest: identity.digest(),
            source_export_digest: &context.source_export_digest,
            prefetch_evidence_digest: &context.prefetch_evidence_digest,
            ci_evidence_digest: &ci.digest,
            build_context_digest: &context.context_digest,
            resource_reservation_digest: &reservation.reservation_digest,
            build_plan_digest: &image.build_plan_digest,
            image_registry_digest: &image.registry_digest,
            local_image_id: &image.local_image_id,
            image_archive_digest: &image.image_archive_digest,
            deployment_plan: plan,
            runtime_policy_digest: &plan.runtime_policy_digest,
            credential_versions_digest: &plan.credential_versions_digest,
            application_schema_version: &runtime.application_schema_version,
            rollback: runtime.rollback,
        };
        let bundle_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&payload)?);
        Ok(Self {
            schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
            project_id: identity.project_id.clone(),
            release_identity_digest: identity.digest().clone(),
            source_export_digest: context.source_export_digest.clone(),
            prefetch_evidence_digest: context.prefetch_evidence_digest.clone(),
            ci_evidence_digest: ci.digest.clone(),
            build_context_digest: context.context_digest.clone(),
            resource_reservation_digest: reservation.reservation_digest.clone(),
            build_plan_digest: image.build_plan_digest.clone(),
            image_registry_digest: image.registry_digest.clone(),
            local_image_id: image.local_image_id.clone(),
            image_archive_digest: image.image_archive_digest.clone(),
            deployment_plan: plan.clone(),
            runtime_policy_digest: plan.runtime_policy_digest.clone(),
            credential_versions_digest: plan.credential_versions_digest.clone(),
            application_schema_version: runtime.application_schema_version,
            rollback: runtime.rollback,
            bundle_digest,
        })
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.bundle_digest
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn application_schema_version(&self) -> &str {
        self.application_schema_version.as_str()
    }

    pub const fn source_export_digest(&self) -> &EvidenceDigest {
        &self.source_export_digest
    }

    pub const fn prefetch_evidence_digest(&self) -> &EvidenceDigest {
        &self.prefetch_evidence_digest
    }

    pub const fn ci_evidence_digest(&self) -> &EvidenceDigest {
        &self.ci_evidence_digest
    }

    pub const fn build_context_digest(&self) -> &EvidenceDigest {
        &self.build_context_digest
    }

    pub const fn resource_reservation_digest(&self) -> &EvidenceDigest {
        &self.resource_reservation_digest
    }

    pub const fn build_plan_digest(&self) -> &EvidenceDigest {
        &self.build_plan_digest
    }

    pub const fn image_registry_digest(&self) -> &OciDigest {
        &self.image_registry_digest
    }

    pub const fn local_image_id(&self) -> &OciDigest {
        &self.local_image_id
    }

    pub const fn image_archive_digest(&self) -> &EvidenceDigest {
        &self.image_archive_digest
    }

    pub const fn deployment_plan_digest(&self) -> &EvidenceDigest {
        self.deployment_plan.digest()
    }

    pub const fn deployment_plan(&self) -> &KamalDeploymentPlanV1 {
        &self.deployment_plan
    }

    pub const fn rollback_contract(&self) -> ReleaseRollbackContractV1 {
        self.rollback
    }

    pub fn encode_canonical_json(&self) -> Result<Vec<u8>, BuildContractError> {
        self.verify()?;
        Ok(serde_jcs::to_vec(&self.document())?)
    }

    pub fn decode_canonical_json(bytes: &[u8]) -> Result<Self, BuildContractError> {
        let document: ReleaseBundleDocumentV1 = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&document)? != bytes {
            return Err(BuildContractError::NonCanonicalReleaseBundle);
        }
        let bundle = Self::from_document(document)?;
        bundle.verify()?;
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<(), BuildContractError> {
        if self.schema_version != RELEASE_BUNDLE_SCHEMA_VERSION {
            return Err(BuildContractError::UnsupportedReleaseBundleSchema(
                self.schema_version,
            ));
        }
        if !valid_application_schema_version(&self.application_schema_version) {
            return Err(BuildContractError::InvalidReleaseRuntime);
        }
        if !self.deployment_plan.has_valid_digest()?
            || self.deployment_plan.project_id != self.project_id
            || self.deployment_plan.runtime_policy_digest != self.runtime_policy_digest
            || self.deployment_plan.credential_versions_digest != self.credential_versions_digest
            || self.deployment_plan.image_registry_digest != self.image_registry_digest
        {
            return Err(BuildContractError::ContextIdentityMismatch);
        }
        if self.bundle_digest != self.calculate_digest()? {
            return Err(BuildContractError::ReleaseBundleDigestMismatch);
        }
        Ok(())
    }

    pub fn phase_artifacts(&self) -> PhaseArtifacts {
        PhaseArtifacts {
            deployment_plan_digest: Some(self.deployment_plan.digest().clone()),
            release_bundle_digest: Some(self.bundle_digest.clone()),
            ..PhaseArtifacts::default()
        }
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BuildContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &ReleaseBundleDigestPayload {
                purpose: "rdashboard.release-bundle.v1",
                schema_version: self.schema_version,
                project_id: &self.project_id,
                release_identity_digest: &self.release_identity_digest,
                source_export_digest: &self.source_export_digest,
                prefetch_evidence_digest: &self.prefetch_evidence_digest,
                ci_evidence_digest: &self.ci_evidence_digest,
                build_context_digest: &self.build_context_digest,
                resource_reservation_digest: &self.resource_reservation_digest,
                build_plan_digest: &self.build_plan_digest,
                image_registry_digest: &self.image_registry_digest,
                local_image_id: &self.local_image_id,
                image_archive_digest: &self.image_archive_digest,
                deployment_plan: &self.deployment_plan,
                runtime_policy_digest: &self.runtime_policy_digest,
                credential_versions_digest: &self.credential_versions_digest,
                application_schema_version: &self.application_schema_version,
                rollback: self.rollback,
            },
        )?))
    }

    fn document(&self) -> ReleaseBundleDocumentV1 {
        ReleaseBundleDocumentV1 {
            schema_version: self.schema_version,
            project_id: self.project_id.clone(),
            release_identity_digest: self.release_identity_digest.clone(),
            source_export_digest: self.source_export_digest.clone(),
            prefetch_evidence_digest: self.prefetch_evidence_digest.clone(),
            ci_evidence_digest: self.ci_evidence_digest.clone(),
            build_context_digest: self.build_context_digest.clone(),
            resource_reservation_digest: self.resource_reservation_digest.clone(),
            build_plan_digest: self.build_plan_digest.clone(),
            image_registry_digest: self.image_registry_digest.clone(),
            local_image_id: self.local_image_id.clone(),
            image_archive_digest: self.image_archive_digest.clone(),
            deployment_plan: self.deployment_plan.clone(),
            runtime_policy_digest: self.runtime_policy_digest.clone(),
            credential_versions_digest: self.credential_versions_digest.clone(),
            application_schema_version: self.application_schema_version.clone(),
            rollback: self.rollback,
            bundle_digest: self.bundle_digest.clone(),
        }
    }

    fn from_document(document: ReleaseBundleDocumentV1) -> Result<Self, BuildContractError> {
        if document.schema_version != RELEASE_BUNDLE_SCHEMA_VERSION {
            return Err(BuildContractError::UnsupportedReleaseBundleSchema(
                document.schema_version,
            ));
        }
        Ok(Self {
            schema_version: document.schema_version,
            project_id: document.project_id,
            release_identity_digest: document.release_identity_digest,
            source_export_digest: document.source_export_digest,
            prefetch_evidence_digest: document.prefetch_evidence_digest,
            ci_evidence_digest: document.ci_evidence_digest,
            build_context_digest: document.build_context_digest,
            resource_reservation_digest: document.resource_reservation_digest,
            build_plan_digest: document.build_plan_digest,
            image_registry_digest: document.image_registry_digest,
            local_image_id: document.local_image_id,
            image_archive_digest: document.image_archive_digest,
            deployment_plan: document.deployment_plan,
            runtime_policy_digest: document.runtime_policy_digest,
            credential_versions_digest: document.credential_versions_digest,
            application_schema_version: document.application_schema_version,
            rollback: document.rollback,
            bundle_digest: document.bundle_digest,
        })
    }
}

fn valid_kamal_name(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_absolute_policy_path(value: &str) -> Result<(), BuildContractError> {
    if value.len() < 2
        || value.len() > 512
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains("//")
        || value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(BuildContractError::InvalidKamalPath(value.to_owned()));
    }
    Ok(())
}

fn sort_unique<T: Ord>(values: &mut [T], field: &'static str) -> Result<(), BuildContractError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BuildContractError::DuplicateKamalField(field));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DockerfileBaseRequirement {
    stage: String,
    requested: String,
}

pub fn validate_repository_dockerfile(contents: &str) -> Result<(), BuildContractError> {
    inspect_repository_dockerfile(contents).map(|_| ())
}

fn inspect_repository_dockerfile(
    contents: &str,
) -> Result<Vec<DockerfileBaseRequirement>, BuildContractError> {
    if contents.len() > MAX_DOCKERFILE_BYTES {
        return Err(BuildContractError::DockerfileRejected("size_limit"));
    }
    if contents
        .bytes()
        .any(|byte| byte != b'\n' && (byte.is_ascii_control() || byte == 0x7f))
    {
        return Err(BuildContractError::DockerfileRejected(
            "noncanonical_whitespace",
        ));
    }
    let mut stages = BTreeSet::new();
    let mut required_bases = Vec::new();
    let mut stage_index = 0_usize;
    for line in dockerfile_logical_lines(contents)? {
        let lowercase = line.to_ascii_lowercase();
        if dockerfile_parser_directive(&lowercase) == Some("syntax") {
            return Err(BuildContractError::DockerfileRejected(
                "repository_syntax_frontend",
            ));
        }
        if dockerfile_parser_directive(&lowercase) == Some("escape") {
            return Err(BuildContractError::DockerfileRejected(
                "unsupported_parser_directive",
            ));
        }
        let Some((instruction, arguments)) = canonical_dockerfile_instruction(&line)? else {
            continue;
        };
        if arguments.contains("<<") {
            return Err(BuildContractError::DockerfileRejected(
                "unsupported_heredoc",
            ));
        }
        match instruction {
            "add" => {
                return Err(BuildContractError::DockerfileRejected("add_not_allowed"));
            }
            "volume" => {
                return Err(BuildContractError::DockerfileRejected("volume_not_allowed"));
            }
            "run" => validate_run_instruction(arguments)?,
            "copy" => validate_copy_instruction(arguments, &stages)?,
            "from" => {
                stage_index = inspect_from_instruction(
                    arguments,
                    &mut stages,
                    &mut required_bases,
                    stage_index,
                )?;
            }
            "arg" | "cmd" | "entrypoint" | "env" | "expose" | "healthcheck" | "label" | "shell"
            | "stopsignal" | "user" | "workdir" => {}
            _ => {
                return Err(BuildContractError::DockerfileRejected(
                    "unsupported_instruction",
                ));
            }
        }
    }
    if stage_index == 0 {
        return Err(BuildContractError::DockerfileRejected("missing_from"));
    }
    Ok(required_bases)
}

fn inspect_from_instruction(
    arguments: &str,
    stages: &mut BTreeSet<String>,
    required_bases: &mut Vec<DockerfileBaseRequirement>,
    stage_index: usize,
) -> Result<usize, BuildContractError> {
    let tokens = arguments
        .split(' ')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if !matches!(tokens.len(), 1 | 3)
        || tokens.first().is_some_and(|token| token.starts_with("--"))
        || tokens.len() == 3 && !tokens[1].eq_ignore_ascii_case("as")
    {
        return Err(BuildContractError::DockerfileRejected("invalid_from"));
    }
    let image = tokens[0];
    if image
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'\'' | b'"'))
    {
        return Err(BuildContractError::DockerfileRejected("noncanonical_from"));
    }
    let alias = tokens.get(2).map(|alias| alias.to_ascii_lowercase());
    if alias
        .as_deref()
        .is_some_and(|alias| !valid_docker_stage(alias))
    {
        return Err(BuildContractError::DockerfileRejected("invalid_stage"));
    }
    let stage = alias.clone().unwrap_or_else(|| stage_index.to_string());
    let normalized_image = image.to_ascii_lowercase();
    if !image.eq_ignore_ascii_case("scratch") && !stages.contains(&normalized_image) {
        if !has_canonical_image_digest(image) {
            return Err(BuildContractError::DockerfileRejected(
                "dynamic_or_unpinned_from",
            ));
        }
        required_bases.push(DockerfileBaseRequirement {
            stage: stage.clone(),
            requested: image.to_owned(),
        });
    }
    if !stages.insert(stage_index.to_string()) {
        return Err(BuildContractError::DockerfileRejected("duplicate_stage"));
    }
    if let Some(alias) = alias
        && (!valid_docker_stage(&alias) || !stages.insert(alias))
    {
        return Err(BuildContractError::DockerfileRejected("duplicate_stage"));
    }
    stage_index
        .checked_add(1)
        .ok_or(BuildContractError::SizeOverflow)
}

fn canonical_dockerfile_instruction(
    line: &str,
) -> Result<Option<(&str, &str)>, BuildContractError> {
    if line.starts_with('#') {
        return Ok(None);
    }
    let Some((instruction, arguments)) = line.split_once(' ') else {
        return Err(BuildContractError::DockerfileRejected(
            "missing_instruction_arguments",
        ));
    };
    if instruction.is_empty() || !instruction.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(BuildContractError::DockerfileRejected(
            "invalid_instruction",
        ));
    }
    let arguments = arguments.trim_start_matches(' ');
    if arguments.is_empty() {
        return Err(BuildContractError::DockerfileRejected(
            "missing_instruction_arguments",
        ));
    }
    Ok(Some((
        match instruction.to_ascii_lowercase().as_str() {
            "add" => "add",
            "arg" => "arg",
            "cmd" => "cmd",
            "copy" => "copy",
            "entrypoint" => "entrypoint",
            "env" => "env",
            "expose" => "expose",
            "from" => "from",
            "healthcheck" => "healthcheck",
            "label" => "label",
            "run" => "run",
            "shell" => "shell",
            "stopsignal" => "stopsignal",
            "user" => "user",
            "volume" => "volume",
            "workdir" => "workdir",
            _ => "unsupported",
        },
        arguments,
    )))
}

fn validate_run_instruction(arguments: &str) -> Result<(), BuildContractError> {
    for flag in canonical_builder_flags(arguments)? {
        let flag = flag.to_ascii_lowercase();
        if flag == "--network=none" {
            continue;
        }
        if flag == "--mount" || flag.starts_with("--mount=") {
            return Err(BuildContractError::DockerfileRejected(
                "repository_run_mount",
            ));
        }
        return Err(BuildContractError::DockerfileRejected(
            "unsupported_run_option",
        ));
    }
    Ok(())
}

fn validate_copy_instruction(
    arguments: &str,
    stages: &BTreeSet<String>,
) -> Result<(), BuildContractError> {
    for flag in canonical_builder_flags(arguments)? {
        if flag.eq_ignore_ascii_case("--from") {
            return Err(BuildContractError::DockerfileRejected(
                "invalid_copy_source",
            ));
        }
        if let Some((name, from)) = flag.split_once('=')
            && name.eq_ignore_ascii_case("--from")
            && (from.is_empty() || !stages.contains(&from.to_ascii_lowercase()))
        {
            return Err(BuildContractError::DockerfileRejected(
                "external_copy_source",
            ));
        }
    }
    Ok(())
}

fn canonical_builder_flags(arguments: &str) -> Result<Vec<&str>, BuildContractError> {
    let mut flags = Vec::new();
    for token in arguments.split(' ').filter(|token| !token.is_empty()) {
        if !token.starts_with("--") {
            break;
        }
        if token
            .bytes()
            .any(|byte| matches!(byte, b'\\' | b'\'' | b'"'))
        {
            return Err(BuildContractError::DockerfileRejected(
                "noncanonical_builder_flag",
            ));
        }
        flags.push(token);
    }
    Ok(flags)
}

fn dockerfile_parser_directive(line: &str) -> Option<&str> {
    let directive = line.strip_prefix('#')?.trim_start();
    let (name, _value) = directive.split_once('=')?;
    Some(name.trim())
}

fn dockerfile_logical_lines(contents: &str) -> Result<Vec<String>, BuildContractError> {
    let mut logical_lines = Vec::new();
    let mut pending = String::new();
    for raw_line in contents.lines() {
        if raw_line.ends_with(' ') {
            return Err(BuildContractError::DockerfileRejected(
                "trailing_whitespace",
            ));
        }
        let line = raw_line.trim();
        if line.starts_with('#') {
            if !pending.is_empty() {
                return Err(BuildContractError::DockerfileRejected(
                    "comment_in_continuation",
                ));
            }
            logical_lines.push(line.to_owned());
            continue;
        }
        if line.is_empty() {
            if !pending.is_empty() {
                return Err(BuildContractError::DockerfileRejected(
                    "empty_continuation_line",
                ));
            }
            continue;
        }
        let continued = line.ends_with('\\');
        if continued
            && line
                .as_bytes()
                .get(line.len().saturating_sub(2))
                .is_none_or(|byte| *byte != b' ')
        {
            return Err(BuildContractError::DockerfileRejected(
                "noncanonical_continuation",
            ));
        }
        let segment = line.strip_suffix('\\').unwrap_or(line).trim_end();
        if !pending.is_empty() && !segment.is_empty() {
            pending.push(' ');
        }
        pending.push_str(segment);
        if !continued {
            let logical = std::mem::take(&mut pending);
            if !logical.is_empty() {
                logical_lines.push(logical);
            }
        }
    }
    if !pending.is_empty() {
        return Err(BuildContractError::DockerfileRejected(
            "dangling_continuation",
        ));
    }
    Ok(logical_lines)
}

#[derive(Debug)]
struct ParsedBaseImageReference {
    registry: BaseRegistryHost,
    manifest: OciDigest,
}

fn parse_base_image_reference(value: &str) -> Result<ParsedBaseImageReference, BuildContractError> {
    let (name_and_tag, manifest) = value
        .rsplit_once('@')
        .ok_or(BuildContractError::InvalidBaseImage)?;
    if name_and_tag.is_empty()
        || name_and_tag.len() > 255
        || name_and_tag.contains('@')
        || name_and_tag.chars().any(char::is_whitespace)
    {
        return Err(BuildContractError::InvalidBaseImage);
    }
    let manifest = OciDigest::from_str(manifest)?;
    let last_slash = name_and_tag.rfind('/');
    let tag_separator = name_and_tag
        .rfind(':')
        .filter(|separator| last_slash.is_none_or(|slash| *separator > slash));
    let repository = if let Some(separator) = tag_separator {
        let tag = &name_and_tag[separator + 1..];
        if !valid_oci_tag(tag) {
            return Err(BuildContractError::InvalidBaseImage);
        }
        &name_and_tag[..separator]
    } else {
        name_and_tag
    };
    let components = repository.split('/').collect::<Vec<_>>();
    let first = components
        .first()
        .copied()
        .ok_or(BuildContractError::InvalidBaseImage)?;
    let has_explicit_registry = first.contains('.') || first.contains(':') || first == "localhost";
    let (registry, repository_components) = if has_explicit_registry {
        if components.len() < 2 || first.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(BuildContractError::InvalidBaseImage);
        }
        (BaseRegistryHost::parse(first)?, &components[1..])
    } else {
        (BaseRegistryHost::parse("docker.io")?, components.as_slice())
    };
    if repository_components.is_empty()
        || repository_components
            .iter()
            .any(|component| !valid_oci_repository_component(component))
    {
        return Err(BuildContractError::InvalidBaseImage);
    }
    Ok(ParsedBaseImageReference { registry, manifest })
}

fn valid_public_registry_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value != "localhost"
        && ![
            ".local",
            ".localhost",
            ".localdomain",
            ".internal",
            ".home",
            ".lan",
        ]
        .iter()
        .any(|suffix| value.ends_with(*suffix))
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_oci_tag(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_oci_repository_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        match bytes[index] {
            b'.' => index += 1,
            b'_' => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                }
            }
            b'-' => {
                while bytes.get(index) == Some(&b'-') {
                    index += 1;
                }
            }
            _ => return false,
        }
        if !bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

fn has_canonical_image_digest(value: &str) -> bool {
    parse_base_image_reference(value).is_ok()
}

fn valid_docker_stage(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[derive(Debug, thiserror::Error)]
pub enum BuildContractError {
    #[error("authorized release identity is incomplete or invalid")]
    InvalidReleaseIdentity,
    #[error("invalid build path {0:?}")]
    InvalidPath(String),
    #[error("duplicate build path {0:?}")]
    DuplicatePath(String),
    #[error("immutable source export file limit was exceeded")]
    SourceFileLimit,
    #[error("immutable source export byte limit was exceeded")]
    SourceByteLimit,
    #[error("build size calculation overflowed")]
    SizeOverflow,
    #[error("reviewed lockfile is missing from the immutable source export")]
    MissingReviewedLockfile,
    #[error("dependency prefetch evidence does not match the immutable source export")]
    PrefetchEvidenceMismatch,
    #[error("artifact registry allowlist must not be empty")]
    RegistryAllowlistEmpty,
    #[error("invalid public registry host {0:?}")]
    InvalidRegistry(String),
    #[error("base-image registry allowlist must not be empty")]
    BaseRegistryAllowlistEmpty,
    #[error("invalid public base-image registry host {0:?}")]
    InvalidBaseRegistry(String),
    #[error("base-image registry {0:?} is not present in the installed allowlist")]
    BaseRegistryNotAllowed(String),
    #[error("OCI digest must be canonical sha256:<64 lowercase hex>")]
    InvalidOciDigest,
    #[error("resolved base image evidence is invalid")]
    InvalidBaseImage,
    #[error("Dockerfile is missing from immutable source export")]
    MissingDockerfile,
    #[error("Dockerfile bytes do not match the immutable source export evidence")]
    DockerfileEvidenceMismatch,
    #[error("generated file count limit was exceeded")]
    GeneratedFileLimit,
    #[error("generated output {0:?} is undeclared, duplicate, or overwrites source")]
    GeneratedOutputRejected(String),
    #[error("generated output declaration is duplicated")]
    DuplicateGeneratedDeclaration,
    #[error("declared generated output is missing")]
    MissingGeneratedOutput,
    #[error("generated output byte limit was exceeded")]
    GeneratedByteLimit,
    #[error("resolved base image evidence does not exactly match Dockerfile FROM instructions")]
    ResolvedBaseMismatch,
    #[error("resolved base stage {0:?} is duplicated")]
    DuplicateBaseStage(String),
    #[error("CI/build context identities do not match")]
    ContextIdentityMismatch,
    #[error("resource reservation evidence is invalid or internally inconsistent")]
    InvalidResourceReservationEvidence,
    #[error("job limits are invalid or outside hard safety bounds")]
    InvalidJobLimits,
    #[error("image tag is not the full immutable source SHA")]
    AbbreviatedImageTag,
    #[error("repository Dockerfile violates offline build policy: {0}")]
    DockerfileRejected(&'static str),
    #[error("invalid Kamal name {0:?}")]
    InvalidKamalName(String),
    #[error("invalid Kamal target host {0:?}")]
    InvalidKamalHost(String),
    #[error("invalid Kamal environment key {0:?}")]
    InvalidEnvironmentKey(String),
    #[error("Kamal clear-environment value is too large or contains a forbidden control byte")]
    InvalidEnvironmentValue,
    #[error("invalid Kamal secret name {0:?}")]
    InvalidSecretName(String),
    #[error("invalid root-owned Kamal path {0:?}")]
    InvalidKamalPath(String),
    #[error("Kamal host-path root allowlist must not be empty")]
    HostRootAllowlistEmpty,
    #[error("Kamal host path is outside the installed root-owned allowlist")]
    HostPathNotAllowlisted,
    #[error("Kamal port mapping is invalid or conflicts with local registry port 5555")]
    InvalidKamalPort,
    #[error("the pilot Kamal runtime requires its fixed managed Docker network")]
    InvalidKamalNetwork,
    #[error("Kamal policy field {0} contains a duplicate")]
    DuplicateKamalField(&'static str),
    #[error("Kamal runtime UID/GID must be non-root ordinary identities")]
    InvalidRuntimeIdentity,
    #[error("Kamal clear and secret environment bindings must be unique, disjoint and versioned")]
    InvalidEnvironmentBinding,
    #[error("Kamal local log rotation must be non-zero and stay within 256 MiB")]
    InvalidLoggingPolicy,
    #[error("release bundle schema version {0} is unsupported")]
    UnsupportedReleaseBundleSchema(u32),
    #[error("release bundle digest does not match its canonical payload")]
    ReleaseBundleDigestMismatch,
    #[error("release runtime schema identity is empty, non-canonical or too large")]
    InvalidReleaseRuntime,
    #[error("release bundle JSON is not in canonical form")]
    NonCanonicalReleaseBundle,
    #[error(transparent)]
    Disk(#[from] DiskReservationError),
    #[error("canonical build evidence encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
}

impl fmt::Display for RegistryHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for BaseRegistryHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_reservation_evidence_rejects_forged_digest_and_impossible_bounds() {
        let operation_digest = EvidenceDigest::sha256("operation");
        let filesystem_identity = EvidenceDigest::sha256("filesystem");
        let reservation_digest = AuthorizedDiskReservation::calculate_reservation_digest(
            &operation_digest,
            100,
            200,
            10,
            &filesystem_identity,
            50,
        )
        .unwrap_or_else(|error| panic!("reservation digest: {error}"));
        let valid = ResourceReservationEvidenceV1 {
            operation_digest,
            required_bytes: 100,
            available_bytes: 200,
            emergency_reserve_bytes: 10,
            filesystem_identity,
            observed_at_ms: 50,
            reservation_digest,
        };
        valid
            .validate()
            .unwrap_or_else(|error| panic!("valid reservation evidence: {error}"));

        let mut forged = valid.clone();
        forged.available_bytes = 99;
        assert!(matches!(
            forged.validate(),
            Err(BuildContractError::InvalidResourceReservationEvidence)
        ));

        let mut forged = valid;
        forged.reservation_digest = EvidenceDigest::sha256("forged reservation");
        assert!(matches!(
            forged.validate(),
            Err(BuildContractError::InvalidResourceReservationEvidence)
        ));
    }
}
