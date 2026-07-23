use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Component, Path, PathBuf},
    str::FromStr as _,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::EvidenceDigest;

pub const TITANIUM_REGISTRY_ROOT: &str = "/var/lib/rdashboard-build/titanium";

const TREE_PURPOSE: &str = "rdashboard.titanium-tree.v1";
const ARTIFACT_PURPOSE: &str = "rdashboard.titanium-artifact.v1";
const ACTION_PURPOSE: &str = "rdashboard.titanium-action.v1";
const ROOT_PURPOSE: &str = "rdashboard.titanium-root.v1";
const AUTHORIZATION_PURPOSE: &str = "rdashboard.titanium-authorization.v1";
const TOOLCHAIN_DESCRIPTOR_PURPOSE: &str = "rdashboard.titanium-toolchain.v1";
const RELEASE_DESCRIPTOR_PURPOSE: &str = "rdashboard.titanium-release.v1";
pub const TITANIUM_TOOLCHAIN_DESCRIPTOR_FILE: &str = ".titanium-toolchain.jcs";
pub const TITANIUM_RELEASE_DESCRIPTOR_FILE: &str = ".titanium-release.jcs";
const SCHEMA_VERSION: u16 = 1;
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TitaniumArtifactKindV1 {
    BuildTool,
    CompilerToolchain,
    RuntimeLibrary,
    RuntimeSupport,
    DependencySnapshot,
    Release,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumReleaseRuntimeArtifactV1 {
    pub mount: String,
    pub artifact_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumToolchainDescriptorV1 {
    purpose: String,
    schema_version: u16,
    pub interface: String,
    pub target: String,
    pub required_executables: Vec<String>,
    pub components: Vec<TitaniumToolchainComponentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumToolchainComponentV1 {
    pub mount: String,
    pub artifact_digest: EvidenceDigest,
}

impl TitaniumToolchainDescriptorV1 {
    pub fn new(
        interface: String,
        target: String,
        required_executables: Vec<String>,
        components: Vec<TitaniumToolchainComponentV1>,
    ) -> Result<Self, TitaniumRegistryError> {
        let value = Self {
            purpose: TOOLCHAIN_DESCRIPTOR_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            interface,
            target,
            required_executables,
            components,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != TOOLCHAIN_DESCRIPTOR_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.interface)
            || !valid_component(&self.target)
            || self.required_executables.is_empty()
            || self.required_executables.len() > 64
            || !strictly_sorted_unique(&self.required_executables)
            || self
                .required_executables
                .iter()
                .any(|executable| !valid_component(executable))
            || !self
                .components
                .windows(2)
                .all(|pair| pair[0].mount < pair[1].mount)
            || self
                .components
                .iter()
                .any(|component| !valid_component(&component.mount))
            || self
                .components
                .iter()
                .map(|component| &component.artifact_digest)
                .collect::<BTreeSet<_>>()
                .len()
                != self.components.len()
        {
            return Err(TitaniumRegistryError::InvalidToolchainDescriptor);
        }
        Ok(())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumReleaseDescriptorV1 {
    purpose: String,
    schema_version: u16,
    pub project_id: String,
    pub interface: String,
    pub target: String,
    pub entrypoint: String,
    pub runtime_contract_digest: EvidenceDigest,
    pub runtime_artifacts: Vec<TitaniumReleaseRuntimeArtifactV1>,
}

impl TitaniumReleaseDescriptorV1 {
    pub fn new(
        project_id: String,
        interface: String,
        target: String,
        entrypoint: String,
        runtime_contract_digest: EvidenceDigest,
        runtime_artifacts: Vec<TitaniumReleaseRuntimeArtifactV1>,
    ) -> Result<Self, TitaniumRegistryError> {
        let value = Self {
            purpose: RELEASE_DESCRIPTOR_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            project_id,
            interface,
            target,
            entrypoint,
            runtime_contract_digest,
            runtime_artifacts,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != RELEASE_DESCRIPTOR_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.project_id)
            || !valid_component(&self.interface)
            || !valid_component(&self.target)
            || !valid_relative_path(&self.entrypoint)
            || !self
                .runtime_artifacts
                .windows(2)
                .all(|pair| pair[0].mount < pair[1].mount)
            || self
                .runtime_artifacts
                .iter()
                .any(|runtime| !valid_component(&runtime.mount))
            || self
                .runtime_artifacts
                .iter()
                .map(|runtime| &runtime.artifact_digest)
                .collect::<BTreeSet<_>>()
                .len()
                != self.runtime_artifacts.len()
        {
            return Err(TitaniumRegistryError::InvalidReleaseDescriptor);
        }
        Ok(())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TitaniumAcquisitionClassV1 {
    VerifiedUpstreamPrebuilt,
    ControlledSourceBuild,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TitaniumRootKindV1 {
    InstalledArtifact,
    InstalledToolchain,
    CandidateRelease,
    CurrentRelease,
    LastKnownGoodRelease,
    ActiveOperation,
    PublicationRecovery,
    WarmAction,
}

impl TitaniumRootKindV1 {
    const ALL: [Self; 8] = [
        Self::InstalledArtifact,
        Self::InstalledToolchain,
        Self::CandidateRelease,
        Self::CurrentRelease,
        Self::LastKnownGoodRelease,
        Self::ActiveOperation,
        Self::PublicationRecovery,
        Self::WarmAction,
    ];

    const fn directory_name(self) -> &'static str {
        match self {
            Self::InstalledArtifact => "installed-artifact",
            Self::InstalledToolchain => "installed-toolchain",
            Self::CandidateRelease => "candidate-release",
            Self::CurrentRelease => "current-release",
            Self::LastKnownGoodRelease => "last-known-good-release",
            Self::ActiveOperation => "active-operation",
            Self::PublicationRecovery => "publication-recovery",
            Self::WarmAction => "warm-action",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TitaniumTreeEntryKindV1 {
    Directory,
    RegularFile,
    SymbolicLink,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TitaniumTreeEntryV1 {
    path_base64url: String,
    entry_kind: TitaniumTreeEntryKindV1,
    mode: u32,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<EvidenceDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_target_base64url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TitaniumTreeManifestV1 {
    purpose: String,
    schema_version: u16,
    tree_digest: EvidenceDigest,
    entries: Vec<TitaniumTreeEntryV1>,
}

#[derive(Serialize)]
struct TitaniumTreePayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    entries: &'a [TitaniumTreeEntryV1],
}

impl TitaniumTreeManifestV1 {
    fn from_directory(path: &Path) -> Result<Self, TitaniumRegistryError> {
        let entries = inspect_tree(path)?;
        let tree_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&TitaniumTreePayload {
            purpose: TREE_PURPOSE,
            schema_version: SCHEMA_VERSION,
            entries: &entries,
        })?);
        Ok(Self {
            purpose: TREE_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            tree_digest,
            entries,
        })
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != TREE_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || self.entries.is_empty()
            || self.entries.len() > MAX_ENTRIES
            || !self
                .entries
                .windows(2)
                .all(|pair| pair[0].path_base64url.as_bytes() < pair[1].path_base64url.as_bytes())
            || self.tree_digest
                != EvidenceDigest::sha256(serde_jcs::to_vec(&TitaniumTreePayload {
                    purpose: TREE_PURPOSE,
                    schema_version: SCHEMA_VERSION,
                    entries: &self.entries,
                })?)
        {
            return Err(TitaniumRegistryError::InvalidTreeManifest);
        }
        for entry in &self.entries {
            validate_tree_entry(entry)?;
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&value)? != bytes {
            return Err(TitaniumRegistryError::NonCanonicalDocument);
        }
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumArtifactManifestV1 {
    purpose: String,
    schema_version: u16,
    pub kind: TitaniumArtifactKindV1,
    pub acquisition: TitaniumAcquisitionClassV1,
    pub target: String,
    pub tree_digest: EvidenceDigest,
    pub dependencies: Vec<EvidenceDigest>,
    pub provenance_digest: EvidenceDigest,
    pub artifact_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TitaniumArtifactSpecV1 {
    pub kind: TitaniumArtifactKindV1,
    pub acquisition: TitaniumAcquisitionClassV1,
    pub target: String,
    pub dependencies: Vec<EvidenceDigest>,
    pub provenance_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct TitaniumArtifactPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    kind: TitaniumArtifactKindV1,
    acquisition: TitaniumAcquisitionClassV1,
    target: &'a str,
    tree_digest: &'a EvidenceDigest,
    dependencies: &'a [EvidenceDigest],
    provenance_digest: &'a EvidenceDigest,
}

impl TitaniumArtifactManifestV1 {
    pub fn new(
        kind: TitaniumArtifactKindV1,
        acquisition: TitaniumAcquisitionClassV1,
        target: String,
        tree_digest: EvidenceDigest,
        dependencies: Vec<EvidenceDigest>,
        provenance_digest: EvidenceDigest,
    ) -> Result<Self, TitaniumRegistryError> {
        let mut value = Self {
            purpose: ARTIFACT_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            kind,
            acquisition,
            target,
            tree_digest,
            dependencies,
            provenance_digest,
            artifact_digest: EvidenceDigest::sha256([]),
        };
        value.artifact_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, TitaniumRegistryError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &TitaniumArtifactPayload {
                purpose: ARTIFACT_PURPOSE,
                schema_version: SCHEMA_VERSION,
                kind: self.kind,
                acquisition: self.acquisition,
                target: &self.target,
                tree_digest: &self.tree_digest,
                dependencies: &self.dependencies,
                provenance_digest: &self.provenance_digest,
            },
        )?))
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != ARTIFACT_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.target)
            || !strictly_sorted_unique(&self.dependencies)
            || self.dependencies.contains(&self.artifact_digest)
            || self.artifact_digest != self.calculate_digest()?
        {
            return Err(TitaniumRegistryError::InvalidArtifactManifest);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumActionKeyMaterialV1 {
    pub recipe_digest: EvidenceDigest,
    pub source_content_digests: Vec<EvidenceDigest>,
    pub dependency_artifacts: Vec<EvidenceDigest>,
    pub toolchain_artifacts: Vec<EvidenceDigest>,
    pub target: String,
    pub cpu_baseline: String,
    pub abi: String,
    pub normalized_environment: BTreeMap<String, String>,
    pub output_contract_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct TitaniumActionKeyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    material: &'a TitaniumActionKeyMaterialV1,
}

impl TitaniumActionKeyMaterialV1 {
    pub fn key(&self) -> Result<EvidenceDigest, TitaniumRegistryError> {
        self.validate()?;
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &TitaniumActionKeyPayload {
                purpose: ACTION_PURPOSE,
                schema_version: SCHEMA_VERSION,
                material: self,
            },
        )?))
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if !valid_component(&self.target)
            || !valid_component(&self.cpu_baseline)
            || !valid_component(&self.abi)
            || !strictly_sorted_unique(&self.source_content_digests)
            || !strictly_sorted_unique(&self.dependency_artifacts)
            || !strictly_sorted_unique(&self.toolchain_artifacts)
            || self.toolchain_artifacts.is_empty()
            || self
                .dependency_artifacts
                .iter()
                .any(|digest| self.toolchain_artifacts.contains(digest))
            || self.normalized_environment.iter().any(|(name, value)| {
                !valid_environment_name(name)
                    || value.len() > 4_096
                    || value.contains('\0')
                    || value.starts_with('/')
            })
        {
            return Err(TitaniumRegistryError::InvalidActionMaterial);
        }
        Ok(())
    }

    fn referenced_artifacts(&self) -> impl Iterator<Item = &EvidenceDigest> {
        self.dependency_artifacts
            .iter()
            .chain(&self.toolchain_artifacts)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumActionRecordV1 {
    purpose: String,
    schema_version: u16,
    pub action_key: EvidenceDigest,
    pub material: TitaniumActionKeyMaterialV1,
    pub output_artifact: EvidenceDigest,
    pub provenance_digest: EvidenceDigest,
    document_digest: EvidenceDigest,
}

impl TitaniumActionRecordV1 {
    pub fn new(
        material: TitaniumActionKeyMaterialV1,
        output_artifact: EvidenceDigest,
        provenance_digest: EvidenceDigest,
    ) -> Result<Self, TitaniumRegistryError> {
        let action_key = material.key()?;
        let mut value = Self {
            purpose: ACTION_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            action_key,
            material,
            output_artifact,
            provenance_digest,
            document_digest: EvidenceDigest::sha256([]),
        };
        value.document_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, TitaniumRegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            purpose: &'static str,
            schema_version: u16,
            action_key: &'a EvidenceDigest,
            material: &'a TitaniumActionKeyMaterialV1,
            output_artifact: &'a EvidenceDigest,
            provenance_digest: &'a EvidenceDigest,
        }
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(&Payload {
            purpose: ACTION_PURPOSE,
            schema_version: SCHEMA_VERSION,
            action_key: &self.action_key,
            material: &self.material,
            output_artifact: &self.output_artifact,
            provenance_digest: &self.provenance_digest,
        })?))
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != ACTION_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || self.action_key != self.material.key()?
            || self.document_digest != self.calculate_digest()?
        {
            return Err(TitaniumRegistryError::InvalidActionRecord);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TitaniumRootTargetV1 {
    Artifact { digest: EvidenceDigest },
    Action { key: EvidenceDigest },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumRootRecordV1 {
    purpose: String,
    schema_version: u16,
    pub kind: TitaniumRootKindV1,
    pub name: String,
    pub targets: Vec<TitaniumRootTargetV1>,
    document_digest: EvidenceDigest,
}

impl TitaniumRootRecordV1 {
    pub fn new(
        kind: TitaniumRootKindV1,
        name: String,
        targets: Vec<TitaniumRootTargetV1>,
    ) -> Result<Self, TitaniumRegistryError> {
        let mut value = Self {
            purpose: ROOT_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            kind,
            name,
            targets,
            document_digest: EvidenceDigest::sha256([]),
        };
        value.document_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, TitaniumRegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            purpose: &'static str,
            schema_version: u16,
            kind: TitaniumRootKindV1,
            name: &'a str,
            targets: &'a [TitaniumRootTargetV1],
        }
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(&Payload {
            purpose: ROOT_PURPOSE,
            schema_version: SCHEMA_VERSION,
            kind: self.kind,
            name: &self.name,
            targets: &self.targets,
        })?))
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != ROOT_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.name)
            || self.targets.is_empty()
            || !strictly_sorted_unique(&self.targets)
            || self.document_digest != self.calculate_digest()?
        {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TitaniumRegistryError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, TitaniumRegistryError> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitaniumAuthorizationV1 {
    purpose: String,
    schema_version: u16,
    pub project_id: String,
    pub workflow_policy_digest: EvidenceDigest,
    pub action_key: EvidenceDigest,
    pub allowed_acquisition: Vec<TitaniumAcquisitionClassV1>,
}

impl TitaniumAuthorizationV1 {
    pub fn new(
        project_id: String,
        workflow_policy_digest: EvidenceDigest,
        action_key: EvidenceDigest,
        allowed_acquisition: Vec<TitaniumAcquisitionClassV1>,
    ) -> Result<Self, TitaniumRegistryError> {
        let value = Self {
            purpose: AUTHORIZATION_PURPOSE.to_owned(),
            schema_version: SCHEMA_VERSION,
            project_id,
            workflow_policy_digest,
            action_key,
            allowed_acquisition,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), TitaniumRegistryError> {
        if self.purpose != AUTHORIZATION_PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_component(&self.project_id)
            || self.allowed_acquisition.is_empty()
            || !strictly_sorted_unique(&self.allowed_acquisition)
        {
            return Err(TitaniumRegistryError::InvalidAuthorization);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TitaniumGcReportV1 {
    pub removed_trees: u64,
    pub removed_artifacts: u64,
    pub removed_actions: u64,
    pub removed_staging_entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TitaniumReleaseActivationV1 {
    pub project_id: String,
    pub candidate_artifact: EvidenceDigest,
    pub previous_current_artifact: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TitaniumReleaseRecoveryV1 {
    pub candidate_artifact: EvidenceDigest,
    pub current_artifact: Option<EvidenceDigest>,
}

#[derive(Clone, Debug)]
pub struct TitaniumRegistryV1 {
    root: PathBuf,
    expected_owner_uid: u32,
}

impl TitaniumRegistryV1 {
    pub fn open_for_owner(
        root: impl Into<PathBuf>,
        expected_owner_uid: u32,
    ) -> Result<Self, TitaniumRegistryError> {
        let registry = Self {
            root: root.into(),
            expected_owner_uid,
        };
        registry.initialize()?;
        Ok(registry)
    }

    pub fn open_existing(
        root: impl Into<PathBuf>,
        expected_owner_uid: u32,
    ) -> Result<Self, TitaniumRegistryError> {
        let registry = Self {
            root: root.into(),
            expected_owner_uid,
        };
        registry.validate_layout()?;
        Ok(registry)
    }

    pub fn installed_artifact(
        &self,
        name: &str,
        expected_kind: TitaniumArtifactKindV1,
        expected_target: &str,
        expected_interface: &str,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let root = self.read_root_unlocked(TitaniumRootKindV1::InstalledToolchain, name)?;
        let [TitaniumRootTargetV1::Artifact { digest }] = root.targets.as_slice() else {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        };
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        if artifact.kind != expected_kind || artifact.target != expected_target {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        if expected_kind == TitaniumArtifactKindV1::CompilerToolchain {
            self.read_toolchain_descriptor_unlocked(&artifact, Some(expected_interface))?;
        }
        Ok(artifact)
    }

    pub fn installed_named_artifact(
        &self,
        name: &str,
        expected_kind: TitaniumArtifactKindV1,
        expected_target: &str,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let root = self.read_root_unlocked(TitaniumRootKindV1::InstalledArtifact, name)?;
        let [TitaniumRootTargetV1::Artifact { digest }] = root.targets.as_slice() else {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        };
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        if artifact.kind != expected_kind || artifact.target != expected_target {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        Ok(artifact)
    }

    #[cfg(test)]
    fn publish_tree_artifact(
        &self,
        source: &Path,
        kind: TitaniumArtifactKindV1,
        acquisition: TitaniumAcquisitionClassV1,
        target: String,
        dependencies: Vec<EvidenceDigest>,
        provenance_digest: EvidenceDigest,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let (manifest, artifact) = prepare_tree_artifact(
            source,
            kind,
            acquisition,
            target,
            dependencies,
            provenance_digest,
        )?;
        let _lock = self.lock_exclusive()?;
        self.publish_artifact_unlocked(source, &manifest, &artifact)?;
        Ok(artifact)
    }

    pub fn publish_rooted_tree_artifact(
        &self,
        source: &Path,
        spec: TitaniumArtifactSpecV1,
        root_kind: TitaniumRootKindV1,
        root_name: String,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        if root_kind != TitaniumRootKindV1::WarmAction {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let (manifest, artifact) = prepare_tree_artifact(
            source,
            spec.kind,
            spec.acquisition,
            spec.target,
            spec.dependencies,
            spec.provenance_digest,
        )?;
        let root = TitaniumRootRecordV1::new(
            root_kind,
            root_name,
            vec![TitaniumRootTargetV1::Artifact {
                digest: artifact.artifact_digest.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        self.publish_artifact_unlocked(source, &manifest, &artifact)?;
        if spec.kind == TitaniumArtifactKindV1::CompilerToolchain {
            self.read_toolchain_descriptor_unlocked(&artifact, None)?;
        }
        self.write_root_unlocked(&root)?;
        Ok(artifact)
    }

    pub fn publish_installed_toolchain(
        &self,
        source: &Path,
        root_name: String,
        acquisition: TitaniumAcquisitionClassV1,
        target: String,
        dependencies: Vec<EvidenceDigest>,
        provenance_digest: EvidenceDigest,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        self.publish_immutable_installed_tree_artifact(
            source,
            TitaniumArtifactSpecV1 {
                kind: TitaniumArtifactKindV1::CompilerToolchain,
                acquisition,
                target,
                dependencies,
                provenance_digest,
            },
            TitaniumRootKindV1::InstalledToolchain,
            root_name,
        )
    }

    pub fn publish_installed_artifact(
        &self,
        source: &Path,
        root_name: String,
        spec: TitaniumArtifactSpecV1,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        if !matches!(
            spec.kind,
            TitaniumArtifactKindV1::BuildTool
                | TitaniumArtifactKindV1::RuntimeLibrary
                | TitaniumArtifactKindV1::RuntimeSupport
        ) {
            return Err(TitaniumRegistryError::InvalidArtifactManifest);
        }
        self.publish_immutable_installed_tree_artifact(
            source,
            spec,
            TitaniumRootKindV1::InstalledArtifact,
            root_name,
        )
    }

    pub fn publish_candidate_release(
        &self,
        source: &Path,
        spec: TitaniumArtifactSpecV1,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        if spec.kind != TitaniumArtifactKindV1::Release {
            return Err(TitaniumRegistryError::InvalidArtifactManifest);
        }
        let (tree, artifact) = prepare_tree_artifact(
            source,
            spec.kind,
            spec.acquisition,
            spec.target,
            spec.dependencies,
            spec.provenance_digest,
        )?;
        let root = TitaniumRootRecordV1::new(
            TitaniumRootKindV1::CandidateRelease,
            artifact.artifact_digest.as_str().to_owned(),
            vec![TitaniumRootTargetV1::Artifact {
                digest: artifact.artifact_digest.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        self.publish_artifact_unlocked(source, &tree, &artifact)?;
        self.read_release_descriptor_unlocked(&artifact)?;
        self.write_candidate_root_unlocked(&root)?;
        Ok(artifact)
    }

    fn publish_immutable_installed_tree_artifact(
        &self,
        source: &Path,
        spec: TitaniumArtifactSpecV1,
        root_kind: TitaniumRootKindV1,
        root_name: String,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        if !matches!(
            root_kind,
            TitaniumRootKindV1::InstalledArtifact | TitaniumRootKindV1::InstalledToolchain
        ) {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let (manifest, artifact) = prepare_tree_artifact(
            source,
            spec.kind,
            spec.acquisition,
            spec.target,
            spec.dependencies,
            spec.provenance_digest,
        )?;
        let root = TitaniumRootRecordV1::new(
            root_kind,
            root_name,
            vec![TitaniumRootTargetV1::Artifact {
                digest: artifact.artifact_digest.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        match self.read_root_unlocked(root.kind, &root.name) {
            Ok(existing) if existing == root => {
                self.read_artifact_closure_unlocked(&artifact.artifact_digest)?;
                return Ok(artifact);
            }
            Ok(_) => return Err(TitaniumRegistryError::InstalledRootConflict),
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.publish_artifact_unlocked(source, &manifest, &artifact)?;
        if artifact.kind == TitaniumArtifactKindV1::CompilerToolchain {
            self.read_toolchain_descriptor_unlocked(&artifact, None)?;
        }
        self.write_root_unlocked(&root)?;
        Ok(artifact)
    }

    pub fn publish_rooted_action(
        &self,
        record: &TitaniumActionRecordV1,
        root_kind: TitaniumRootKindV1,
        root_name: String,
    ) -> Result<(), TitaniumRegistryError> {
        if root_kind != TitaniumRootKindV1::WarmAction {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let root = TitaniumRootRecordV1::new(
            root_kind,
            root_name,
            vec![TitaniumRootTargetV1::Action {
                key: record.action_key.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        self.validate_action_inputs_unlocked(&record.material)?;
        self.read_artifact_closure_unlocked(&record.output_artifact)?;
        publish_immutable_document(
            &self.action_path(&record.action_key),
            &record.canonical_bytes()?,
            self.expected_owner_uid,
        )?;
        self.write_root_unlocked(&root)
    }

    pub fn publish_rooted_tree_action(
        &self,
        source: &Path,
        artifact_spec: TitaniumArtifactSpecV1,
        material: TitaniumActionKeyMaterialV1,
        action_provenance_digest: EvidenceDigest,
        root_kind: TitaniumRootKindV1,
        root_name: String,
    ) -> Result<(TitaniumArtifactManifestV1, TitaniumActionRecordV1), TitaniumRegistryError> {
        if root_kind != TitaniumRootKindV1::WarmAction {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let (tree, artifact) = prepare_tree_artifact(
            source,
            artifact_spec.kind,
            artifact_spec.acquisition,
            artifact_spec.target,
            artifact_spec.dependencies,
            artifact_spec.provenance_digest,
        )?;
        let action = TitaniumActionRecordV1::new(
            material,
            artifact.artifact_digest.clone(),
            action_provenance_digest,
        )?;
        let root = TitaniumRootRecordV1::new(
            root_kind,
            root_name,
            vec![TitaniumRootTargetV1::Action {
                key: action.action_key.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        self.validate_action_inputs_unlocked(&action.material)?;
        self.publish_artifact_unlocked(source, &tree, &artifact)?;
        publish_immutable_document(
            &self.action_path(&action.action_key),
            &action.canonical_bytes()?,
            self.expected_owner_uid,
        )?;
        self.write_root_unlocked(&root)?;
        Ok((artifact, action))
    }

    pub fn publish_candidate_release_action(
        &self,
        source: &Path,
        artifact_spec: TitaniumArtifactSpecV1,
        material: TitaniumActionKeyMaterialV1,
        action_provenance_digest: EvidenceDigest,
    ) -> Result<(TitaniumArtifactManifestV1, TitaniumActionRecordV1), TitaniumRegistryError> {
        if artifact_spec.kind != TitaniumArtifactKindV1::Release {
            return Err(TitaniumRegistryError::InvalidReleaseDescriptor);
        }
        let (tree, artifact) = prepare_tree_artifact(
            source,
            artifact_spec.kind,
            artifact_spec.acquisition,
            artifact_spec.target,
            artifact_spec.dependencies,
            artifact_spec.provenance_digest,
        )?;
        let action = TitaniumActionRecordV1::new(
            material,
            artifact.artifact_digest.clone(),
            action_provenance_digest,
        )?;
        let root = TitaniumRootRecordV1::new(
            TitaniumRootKindV1::CandidateRelease,
            artifact.artifact_digest.as_str().to_owned(),
            vec![TitaniumRootTargetV1::Action {
                key: action.action_key.clone(),
            }],
        )?;
        let _lock = self.lock_exclusive()?;
        self.validate_action_inputs_unlocked(&action.material)?;
        self.publish_artifact_unlocked(source, &tree, &artifact)?;
        self.read_release_descriptor_unlocked(&artifact)?;
        publish_immutable_document(
            &self.action_path(&action.action_key),
            &action.canonical_bytes()?,
            self.expected_owner_uid,
        )?;
        self.write_candidate_root_unlocked(&root)?;
        Ok((artifact, action))
    }

    pub fn resolve_action(
        &self,
        material: &TitaniumActionKeyMaterialV1,
        authorization: &TitaniumAuthorizationV1,
    ) -> Result<Option<TitaniumArtifactManifestV1>, TitaniumRegistryError> {
        authorization.validate()?;
        let key = material.key()?;
        if authorization.action_key != key {
            return Err(TitaniumRegistryError::AuthorizationMismatch);
        }
        let _lock = self.lock_shared()?;
        let path = self.action_path(&key);
        if !path.exists() {
            return Ok(None);
        }
        let record = self.read_action_unlocked(&key)?;
        if record.material != *material {
            return Err(TitaniumRegistryError::ActionConflict);
        }
        self.validate_action_inputs_unlocked(&record.material)?;
        let output = self.read_artifact_closure_unlocked(&record.output_artifact)?;
        if !self.action_acquisition_is_authorized_unlocked(&record, authorization)? {
            return Err(TitaniumRegistryError::AcquisitionDenied);
        }
        Ok(Some(output))
    }

    pub fn set_root(&self, root: &TitaniumRootRecordV1) -> Result<(), TitaniumRegistryError> {
        root.validate()?;
        if root.kind != TitaniumRootKindV1::ActiveOperation {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let _lock = self.lock_exclusive()?;
        self.write_root_unlocked(root)
    }

    pub fn remove_root(
        &self,
        kind: TitaniumRootKindV1,
        name: &str,
    ) -> Result<(), TitaniumRegistryError> {
        if kind != TitaniumRootKindV1::ActiveOperation || !valid_component(name) {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let _lock = self.lock_exclusive()?;
        self.remove_root_unlocked(kind, name)
    }

    pub fn read_root(
        &self,
        kind: TitaniumRootKindV1,
        name: &str,
    ) -> Result<TitaniumRootRecordV1, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        self.read_root_unlocked(kind, name)
    }

    pub fn release_root_artifact(
        &self,
        kind: TitaniumRootKindV1,
        project_id: &str,
    ) -> Result<Option<EvidenceDigest>, TitaniumRegistryError> {
        if !matches!(
            kind,
            TitaniumRootKindV1::CurrentRelease | TitaniumRootKindV1::LastKnownGoodRelease
        ) || !valid_component(project_id)
        {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let _lock = self.lock_shared()?;
        self.read_optional_single_artifact_root_unlocked(kind, project_id)
    }

    pub fn read_artifact_closure(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        self.read_artifact_closure_unlocked(digest)
    }

    fn read_artifact_closure_unlocked(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let root = self.read_artifact_unlocked(digest)?;
        let mut queue = VecDeque::from(root.dependencies.clone());
        let mut visited = BTreeSet::new();
        while let Some(dependency) = queue.pop_front() {
            if !visited.insert(dependency.clone()) {
                continue;
            }
            let manifest = self.read_artifact_unlocked(&dependency)?;
            queue.extend(manifest.dependencies);
        }
        Ok(root)
    }

    fn action_acquisition_is_authorized_unlocked(
        &self,
        record: &TitaniumActionRecordV1,
        authorization: &TitaniumAuthorizationV1,
    ) -> Result<bool, TitaniumRegistryError> {
        let mut pending = VecDeque::from([record.output_artifact.clone()]);
        pending.extend(record.material.referenced_artifacts().cloned());
        let mut visited = BTreeSet::new();
        while let Some(digest) = pending.pop_front() {
            if !visited.insert(digest.clone()) {
                continue;
            }
            let artifact = self.read_artifact_unlocked(&digest)?;
            if !authorization
                .allowed_acquisition
                .contains(&artifact.acquisition)
            {
                return Ok(false);
            }
            pending.extend(artifact.dependencies);
        }
        Ok(true)
    }

    fn validate_action_inputs_unlocked(
        &self,
        material: &TitaniumActionKeyMaterialV1,
    ) -> Result<(), TitaniumRegistryError> {
        for digest in &material.dependency_artifacts {
            let artifact = self.read_artifact_closure_unlocked(digest)?;
            if artifact.kind != TitaniumArtifactKindV1::DependencySnapshot {
                return Err(TitaniumRegistryError::InvalidActionMaterial);
            }
        }
        for digest in &material.toolchain_artifacts {
            let artifact = self.read_artifact_closure_unlocked(digest)?;
            if !matches!(
                artifact.kind,
                TitaniumArtifactKindV1::CompilerToolchain
                    | TitaniumArtifactKindV1::BuildTool
                    | TitaniumArtifactKindV1::RuntimeLibrary
                    | TitaniumArtifactKindV1::RuntimeSupport
            ) {
                return Err(TitaniumRegistryError::InvalidActionMaterial);
            }
        }
        Ok(())
    }

    pub fn artifact_payload_path(
        &self,
        digest: &EvidenceDigest,
        expected_kind: TitaniumArtifactKindV1,
    ) -> Result<PathBuf, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        if artifact.kind != expected_kind {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        if expected_kind == TitaniumArtifactKindV1::CompilerToolchain {
            self.read_toolchain_descriptor_unlocked(&artifact, None)?;
        }
        Ok(self
            .root
            .join("trees")
            .join(artifact.tree_digest.as_str())
            .join("payload"))
    }

    pub fn toolchain_component_payloads(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<Vec<(String, PathBuf)>, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        if artifact.kind != TitaniumArtifactKindV1::CompilerToolchain {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        let descriptor = self.read_toolchain_descriptor_unlocked(&artifact, None)?;
        descriptor
            .components
            .into_iter()
            .map(|component| {
                let dependency = self.read_artifact_unlocked(&component.artifact_digest)?;
                if !matches!(
                    dependency.kind,
                    TitaniumArtifactKindV1::BuildTool
                        | TitaniumArtifactKindV1::RuntimeLibrary
                        | TitaniumArtifactKindV1::RuntimeSupport
                ) {
                    return Err(TitaniumRegistryError::InvalidToolchainDescriptor);
                }
                Ok((
                    component.mount,
                    self.root
                        .join("trees")
                        .join(dependency.tree_digest.as_str())
                        .join("payload"),
                ))
            })
            .collect()
    }

    pub fn release_descriptor(
        &self,
        digest: &EvidenceDigest,
        expected_project_id: &str,
        expected_target: &str,
        expected_interface: &str,
    ) -> Result<TitaniumReleaseDescriptorV1, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        let descriptor = self.read_release_descriptor_unlocked(&artifact)?;
        if descriptor.project_id != expected_project_id
            || descriptor.target != expected_target
            || descriptor.interface != expected_interface
        {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        Ok(descriptor)
    }

    pub fn release_runtime_payloads(
        &self,
        digest: &EvidenceDigest,
        expected_project_id: &str,
        expected_target: &str,
        expected_interface: &str,
    ) -> Result<Vec<(String, PathBuf)>, TitaniumRegistryError> {
        let _lock = self.lock_shared()?;
        let artifact = self.read_artifact_closure_unlocked(digest)?;
        let descriptor = self.read_release_descriptor_unlocked(&artifact)?;
        if descriptor.project_id != expected_project_id
            || descriptor.target != expected_target
            || descriptor.interface != expected_interface
        {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        descriptor
            .runtime_artifacts
            .into_iter()
            .map(|runtime| {
                let dependency = self.read_artifact_unlocked(&runtime.artifact_digest)?;
                if !matches!(
                    dependency.kind,
                    TitaniumArtifactKindV1::RuntimeLibrary | TitaniumArtifactKindV1::RuntimeSupport
                ) {
                    return Err(TitaniumRegistryError::InvalidReleaseDescriptor);
                }
                Ok((
                    runtime.mount,
                    self.root
                        .join("trees")
                        .join(dependency.tree_digest.as_str())
                        .join("payload"),
                ))
            })
            .collect()
    }

    pub fn begin_release_activation(
        &self,
        project_id: &str,
        candidate_artifact: &EvidenceDigest,
    ) -> Result<TitaniumReleaseActivationV1, TitaniumRegistryError> {
        if !valid_component(project_id) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let _lock = self.lock_exclusive()?;
        self.candidate_root_artifact_unlocked(candidate_artifact)?;
        let candidate = self.read_artifact_closure_unlocked(candidate_artifact)?;
        let descriptor = self.read_release_descriptor_unlocked(&candidate)?;
        if descriptor.project_id != project_id {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let previous_current_artifact = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::CurrentRelease,
            project_id,
        )?;
        let existing_recovery = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            project_id,
        )?;
        if existing_recovery.is_some() && existing_recovery.as_ref() != Some(candidate_artifact) {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        self.write_root_unlocked(&TitaniumRootRecordV1::new(
            TitaniumRootKindV1::PublicationRecovery,
            project_id.to_owned(),
            vec![TitaniumRootTargetV1::Artifact {
                digest: candidate_artifact.clone(),
            }],
        )?)?;
        Ok(TitaniumReleaseActivationV1 {
            project_id: project_id.to_owned(),
            candidate_artifact: candidate_artifact.clone(),
            previous_current_artifact,
        })
    }

    pub fn discard_candidate_release(
        &self,
        candidate_artifact: &EvidenceDigest,
    ) -> Result<(), TitaniumRegistryError> {
        let _lock = self.lock_exclusive()?;
        self.candidate_root_artifact_unlocked(candidate_artifact)?;
        if self.read_all_roots_unlocked()?.iter().any(|root| {
            root.kind == TitaniumRootKindV1::PublicationRecovery
                && root.targets
                    == [TitaniumRootTargetV1::Artifact {
                        digest: candidate_artifact.clone(),
                    }]
        }) {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        self.remove_root_unlocked(
            TitaniumRootKindV1::CandidateRelease,
            candidate_artifact.as_str(),
        )
    }

    pub fn commit_release_activation(
        &self,
        activation: &TitaniumReleaseActivationV1,
    ) -> Result<(), TitaniumRegistryError> {
        if !valid_component(&activation.project_id) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let _lock = self.lock_exclusive()?;
        let recovery = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            &activation.project_id,
        )?;
        let current = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::CurrentRelease,
            &activation.project_id,
        )?;
        let already_switched = current.as_ref() == Some(&activation.candidate_artifact);
        if recovery.is_none() && already_switched {
            let last_known_good = self.read_optional_single_artifact_root_unlocked(
                TitaniumRootKindV1::LastKnownGoodRelease,
                &activation.project_id,
            )?;
            if activation.previous_current_artifact.is_none()
                || last_known_good == activation.previous_current_artifact
            {
                return Ok(());
            }
        }
        if recovery.as_ref() != Some(&activation.candidate_artifact) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        if !already_switched && current != activation.previous_current_artifact {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        if !already_switched {
            if let Some(previous) = activation.previous_current_artifact.as_ref()
                && previous != &activation.candidate_artifact
            {
                self.write_root_unlocked(&TitaniumRootRecordV1::new(
                    TitaniumRootKindV1::LastKnownGoodRelease,
                    activation.project_id.clone(),
                    vec![TitaniumRootTargetV1::Artifact {
                        digest: previous.clone(),
                    }],
                )?)?;
            }
            self.write_root_unlocked(&TitaniumRootRecordV1::new(
                TitaniumRootKindV1::CurrentRelease,
                activation.project_id.clone(),
                vec![TitaniumRootTargetV1::Artifact {
                    digest: activation.candidate_artifact.clone(),
                }],
            )?)?;
        }
        Ok(())
    }

    pub fn abort_release_activation(
        &self,
        activation: &TitaniumReleaseActivationV1,
    ) -> Result<(), TitaniumRegistryError> {
        if !valid_component(&activation.project_id) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let _lock = self.lock_exclusive()?;
        let recovery = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            &activation.project_id,
        )?;
        if recovery.as_ref() != Some(&activation.candidate_artifact) {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        let current = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::CurrentRelease,
            &activation.project_id,
        )?;
        if current != activation.previous_current_artifact {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        Ok(())
    }

    pub fn release_recovery(
        &self,
        project_id: &str,
    ) -> Result<Option<TitaniumReleaseRecoveryV1>, TitaniumRegistryError> {
        if !valid_component(project_id) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let _lock = self.lock_shared()?;
        let Some(candidate_artifact) = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            project_id,
        )?
        else {
            return Ok(None);
        };
        self.read_artifact_closure_unlocked(&candidate_artifact)?;
        let current_artifact = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::CurrentRelease,
            project_id,
        )?;
        Ok(Some(TitaniumReleaseRecoveryV1 {
            candidate_artifact,
            current_artifact,
        }))
    }

    pub fn finalize_release_activation(
        &self,
        activation: &TitaniumReleaseActivationV1,
        committed: bool,
    ) -> Result<(), TitaniumRegistryError> {
        if !valid_component(&activation.project_id) {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        let _lock = self.lock_exclusive()?;
        let recovery = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            &activation.project_id,
        )?;
        let current = self.read_optional_single_artifact_root_unlocked(
            TitaniumRootKindV1::CurrentRelease,
            &activation.project_id,
        )?;
        if recovery.as_ref() != Some(&activation.candidate_artifact)
            || committed && current.as_ref() != Some(&activation.candidate_artifact)
            || !committed && current != activation.previous_current_artifact
        {
            return Err(TitaniumRegistryError::ReleaseActivationConflict);
        }
        match self.candidate_root_artifact_unlocked(&activation.candidate_artifact) {
            Ok(()) => {}
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.remove_root_unlocked(
            TitaniumRootKindV1::CandidateRelease,
            activation.candidate_artifact.as_str(),
        )?;
        self.remove_root_unlocked(
            TitaniumRootKindV1::PublicationRecovery,
            &activation.project_id,
        )
    }

    pub fn collect_garbage(&self) -> Result<TitaniumGcReportV1, TitaniumRegistryError> {
        let _lock = self.lock_exclusive()?;
        let mut root_artifacts = BTreeSet::new();
        let mut actions = BTreeSet::new();
        for root in self.read_all_roots_unlocked()? {
            for target in root.targets {
                match target {
                    TitaniumRootTargetV1::Artifact { digest } => {
                        root_artifacts.insert(digest);
                    }
                    TitaniumRootTargetV1::Action { key } => {
                        actions.insert(key);
                    }
                }
            }
        }
        let mut artifacts = BTreeSet::new();
        let mut queue = root_artifacts.into_iter().collect::<VecDeque<_>>();
        for key in actions.clone() {
            let action = self.read_action_unlocked(&key)?;
            self.validate_action_inputs_unlocked(&action.material)?;
            queue.push_back(action.output_artifact);
            queue.extend(action.material.referenced_artifacts().cloned());
        }
        while let Some(digest) = queue.pop_front() {
            if !artifacts.insert(digest.clone()) {
                continue;
            }
            queue.extend(self.read_artifact_unlocked(&digest)?.dependencies);
        }
        let mut trees = BTreeSet::new();
        for digest in &artifacts {
            trees.insert(self.read_artifact_unlocked(digest)?.tree_digest);
        }
        Ok(TitaniumGcReportV1 {
            removed_actions: sweep_documents(
                &self.root.join("actions"),
                &actions,
                self.expected_owner_uid,
            )?,
            removed_artifacts: sweep_documents(
                &self.root.join("artifacts"),
                &artifacts,
                self.expected_owner_uid,
            )?,
            removed_trees: sweep_tree_directories(
                &self.root.join("trees"),
                &trees,
                self.expected_owner_uid,
            )?,
            removed_staging_entries: sweep_staging(
                &self.root.join("staging"),
                self.expected_owner_uid,
            )?,
        })
    }

    fn initialize(&self) -> Result<(), TitaniumRegistryError> {
        validate_directory(&self.root, self.expected_owner_uid, 0o755)?;
        for relative in ["trees", "artifacts", "actions", "roots", "staging"] {
            ensure_owned_directory(&self.root.join(relative), self.expected_owner_uid, 0o755)?;
        }
        for kind in TitaniumRootKindV1::ALL {
            ensure_owned_directory(
                &self.root.join("roots").join(kind.directory_name()),
                self.expected_owner_uid,
                0o755,
            )?;
        }
        let lock = self.root.join("registry.lock");
        if !lock.exists() {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o644);
            match options.open(&lock) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        validate_regular_file(&lock, self.expected_owner_uid, 0o644)?;
        Ok(())
    }

    fn validate_layout(&self) -> Result<(), TitaniumRegistryError> {
        validate_directory(&self.root, self.expected_owner_uid, 0o755)?;
        for relative in ["trees", "artifacts", "actions", "roots", "staging"] {
            validate_directory(&self.root.join(relative), self.expected_owner_uid, 0o755)?;
        }
        for kind in TitaniumRootKindV1::ALL {
            validate_directory(
                &self.root.join("roots").join(kind.directory_name()),
                self.expected_owner_uid,
                0o755,
            )?;
        }
        validate_regular_file(
            &self.root.join("registry.lock"),
            self.expected_owner_uid,
            0o644,
        )
    }

    fn publish_tree_unlocked(
        &self,
        source: &Path,
        manifest: &TitaniumTreeManifestV1,
    ) -> Result<(), TitaniumRegistryError> {
        let final_path = self.root.join("trees").join(manifest.tree_digest.as_str());
        if final_path.exists() {
            if self.read_tree_unlocked(&manifest.tree_digest).is_ok() {
                return Ok(());
            }
            let metadata = fs::symlink_metadata(&final_path)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != self.expected_owner_uid
            {
                return Err(TitaniumRegistryError::UnsafeRegistryDirectory);
            }
            make_tree_writable(&final_path);
            fs::remove_dir_all(&final_path)?;
            sync_directory(&self.root.join("trees"))?;
        }
        let stage = self
            .root
            .join("staging")
            .join(Uuid::new_v4().simple().to_string());
        publication_step(
            "create staging directory",
            create_directory(&stage, self.expected_owner_uid, 0o700),
        )?;
        let result = (|| {
            let payload = stage.join("payload");
            publication_step(
                "create staged payload",
                create_directory(&payload, self.expected_owner_uid, 0o700),
            )?;
            publication_step(
                "copy staged payload",
                copy_tree(source, &payload, &manifest.entries),
            )?;
            publication_step("seal staged payload", seal_tree(&payload))?;
            let copied = publication_step(
                "verify staged payload",
                TitaniumTreeManifestV1::from_directory(&payload),
            )?;
            if copied != *manifest {
                return Err(TitaniumRegistryError::TreeChangedDuringPublication);
            }
            publication_step(
                "write staged manifest",
                write_new_document(
                    &stage.join("manifest.jcs"),
                    &manifest.canonical_bytes()?,
                    0o444,
                ),
            )?;
            publication_step("sync staged object", sync_directory(&stage))?;
            publication_step(
                "promote staged object",
                fs::rename(&stage, &final_path).map_err(Into::into),
            )?;
            publication_step(
                "seal promoted object",
                fs::set_permissions(&final_path, fs::Permissions::from_mode(0o555))
                    .map_err(Into::into),
            )?;
            publication_step("sync promoted object", sync_directory(&final_path))?;
            publication_step(
                "sync tree registry",
                sync_directory(&self.root.join("trees")),
            )?;
            Ok(())
        })();
        if result.is_err() && stage.exists() {
            make_tree_writable(&stage);
            let _ = fs::remove_dir_all(&stage);
        }
        result
    }

    fn publish_artifact_unlocked(
        &self,
        source: &Path,
        manifest: &TitaniumTreeManifestV1,
        artifact: &TitaniumArtifactManifestV1,
    ) -> Result<(), TitaniumRegistryError> {
        for dependency in &artifact.dependencies {
            self.read_artifact_unlocked(dependency)?;
        }
        self.publish_tree_unlocked(source, manifest)?;
        self.validate_artifact_payload_unlocked(artifact)?;
        publish_immutable_document(
            &self.artifact_path(&artifact.artifact_digest),
            &artifact.canonical_bytes()?,
            self.expected_owner_uid,
        )
    }

    fn write_root_unlocked(
        &self,
        root: &TitaniumRootRecordV1,
    ) -> Result<(), TitaniumRegistryError> {
        root.validate()?;
        self.validate_targets_unlocked(&root.targets)?;
        write_atomic_document(
            &self.root_path(root.kind, &root.name),
            &root.canonical_bytes()?,
            self.expected_owner_uid,
        )
    }

    fn write_candidate_root_unlocked(
        &self,
        root: &TitaniumRootRecordV1,
    ) -> Result<(), TitaniumRegistryError> {
        if root.kind != TitaniumRootKindV1::CandidateRelease {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        match self.read_root_unlocked(root.kind, &root.name) {
            Ok(existing) if existing == *root => Ok(()),
            Ok(_) => Err(TitaniumRegistryError::CandidateRootConflict),
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                self.write_root_unlocked(root)
            }
            Err(error) => Err(error),
        }
    }

    fn remove_root_unlocked(
        &self,
        kind: TitaniumRootKindV1,
        name: &str,
    ) -> Result<(), TitaniumRegistryError> {
        match fs::remove_file(self.root_path(kind, name)) {
            Ok(()) => sync_directory(&self.root.join("roots").join(kind.directory_name())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn read_optional_single_artifact_root_unlocked(
        &self,
        kind: TitaniumRootKindV1,
        name: &str,
    ) -> Result<Option<EvidenceDigest>, TitaniumRegistryError> {
        match self.read_root_unlocked(kind, name) {
            Ok(root) => {
                let [TitaniumRootTargetV1::Artifact { digest }] = root.targets.as_slice() else {
                    return Err(TitaniumRegistryError::InvalidRootRecord);
                };
                Ok(Some(digest.clone()))
            }
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn candidate_root_artifact_unlocked(
        &self,
        candidate_artifact: &EvidenceDigest,
    ) -> Result<(), TitaniumRegistryError> {
        let root = self.read_root_unlocked(
            TitaniumRootKindV1::CandidateRelease,
            candidate_artifact.as_str(),
        )?;
        let matches = match root.targets.as_slice() {
            [TitaniumRootTargetV1::Artifact { digest }] => digest == candidate_artifact,
            [TitaniumRootTargetV1::Action { key }] => {
                let action = self.read_action_unlocked(key)?;
                self.validate_action_inputs_unlocked(&action.material)?;
                action.output_artifact == *candidate_artifact
            }
            _ => false,
        };
        if !matches {
            return Err(TitaniumRegistryError::InvalidReleaseActivation);
        }
        Ok(())
    }

    fn read_tree_unlocked(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<TitaniumTreeManifestV1, TitaniumRegistryError> {
        let root = self.root.join("trees").join(digest.as_str());
        validate_directory(&root, self.expected_owner_uid, 0o555)?;
        let manifest = TitaniumTreeManifestV1::decode_canonical(&read_document(
            &root.join("manifest.jcs"),
            self.expected_owner_uid,
        )?)?;
        if manifest.tree_digest != *digest
            || TitaniumTreeManifestV1::from_directory(&root.join("payload"))? != manifest
        {
            return Err(TitaniumRegistryError::TreeIntegrityMismatch);
        }
        Ok(manifest)
    }

    fn read_toolchain_descriptor_unlocked(
        &self,
        artifact: &TitaniumArtifactManifestV1,
        expected_interface: Option<&str>,
    ) -> Result<TitaniumToolchainDescriptorV1, TitaniumRegistryError> {
        if artifact.kind != TitaniumArtifactKindV1::CompilerToolchain {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        let payload = self
            .root
            .join("trees")
            .join(artifact.tree_digest.as_str())
            .join("payload");
        let descriptor = TitaniumToolchainDescriptorV1::decode_canonical(&read_document(
            &payload.join(TITANIUM_TOOLCHAIN_DESCRIPTOR_FILE),
            self.expected_owner_uid,
        )?)?;
        let mut declared_dependencies = descriptor
            .components
            .iter()
            .map(|component| component.artifact_digest.clone())
            .collect::<Vec<_>>();
        declared_dependencies.sort();
        if descriptor.target != artifact.target
            || expected_interface.is_some_and(|value| descriptor.interface != value)
            || declared_dependencies != artifact.dependencies
        {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        for executable in &descriptor.required_executables {
            validate_regular_file(
                &payload.join("bin").join(executable),
                self.expected_owner_uid,
                0o555,
            )?;
        }
        for component in &descriptor.components {
            validate_directory(
                &payload.join(&component.mount),
                self.expected_owner_uid,
                0o555,
            )?;
            if fs::read_dir(payload.join(&component.mount))?
                .next()
                .is_some()
            {
                return Err(TitaniumRegistryError::InvalidToolchainDescriptor);
            }
            let dependency = self.read_artifact_unlocked(&component.artifact_digest)?;
            if !matches!(
                dependency.kind,
                TitaniumArtifactKindV1::BuildTool
                    | TitaniumArtifactKindV1::RuntimeLibrary
                    | TitaniumArtifactKindV1::RuntimeSupport
            ) {
                return Err(TitaniumRegistryError::InvalidToolchainDescriptor);
            }
        }
        Ok(descriptor)
    }

    fn read_artifact_unlocked(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<TitaniumArtifactManifestV1, TitaniumRegistryError> {
        let manifest = TitaniumArtifactManifestV1::decode_canonical(&read_document(
            &self.artifact_path(digest),
            self.expected_owner_uid,
        )?)?;
        if manifest.artifact_digest != *digest {
            return Err(TitaniumRegistryError::ArtifactIntegrityMismatch);
        }
        self.read_tree_unlocked(&manifest.tree_digest)?;
        self.validate_artifact_payload_unlocked(&manifest)?;
        Ok(manifest)
    }

    fn validate_artifact_payload_unlocked(
        &self,
        artifact: &TitaniumArtifactManifestV1,
    ) -> Result<(), TitaniumRegistryError> {
        match artifact.kind {
            TitaniumArtifactKindV1::CompilerToolchain => {
                self.read_toolchain_descriptor_unlocked(artifact, None)?;
            }
            TitaniumArtifactKindV1::Release => {
                self.read_release_descriptor_unlocked(artifact)?;
            }
            TitaniumArtifactKindV1::BuildTool
            | TitaniumArtifactKindV1::RuntimeLibrary
            | TitaniumArtifactKindV1::RuntimeSupport
            | TitaniumArtifactKindV1::DependencySnapshot => {}
        }
        Ok(())
    }

    fn read_release_descriptor_unlocked(
        &self,
        artifact: &TitaniumArtifactManifestV1,
    ) -> Result<TitaniumReleaseDescriptorV1, TitaniumRegistryError> {
        if artifact.kind != TitaniumArtifactKindV1::Release {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        let payload = self
            .root
            .join("trees")
            .join(artifact.tree_digest.as_str())
            .join("payload");
        let descriptor = TitaniumReleaseDescriptorV1::decode_canonical(&read_document(
            &payload.join(TITANIUM_RELEASE_DESCRIPTOR_FILE),
            self.expected_owner_uid,
        )?)?;
        let mut declared_dependencies = descriptor
            .runtime_artifacts
            .iter()
            .map(|runtime| runtime.artifact_digest.clone())
            .collect::<Vec<_>>();
        declared_dependencies.sort();
        if descriptor.target != artifact.target || declared_dependencies != artifact.dependencies {
            return Err(TitaniumRegistryError::InstalledArtifactMismatch);
        }
        for dependency_digest in &artifact.dependencies {
            let dependency = self.read_artifact_unlocked(dependency_digest)?;
            if !matches!(
                dependency.kind,
                TitaniumArtifactKindV1::RuntimeLibrary | TitaniumArtifactKindV1::RuntimeSupport
            ) {
                return Err(TitaniumRegistryError::InvalidReleaseDescriptor);
            }
        }
        validate_regular_file(
            &payload.join(&descriptor.entrypoint),
            self.expected_owner_uid,
            0o555,
        )?;
        Ok(descriptor)
    }

    fn read_action_unlocked(
        &self,
        key: &EvidenceDigest,
    ) -> Result<TitaniumActionRecordV1, TitaniumRegistryError> {
        let record = TitaniumActionRecordV1::decode_canonical(&read_document(
            &self.action_path(key),
            self.expected_owner_uid,
        )?)?;
        if record.action_key != *key {
            return Err(TitaniumRegistryError::ActionIntegrityMismatch);
        }
        Ok(record)
    }

    fn validate_targets_unlocked(
        &self,
        targets: &[TitaniumRootTargetV1],
    ) -> Result<(), TitaniumRegistryError> {
        for target in targets {
            match target {
                TitaniumRootTargetV1::Artifact { digest } => {
                    self.read_artifact_closure_unlocked(digest)?;
                }
                TitaniumRootTargetV1::Action { key } => {
                    let action = self.read_action_unlocked(key)?;
                    self.validate_action_inputs_unlocked(&action.material)?;
                    self.read_artifact_closure_unlocked(&action.output_artifact)?;
                }
            }
        }
        Ok(())
    }

    fn read_all_roots_unlocked(&self) -> Result<Vec<TitaniumRootRecordV1>, TitaniumRegistryError> {
        let mut roots = Vec::new();
        for kind in TitaniumRootKindV1::ALL {
            let directory = self.root.join("roots").join(kind.directory_name());
            for entry in sorted_directory_entries(&directory)? {
                let path = entry.path();
                if path.extension() != Some(OsStr::new("jcs")) {
                    return Err(TitaniumRegistryError::UnexpectedRegistryEntry);
                }
                let root = TitaniumRootRecordV1::decode_canonical(&read_document(
                    &path,
                    self.expected_owner_uid,
                )?)?;
                if root.kind != kind
                    || path.file_stem().and_then(OsStr::to_str) != Some(root.name.as_str())
                {
                    return Err(TitaniumRegistryError::InvalidRootRecord);
                }
                self.validate_targets_unlocked(&root.targets)?;
                roots.push(root);
            }
        }
        Ok(roots)
    }

    fn read_root_unlocked(
        &self,
        kind: TitaniumRootKindV1,
        name: &str,
    ) -> Result<TitaniumRootRecordV1, TitaniumRegistryError> {
        if !valid_component(name) {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        let root = TitaniumRootRecordV1::decode_canonical(&read_document(
            &self.root_path(kind, name),
            self.expected_owner_uid,
        )?)?;
        if root.kind != kind || root.name != name {
            return Err(TitaniumRegistryError::InvalidRootRecord);
        }
        self.validate_targets_unlocked(&root.targets)?;
        Ok(root)
    }

    fn artifact_path(&self, digest: &EvidenceDigest) -> PathBuf {
        self.root
            .join("artifacts")
            .join(format!("{}.jcs", digest.as_str()))
    }

    fn action_path(&self, key: &EvidenceDigest) -> PathBuf {
        self.root
            .join("actions")
            .join(format!("{}.jcs", key.as_str()))
    }

    fn root_path(&self, kind: TitaniumRootKindV1, name: &str) -> PathBuf {
        self.root
            .join("roots")
            .join(kind.directory_name())
            .join(format!("{name}.jcs"))
    }

    fn lock_exclusive(&self) -> Result<File, TitaniumRegistryError> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.root.join("registry.lock"))?;
        file.lock_exclusive()?;
        Ok(file)
    }

    fn lock_shared(&self) -> Result<File, TitaniumRegistryError> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.root.join("registry.lock"))?;
        file.lock_shared()?;
        Ok(file)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TitaniumRegistryError {
    #[error("Titanium registry I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Titanium registry JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Titanium registry document is not canonical")]
    NonCanonicalDocument,
    #[error("Titanium registry directory ownership or mode is unsafe")]
    UnsafeRegistryDirectory,
    #[error("Titanium registry file ownership or mode is unsafe")]
    UnsafeRegistryFile,
    #[error("Titanium tree manifest is invalid")]
    InvalidTreeManifest,
    #[error("Titanium tree entry is invalid")]
    InvalidTreeEntry,
    #[error("Titanium artifact manifest is invalid")]
    InvalidArtifactManifest,
    #[error("Titanium toolchain descriptor or required executable is invalid")]
    InvalidToolchainDescriptor,
    #[error("Titanium release descriptor or entrypoint is invalid")]
    InvalidReleaseDescriptor,
    #[error("Titanium action material is invalid")]
    InvalidActionMaterial,
    #[error("Titanium action record is invalid")]
    InvalidActionRecord,
    #[error("Titanium root record is invalid")]
    InvalidRootRecord,
    #[error("Titanium authorization is invalid")]
    InvalidAuthorization,
    #[error("Titanium authorization does not match the requested action")]
    AuthorizationMismatch,
    #[error("Titanium artifact acquisition class is denied by policy")]
    AcquisitionDenied,
    #[error("Titanium tree contains an unsupported entry")]
    UnsupportedTreeEntry,
    #[error("Titanium tree changed during publication")]
    TreeChangedDuringPublication,
    #[error("Titanium tree integrity check failed")]
    TreeIntegrityMismatch,
    #[error("Titanium artifact integrity check failed")]
    ArtifactIntegrityMismatch,
    #[error("Titanium action integrity check failed")]
    ActionIntegrityMismatch,
    #[error("Titanium action publication conflicts with an existing record")]
    ActionConflict,
    #[error("Titanium registry contains an unexpected entry")]
    UnexpectedRegistryEntry,
    #[error("Titanium installed artifact does not match its required kind or target")]
    InstalledArtifactMismatch,
    #[error("Titanium installed artifact name already identifies different immutable content")]
    InstalledRootConflict,
    #[error("Titanium candidate release identity already has different publication evidence")]
    CandidateRootConflict,
    #[error("Titanium release activation request is invalid")]
    InvalidReleaseActivation,
    #[error("Titanium release activation conflicts with current or recovery state")]
    ReleaseActivationConflict,
    #[error("Titanium tree publication failed during {phase}: {source}")]
    PublicationStep {
        phase: &'static str,
        #[source]
        source: Box<TitaniumRegistryError>,
    },
}

fn publication_step<T>(
    phase: &'static str,
    result: Result<T, TitaniumRegistryError>,
) -> Result<T, TitaniumRegistryError> {
    result.map_err(|source| TitaniumRegistryError::PublicationStep {
        phase,
        source: Box::new(source),
    })
}

fn inspect_tree(root: &Path) -> Result<Vec<TitaniumTreeEntryV1>, TitaniumRegistryError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(TitaniumRegistryError::UnsupportedTreeEntry);
    }
    let mut entries = Vec::new();
    inspect_tree_at(root, Path::new(""), &mut entries)?;
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(TitaniumRegistryError::InvalidTreeManifest);
    }
    entries.sort_by(|left, right| left.path_base64url.cmp(&right.path_base64url));
    Ok(entries)
}

fn prepare_tree_artifact(
    source: &Path,
    kind: TitaniumArtifactKindV1,
    acquisition: TitaniumAcquisitionClassV1,
    target: String,
    mut dependencies: Vec<EvidenceDigest>,
    provenance_digest: EvidenceDigest,
) -> Result<(TitaniumTreeManifestV1, TitaniumArtifactManifestV1), TitaniumRegistryError> {
    let manifest = TitaniumTreeManifestV1::from_directory(source)?;
    dependencies.sort();
    dependencies.dedup();
    let artifact = TitaniumArtifactManifestV1::new(
        kind,
        acquisition,
        target,
        manifest.tree_digest.clone(),
        dependencies,
        provenance_digest,
    )?;
    Ok((manifest, artifact))
}

fn inspect_tree_at(
    root: &Path,
    relative: &Path,
    entries: &mut Vec<TitaniumTreeEntryV1>,
) -> Result<(), TitaniumRegistryError> {
    for entry in sorted_directory_entries(&root.join(relative))? {
        if entries.len() >= MAX_ENTRIES {
            return Err(TitaniumRegistryError::InvalidTreeManifest);
        }
        let name = entry.file_name();
        if name.as_bytes().is_empty() || name.as_bytes().len() > 255 {
            return Err(TitaniumRegistryError::InvalidTreeEntry);
        }
        let path = relative.join(name);
        validate_relative_path(&path)?;
        let metadata = fs::symlink_metadata(root.join(&path))?;
        let encoded_path = URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes());
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            entries.push(TitaniumTreeEntryV1 {
                path_base64url: encoded_path,
                entry_kind: TitaniumTreeEntryKindV1::Directory,
                mode: 0o555,
                bytes: 0,
                sha256: None,
                link_target_base64url: None,
            });
            inspect_tree_at(root, &path, entries)?;
        } else if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err(TitaniumRegistryError::UnsupportedTreeEntry);
            }
            let bytes = read_bounded_file(&root.join(&path), metadata.len())?;
            entries.push(TitaniumTreeEntryV1 {
                path_base64url: encoded_path,
                entry_kind: TitaniumTreeEntryKindV1::RegularFile,
                mode: metadata.mode() & 0o555,
                bytes: metadata.len(),
                sha256: Some(EvidenceDigest::sha256(bytes)),
                link_target_base64url: None,
            });
        } else if file_type.is_symlink() {
            let target = fs::read_link(root.join(&path))?;
            validate_link_target(&target)?;
            entries.push(TitaniumTreeEntryV1 {
                path_base64url: encoded_path,
                entry_kind: TitaniumTreeEntryKindV1::SymbolicLink,
                mode: 0o777,
                bytes: u64::try_from(target.as_os_str().as_bytes().len())
                    .map_err(|_| TitaniumRegistryError::InvalidTreeEntry)?,
                sha256: None,
                link_target_base64url: Some(URL_SAFE_NO_PAD.encode(target.as_os_str().as_bytes())),
            });
        } else {
            return Err(TitaniumRegistryError::UnsupportedTreeEntry);
        }
    }
    Ok(())
}

fn validate_tree_entry(entry: &TitaniumTreeEntryV1) -> Result<(), TitaniumRegistryError> {
    let path = decode_relative_path(&entry.path_base64url)?;
    validate_relative_path(&path)?;
    match entry.entry_kind {
        TitaniumTreeEntryKindV1::Directory => {
            if entry.bytes != 0 || entry.sha256.is_some() || entry.link_target_base64url.is_some() {
                return Err(TitaniumRegistryError::InvalidTreeEntry);
            }
        }
        TitaniumTreeEntryKindV1::RegularFile => {
            if entry.sha256.is_none() || entry.link_target_base64url.is_some() {
                return Err(TitaniumRegistryError::InvalidTreeEntry);
            }
        }
        TitaniumTreeEntryKindV1::SymbolicLink => {
            let target = entry
                .link_target_base64url
                .as_deref()
                .ok_or(TitaniumRegistryError::InvalidTreeEntry)?;
            if entry.sha256.is_some() || entry.mode != 0o777 {
                return Err(TitaniumRegistryError::InvalidTreeEntry);
            }
            let target_path = PathBuf::from(decode_os_string(target)?);
            validate_link_target(&target_path)?;
        }
    }
    if entry.mode & !0o777 != 0 {
        return Err(TitaniumRegistryError::InvalidTreeEntry);
    }
    Ok(())
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    entries: &[TitaniumTreeEntryV1],
) -> Result<(), TitaniumRegistryError> {
    for entry in entries {
        let relative = decode_relative_path(&entry.path_base64url)?;
        let from = source.join(&relative);
        let to = destination.join(&relative);
        match entry.entry_kind {
            TitaniumTreeEntryKindV1::Directory => {
                create_directory(&to, fs::metadata(destination)?.uid(), 0o700)?;
            }
            TitaniumTreeEntryKindV1::RegularFile => {
                let mut input = File::open(&from)?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true).mode(0o600);
                let mut output = options.open(&to)?;
                io::copy(&mut input, &mut output)?;
                output.sync_all()?;
                fs::set_permissions(&to, fs::Permissions::from_mode(entry.mode))?;
            }
            TitaniumTreeEntryKindV1::SymbolicLink => {
                let target: PathBuf = decode_os_string(
                    entry
                        .link_target_base64url
                        .as_deref()
                        .ok_or(TitaniumRegistryError::InvalidTreeEntry)?,
                )?
                .into();
                std::os::unix::fs::symlink(target, to)?;
            }
        }
    }
    Ok(())
}

fn seal_tree(path: &Path) -> Result<(), TitaniumRegistryError> {
    let mut directories = Vec::new();
    seal_tree_at(path, &mut directories)?;
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    for directory in directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

fn seal_tree_at(path: &Path, directories: &mut Vec<PathBuf>) -> Result<(), TitaniumRegistryError> {
    directories.push(path.to_path_buf());
    for entry in sorted_directory_entries(path)? {
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            seal_tree_at(&entry.path(), directories)?;
        } else if metadata.is_file() {
            fs::set_permissions(
                entry.path(),
                fs::Permissions::from_mode(metadata.mode() & 0o555),
            )?;
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path, expected_bytes: u64) -> Result<Vec<u8>, TitaniumRegistryError> {
    if expected_bytes > usize::MAX as u64 {
        return Err(TitaniumRegistryError::InvalidTreeEntry);
    }
    let file = File::open(path)?;
    let capacity =
        usize::try_from(expected_bytes).map_err(|_| TitaniumRegistryError::InvalidTreeEntry)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(expected_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_bytes {
        return Err(TitaniumRegistryError::TreeChangedDuringPublication);
    }
    Ok(bytes)
}

fn decode_relative_path(encoded: &str) -> Result<PathBuf, TitaniumRegistryError> {
    Ok(decode_os_string(encoded)?.into())
}

fn decode_os_string(encoded: &str) -> Result<OsString, TitaniumRegistryError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map(OsString::from_vec)
        .map_err(|_| TitaniumRegistryError::InvalidTreeEntry)
}

fn validate_relative_path(path: &Path) -> Result<(), TitaniumRegistryError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(TitaniumRegistryError::InvalidTreeEntry);
    }
    Ok(())
}

fn validate_link_target(path: &Path) -> Result<(), TitaniumRegistryError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(TitaniumRegistryError::InvalidTreeEntry);
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<(), TitaniumRegistryError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != expected_mode
    {
        return Err(TitaniumRegistryError::UnsafeRegistryDirectory);
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<(), TitaniumRegistryError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
    {
        return Err(TitaniumRegistryError::UnsafeRegistryFile);
    }
    Ok(())
}

fn ensure_owned_directory(
    path: &Path,
    expected_owner_uid: u32,
    mode: u32,
) -> Result<(), TitaniumRegistryError> {
    if !path.exists() {
        create_directory(path, expected_owner_uid, mode)?;
    }
    validate_directory(path, expected_owner_uid, mode)
}

fn create_directory(
    path: &Path,
    expected_owner_uid: u32,
    mode: u32,
) -> Result<(), TitaniumRegistryError> {
    let mut builder = DirBuilder::new();
    builder.mode(mode).create(path)?;
    validate_directory(path, expected_owner_uid, mode)
}

fn read_document(path: &Path, expected_owner_uid: u32) -> Result<Vec<u8>, TitaniumRegistryError> {
    validate_regular_file(path, expected_owner_uid, 0o444)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(TitaniumRegistryError::UnsafeRegistryFile);
    }
    read_bounded_file(path, metadata.len())
}

fn publish_immutable_document(
    path: &Path,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<(), TitaniumRegistryError> {
    if path.exists() {
        if read_document(path, expected_owner_uid)? == bytes {
            return Ok(());
        }
        return Err(TitaniumRegistryError::ActionConflict);
    }
    write_new_document(path, bytes, 0o444)?;
    sync_directory(
        path.parent()
            .ok_or(TitaniumRegistryError::UnsafeRegistryDirectory)?,
    )
}

fn write_new_document(path: &Path, bytes: &[u8], mode: u32) -> Result<(), TitaniumRegistryError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic_document(
    path: &Path,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<(), TitaniumRegistryError> {
    let parent = path
        .parent()
        .ok_or(TitaniumRegistryError::UnsafeRegistryDirectory)?;
    validate_directory(parent, expected_owner_uid, 0o755)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(OsStr::to_str).unwrap_or("root"),
        Uuid::new_v4().simple()
    ));
    write_new_document(&temporary, bytes, 0o444)?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), TitaniumRegistryError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sorted_directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>, TitaniumRegistryError> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn sweep_documents(
    directory: &Path,
    retained: &BTreeSet<EvidenceDigest>,
    expected_owner_uid: u32,
) -> Result<u64, TitaniumRegistryError> {
    let mut removed = 0;
    for entry in sorted_directory_entries(directory)? {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            return Err(TitaniumRegistryError::UnexpectedRegistryEntry);
        };
        let digest = EvidenceDigest::from_str(stem)
            .map_err(|_| TitaniumRegistryError::UnexpectedRegistryEntry)?;
        if path.extension() != Some(OsStr::new("jcs")) {
            return Err(TitaniumRegistryError::UnexpectedRegistryEntry);
        }
        validate_regular_file(&path, expected_owner_uid, 0o444)?;
        if !retained.contains(&digest) {
            fs::remove_file(path)?;
            removed += 1;
        }
    }
    sync_directory(directory)?;
    Ok(removed)
}

fn sweep_tree_directories(
    directory: &Path,
    retained: &BTreeSet<EvidenceDigest>,
    expected_owner_uid: u32,
) -> Result<u64, TitaniumRegistryError> {
    let mut removed = 0;
    for entry in sorted_directory_entries(directory)? {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| TitaniumRegistryError::UnexpectedRegistryEntry)?;
        let digest = EvidenceDigest::from_str(&name)
            .map_err(|_| TitaniumRegistryError::UnexpectedRegistryEntry)?;
        if !retained.contains(&digest) {
            validate_directory(&entry.path(), expected_owner_uid, 0o555)?;
            make_tree_writable(&entry.path());
            fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
    }
    sync_directory(directory)?;
    Ok(removed)
}

fn sweep_staging(directory: &Path, expected_owner_uid: u32) -> Result<u64, TitaniumRegistryError> {
    let mut removed = 0;
    for entry in sorted_directory_entries(directory)? {
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.uid() != expected_owner_uid {
            return Err(TitaniumRegistryError::UnexpectedRegistryEntry);
        }
        make_tree_writable(&entry.path());
        fs::remove_dir_all(entry.path())?;
        removed += 1;
    }
    sync_directory(directory)?;
    Ok(removed)
}

fn make_tree_writable(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                make_tree_writable(&entry.path());
            }
        }
    }
}

fn decode_canonical<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), TitaniumRegistryError>,
) -> Result<T, TitaniumRegistryError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice(bytes)?;
    if serde_jcs::to_vec(&value)? != bytes {
        return Err(TitaniumRegistryError::NonCanonicalDocument);
    }
    validate(&value)?;
    Ok(value)
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn valid_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !path.is_absolute()
        && path.components().all(|component| {
            matches!(component, Component::Normal(value) if !value.as_bytes().is_empty())
        })
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;

    fn registry() -> (tempfile::TempDir, TitaniumRegistryV1) {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("titanium");
        fs::create_dir(&root).expect("registry root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("root mode");
        let owner = fs::metadata(&root).expect("root metadata").uid();
        let registry = TitaniumRegistryV1::open_for_owner(&root, owner).expect("open registry");
        (directory, registry)
    }

    fn tree(directory: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let root = directory.path().join(name);
        fs::create_dir(&root).expect("tree root");
        fs::write(root.join("payload"), bytes).expect("tree payload");
        root
    }

    fn toolchain_tree(directory: &tempfile::TempDir, name: &str) -> PathBuf {
        let root = directory.path().join(name);
        fs::create_dir(&root).expect("toolchain root");
        fs::create_dir(root.join("bin")).expect("toolchain bin");
        for executable in ["cargo", "rustc"] {
            let path = root.join("bin").join(executable);
            fs::write(&path, executable.as_bytes()).expect("toolchain executable");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("toolchain executable mode");
        }
        let descriptor = TitaniumToolchainDescriptorV1::new(
            "rust-v1".to_owned(),
            "linux-x86_64".to_owned(),
            vec!["cargo".to_owned(), "rustc".to_owned()],
            Vec::new(),
        )
        .expect("toolchain descriptor");
        fs::write(
            root.join(TITANIUM_TOOLCHAIN_DESCRIPTOR_FILE),
            descriptor.canonical_bytes().expect("canonical descriptor"),
        )
        .expect("write toolchain descriptor");
        root
    }

    fn release_tree(directory: &tempfile::TempDir, name: &str) -> PathBuf {
        let root = directory.path().join(name);
        fs::create_dir(&root).expect("release root");
        fs::create_dir(root.join("bin")).expect("release bin");
        let executable = root.join("bin/rimg");
        fs::write(&executable, b"release").expect("release executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("release executable mode");
        let descriptor = TitaniumReleaseDescriptorV1::new(
            "rimg".to_owned(),
            "native-service-v1".to_owned(),
            "linux-x86_64".to_owned(),
            "bin/rimg".to_owned(),
            EvidenceDigest::sha256("runtime contract"),
            Vec::new(),
        )
        .expect("release descriptor");
        fs::write(
            root.join(TITANIUM_RELEASE_DESCRIPTOR_FILE),
            descriptor.canonical_bytes().expect("canonical descriptor"),
        )
        .expect("write release descriptor");
        root
    }

    fn publish(
        registry: &TitaniumRegistryV1,
        source: &Path,
        kind: TitaniumArtifactKindV1,
        dependencies: Vec<EvidenceDigest>,
    ) -> TitaniumArtifactManifestV1 {
        registry
            .publish_tree_artifact(
                source,
                kind,
                TitaniumAcquisitionClassV1::ControlledSourceBuild,
                "x86_64-linux-gnu".to_owned(),
                dependencies,
                EvidenceDigest::sha256("provenance"),
            )
            .expect("publish artifact")
    }

    #[test]
    fn identical_content_is_stored_once_while_provenance_stays_explicit() {
        let (directory, registry) = registry();
        let source = tree(&directory, "input", b"same bytes");
        let first = publish(
            &registry,
            &source,
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let second = registry
            .publish_tree_artifact(
                &source,
                TitaniumArtifactKindV1::RuntimeLibrary,
                TitaniumAcquisitionClassV1::VerifiedUpstreamPrebuilt,
                "x86_64-linux-gnu".to_owned(),
                vec![],
                EvidenceDigest::sha256("different provenance"),
            )
            .expect("publish second artifact");
        assert_eq!(first.tree_digest, second.tree_digest);
        assert_ne!(first.artifact_digest, second.artifact_digest);
        assert_eq!(
            fs::read_dir(registry.root.join("trees"))
                .expect("trees")
                .count(),
            1
        );
    }

    #[test]
    fn action_identity_excludes_project_and_policy_but_binds_toolchain_and_environment() {
        let material = TitaniumActionKeyMaterialV1 {
            recipe_digest: EvidenceDigest::sha256("recipe"),
            source_content_digests: vec![EvidenceDigest::sha256("source")],
            dependency_artifacts: vec![EvidenceDigest::sha256("dependencies")],
            toolchain_artifacts: vec![EvidenceDigest::sha256("rust-1.96")],
            target: "x86_64-linux-gnu".to_owned(),
            cpu_baseline: "znver3".to_owned(),
            abi: "gnu.2.36".to_owned(),
            normalized_environment: BTreeMap::from([(
                "SOURCE_DATE_EPOCH".to_owned(),
                "1".to_owned(),
            )]),
            output_contract_digest: EvidenceDigest::sha256("release-v1"),
        };
        let key = material.key().expect("action key");
        let authorization = TitaniumAuthorizationV1::new(
            "rimg".to_owned(),
            EvidenceDigest::sha256("policy-a"),
            key.clone(),
            vec![TitaniumAcquisitionClassV1::ControlledSourceBuild],
        )
        .expect("authorization");
        assert_eq!(authorization.action_key, key);
        let mut changed = material;
        changed.toolchain_artifacts = vec![EvidenceDigest::sha256("rust-1.97")];
        assert_ne!(changed.key().expect("changed key"), key);
    }

    #[test]
    fn candidate_action_publication_is_atomic_reusable_and_activatable() {
        let (directory, registry) = registry();
        let toolchain = publish(
            &registry,
            &tree(&directory, "action-toolchain", b"compiler"),
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let dependencies = publish(
            &registry,
            &tree(&directory, "action-dependencies", b"dependencies"),
            TitaniumArtifactKindV1::DependencySnapshot,
            vec![],
        );
        let release_source = release_tree(&directory, "action-release");
        let material = TitaniumActionKeyMaterialV1 {
            recipe_digest: EvidenceDigest::sha256("recipe"),
            source_content_digests: vec![EvidenceDigest::sha256("source")],
            dependency_artifacts: vec![dependencies.artifact_digest],
            toolchain_artifacts: vec![toolchain.artifact_digest.clone()],
            target: "linux-x86_64".to_owned(),
            cpu_baseline: "znver3".to_owned(),
            abi: "gnu.2.36".to_owned(),
            normalized_environment: BTreeMap::new(),
            output_contract_digest: EvidenceDigest::sha256("release-contract"),
        };
        let authorization = TitaniumAuthorizationV1::new(
            "rimg".to_owned(),
            EvidenceDigest::sha256("installed policy"),
            material.key().expect("action key"),
            vec![TitaniumAcquisitionClassV1::ControlledSourceBuild],
        )
        .expect("authorization");
        let (artifact, action) = registry
            .publish_candidate_release_action(
                &release_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("artifact provenance"),
                },
                material.clone(),
                EvidenceDigest::sha256("action provenance"),
            )
            .expect("publish candidate action");
        registry
            .collect_garbage()
            .expect("candidate action is rooted");
        assert_eq!(action.output_artifact, artifact.artifact_digest);
        assert!(matches!(
            registry.publish_candidate_release(
                &release_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("artifact provenance"),
                },
            ),
            Err(TitaniumRegistryError::CandidateRootConflict)
        ));
        assert_eq!(
            registry
                .resolve_action(&material, &authorization)
                .expect("resolve action")
                .expect("cached output"),
            artifact
        );
        assert_eq!(
            registry
                .read_root(
                    TitaniumRootKindV1::CandidateRelease,
                    artifact.artifact_digest.as_str(),
                )
                .expect("action root")
                .targets,
            vec![TitaniumRootTargetV1::Action {
                key: action.action_key.clone(),
            }]
        );
        let activation = registry
            .begin_release_activation("rimg", &artifact.artifact_digest)
            .expect("activate action-rooted candidate");
        registry
            .abort_release_activation(&activation)
            .expect("abort activation");
        registry
            .finalize_release_activation(&activation, false)
            .expect("finalize activation");
    }

    #[test]
    fn action_authorization_checks_the_complete_runtime_and_toolchain_closure() {
        let (directory, registry) = registry();
        let upstream_runtime = registry
            .publish_tree_artifact(
                &tree(&directory, "upstream-runtime", b"runtime"),
                TitaniumArtifactKindV1::RuntimeLibrary,
                TitaniumAcquisitionClassV1::VerifiedUpstreamPrebuilt,
                "linux-x86_64".to_owned(),
                vec![],
                EvidenceDigest::sha256("upstream provenance"),
            )
            .expect("publish upstream runtime");
        let toolchain = publish(
            &registry,
            &tree(&directory, "closure-toolchain", b"compiler"),
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let dependencies = publish(
            &registry,
            &tree(&directory, "closure-dependencies", b"dependencies"),
            TitaniumArtifactKindV1::DependencySnapshot,
            vec![],
        );
        let material = TitaniumActionKeyMaterialV1 {
            recipe_digest: EvidenceDigest::sha256("recipe"),
            source_content_digests: vec![EvidenceDigest::sha256("source")],
            dependency_artifacts: vec![dependencies.artifact_digest],
            toolchain_artifacts: vec![toolchain.artifact_digest],
            target: "linux-x86_64".to_owned(),
            cpu_baseline: "znver3".to_owned(),
            abi: "gnu.2.36".to_owned(),
            normalized_environment: BTreeMap::new(),
            output_contract_digest: EvidenceDigest::sha256("release-contract"),
        };
        let release_source = release_tree(&directory, "closure-release");
        let release_descriptor = TitaniumReleaseDescriptorV1::new(
            "rimg".to_owned(),
            "native-service-v1".to_owned(),
            "linux-x86_64".to_owned(),
            "bin/rimg".to_owned(),
            EvidenceDigest::sha256("runtime contract"),
            vec![TitaniumReleaseRuntimeArtifactV1 {
                mount: "native".to_owned(),
                artifact_digest: upstream_runtime.artifact_digest.clone(),
            }],
        )
        .expect("release descriptor");
        fs::write(
            release_source.join(TITANIUM_RELEASE_DESCRIPTOR_FILE),
            release_descriptor
                .canonical_bytes()
                .expect("release descriptor bytes"),
        )
        .expect("write release descriptor");
        registry
            .publish_rooted_tree_action(
                &release_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![upstream_runtime.artifact_digest],
                    provenance_digest: EvidenceDigest::sha256("release provenance"),
                },
                material.clone(),
                EvidenceDigest::sha256("action provenance"),
                TitaniumRootKindV1::WarmAction,
                "rimg".to_owned(),
            )
            .expect("publish action with runtime closure");
        let denied = TitaniumAuthorizationV1::new(
            "rimg".to_owned(),
            EvidenceDigest::sha256("policy"),
            material.key().expect("action key"),
            vec![TitaniumAcquisitionClassV1::ControlledSourceBuild],
        )
        .expect("restrictive authorization");
        assert!(matches!(
            registry.resolve_action(&material, &denied),
            Err(TitaniumRegistryError::AcquisitionDenied)
        ));
    }

    #[test]
    fn release_activation_roots_preserve_candidate_current_and_last_known_good() {
        let (directory, registry) = registry();
        let first_source = release_tree(&directory, "first-release");
        fs::write(first_source.join("bin/rimg"), b"first").expect("first executable");
        let first = registry
            .publish_candidate_release(
                &first_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("first provenance"),
                },
            )
            .expect("publish first release");
        let first_activation = registry
            .begin_release_activation("rimg", &first.artifact_digest)
            .expect("begin first activation");
        assert_eq!(first_activation.previous_current_artifact, None);
        registry
            .commit_release_activation(&first_activation)
            .expect("commit first activation");
        registry
            .commit_release_activation(&first_activation)
            .expect("idempotent commit replay");
        registry
            .finalize_release_activation(&first_activation, true)
            .expect("finalize first activation");
        assert_eq!(
            registry
                .read_root(TitaniumRootKindV1::CurrentRelease, "rimg")
                .expect("current root")
                .targets,
            vec![TitaniumRootTargetV1::Artifact {
                digest: first.artifact_digest.clone(),
            }]
        );
        assert!(matches!(
            registry.read_root(TitaniumRootKindV1::PublicationRecovery, "rimg"),
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));

        let second_source = release_tree(&directory, "second-release");
        fs::write(second_source.join("bin/rimg"), b"second").expect("second executable");
        let second = registry
            .publish_candidate_release(
                &second_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("second provenance"),
                },
            )
            .expect("publish second release");
        let second_activation = registry
            .begin_release_activation("rimg", &second.artifact_digest)
            .expect("begin second activation");
        assert_eq!(
            second_activation.previous_current_artifact,
            Some(first.artifact_digest.clone())
        );
        registry
            .commit_release_activation(&second_activation)
            .expect("commit second activation");
        registry
            .finalize_release_activation(&second_activation, true)
            .expect("finalize second activation");
        assert_eq!(
            registry
                .read_root(TitaniumRootKindV1::CurrentRelease, "rimg")
                .expect("new current root")
                .targets,
            vec![TitaniumRootTargetV1::Artifact {
                digest: second.artifact_digest,
            }]
        );
        assert_eq!(
            registry
                .read_root(TitaniumRootKindV1::LastKnownGoodRelease, "rimg")
                .expect("last-known-good root")
                .targets,
            vec![TitaniumRootTargetV1::Artifact {
                digest: first.artifact_digest,
            }]
        );
    }

    #[test]
    fn release_activation_rejects_a_second_candidate_until_recovery_is_resolved() {
        let (directory, registry) = registry();
        let first = registry
            .publish_candidate_release(
                &release_tree(&directory, "pending-first"),
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("first"),
                },
            )
            .expect("first candidate");
        let second_source = release_tree(&directory, "pending-second");
        fs::write(second_source.join("bin/rimg"), b"different").expect("different release");
        let second = registry
            .publish_candidate_release(
                &second_source,
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("second"),
                },
            )
            .expect("second candidate");
        let activation = registry
            .begin_release_activation("rimg", &first.artifact_digest)
            .expect("begin first candidate");
        assert!(matches!(
            registry.begin_release_activation("rimg", &second.artifact_digest),
            Err(TitaniumRegistryError::ReleaseActivationConflict)
        ));
        assert!(matches!(
            registry.discard_candidate_release(&first.artifact_digest),
            Err(TitaniumRegistryError::ReleaseActivationConflict)
        ));
        registry
            .abort_release_activation(&activation)
            .expect("abort first candidate");
        registry
            .finalize_release_activation(&activation, false)
            .expect("finalize aborted candidate");
        registry
            .begin_release_activation("rimg", &second.artifact_digest)
            .expect("begin second after abort");
    }

    #[test]
    fn an_unactivated_candidate_has_an_explicit_discard_and_gc_lifecycle() {
        let (directory, registry) = registry();
        let candidate = registry
            .publish_candidate_release(
                &release_tree(&directory, "discarded-release"),
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::Release,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("discard provenance"),
                },
            )
            .expect("publish candidate");
        registry.collect_garbage().expect("candidate is rooted");
        registry
            .read_artifact_closure(&candidate.artifact_digest)
            .expect("candidate survives GC");
        registry
            .discard_candidate_release(&candidate.artifact_digest)
            .expect("discard candidate");
        let report = registry
            .collect_garbage()
            .expect("collect discarded candidate");
        assert_eq!(report.removed_artifacts, 1);
        assert_eq!(report.removed_trees, 1);
    }

    #[test]
    fn installed_toolchain_resolves_to_one_exact_verified_target() {
        let (directory, registry) = registry();
        let source = toolchain_tree(&directory, "rust-toolchain");
        let installed = registry
            .publish_installed_toolchain(
                &source,
                "rust-1.96-linux-x86_64".to_owned(),
                TitaniumAcquisitionClassV1::ControlledSourceBuild,
                "linux-x86_64".to_owned(),
                Vec::new(),
                EvidenceDigest::sha256("rust toolchain provenance"),
            )
            .expect("publish installed toolchain");
        let reopened =
            TitaniumRegistryV1::open_existing(&registry.root, registry.expected_owner_uid)
                .expect("reopen registry read-only");
        assert_eq!(
            reopened
                .installed_artifact(
                    "rust-1.96-linux-x86_64",
                    TitaniumArtifactKindV1::CompilerToolchain,
                    "linux-x86_64",
                    "rust-v1",
                )
                .expect("resolve exact toolchain"),
            installed
        );
        assert!(matches!(
            reopened.installed_artifact(
                "rust-1.96-linux-x86_64",
                TitaniumArtifactKindV1::CompilerToolchain,
                "linux-aarch64",
                "rust-v1",
            ),
            Err(TitaniumRegistryError::InstalledArtifactMismatch)
        ));
    }

    #[test]
    fn installed_root_names_are_immutable_version_identifiers() {
        let (directory, registry) = registry();
        let first_source = toolchain_tree(&directory, "immutable-toolchain-a");
        registry
            .publish_installed_toolchain(
                &first_source,
                "rust-1.96.1-znver3-linux-x86_64-gnu-v1".to_owned(),
                TitaniumAcquisitionClassV1::ControlledSourceBuild,
                "linux-x86_64".to_owned(),
                Vec::new(),
                EvidenceDigest::sha256("first provenance"),
            )
            .expect("publish first immutable version");
        let second_source = toolchain_tree(&directory, "immutable-toolchain-b");
        fs::write(second_source.join("bin/rustc"), b"different compiler")
            .expect("change compiler bytes");
        fs::set_permissions(
            second_source.join("bin/rustc"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("restore executable mode");

        assert!(matches!(
            registry.publish_installed_toolchain(
                &second_source,
                "rust-1.96.1-znver3-linux-x86_64-gnu-v1".to_owned(),
                TitaniumAcquisitionClassV1::ControlledSourceBuild,
                "linux-x86_64".to_owned(),
                Vec::new(),
                EvidenceDigest::sha256("second provenance"),
            ),
            Err(TitaniumRegistryError::InstalledRootConflict)
        ));
    }

    #[test]
    fn composite_toolchain_reuses_exact_named_components_without_copying_their_bytes() {
        let (directory, registry) = registry();
        let native_source = tree(&directory, "native-component", b"native");
        let native = registry
            .publish_installed_artifact(
                &native_source,
                "rimg-native-v1".to_owned(),
                TitaniumArtifactSpecV1 {
                    kind: TitaniumArtifactKindV1::RuntimeLibrary,
                    acquisition: TitaniumAcquisitionClassV1::ControlledSourceBuild,
                    target: "linux-x86_64".to_owned(),
                    dependencies: vec![],
                    provenance_digest: EvidenceDigest::sha256("native provenance"),
                },
            )
            .expect("native component");
        let toolchain_source = toolchain_tree(&directory, "composite-toolchain");
        fs::create_dir(toolchain_source.join("rimg-native")).expect("component mount");
        let descriptor = TitaniumToolchainDescriptorV1::new(
            "rust-v1".to_owned(),
            "linux-x86_64".to_owned(),
            vec!["cargo".to_owned(), "rustc".to_owned()],
            vec![TitaniumToolchainComponentV1 {
                mount: "rimg-native".to_owned(),
                artifact_digest: native.artifact_digest.clone(),
            }],
        )
        .expect("composite descriptor");
        fs::write(
            toolchain_source.join(TITANIUM_TOOLCHAIN_DESCRIPTOR_FILE),
            descriptor.canonical_bytes().expect("descriptor bytes"),
        )
        .expect("replace descriptor");
        let toolchain = registry
            .publish_installed_toolchain(
                &toolchain_source,
                "rust-rimg".to_owned(),
                TitaniumAcquisitionClassV1::ControlledSourceBuild,
                "linux-x86_64".to_owned(),
                vec![native.artifact_digest.clone()],
                EvidenceDigest::sha256("toolchain provenance"),
            )
            .expect("composite toolchain");
        let components = registry
            .toolchain_component_payloads(&toolchain.artifact_digest)
            .expect("component payloads");
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].0, "rimg-native");
        assert_eq!(
            components[0].1,
            registry
                .artifact_payload_path(
                    &native.artifact_digest,
                    TitaniumArtifactKindV1::RuntimeLibrary,
                )
                .expect("native payload")
        );
        assert!(
            fs::read_dir(toolchain_source.join("rimg-native"))
                .expect("placeholder")
                .next()
                .is_none()
        );
    }

    #[test]
    fn roots_preserve_complete_closures_and_gc_removes_only_unreachable_state() {
        let (directory, registry) = registry();
        let toolchain = publish(
            &registry,
            &tree(&directory, "toolchain", b"compiler"),
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let release = publish(
            &registry,
            &tree(&directory, "release", b"binary"),
            TitaniumArtifactKindV1::BuildTool,
            vec![toolchain.artifact_digest.clone()],
        );
        let unreachable = publish(
            &registry,
            &tree(&directory, "old", b"old binary"),
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let root = TitaniumRootRecordV1::new(
            TitaniumRootKindV1::ActiveOperation,
            "rimg".to_owned(),
            vec![TitaniumRootTargetV1::Artifact {
                digest: release.artifact_digest.clone(),
            }],
        )
        .expect("release root");
        registry.set_root(&root).expect("set root");
        let report = registry.collect_garbage().expect("collect garbage");
        assert_eq!(report.removed_artifacts, 1);
        assert_eq!(report.removed_trees, 1);
        registry
            .read_artifact_closure(&release.artifact_digest)
            .expect("release closure");
        registry
            .read_artifact_closure(&toolchain.artifact_digest)
            .expect("toolchain closure");
        assert!(matches!(
            registry.read_artifact_closure(&unreachable.artifact_digest),
            Err(TitaniumRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn corrupt_content_and_invalid_roots_fail_closed() {
        let (directory, registry) = registry();
        let artifact = publish(
            &registry,
            &tree(&directory, "artifact", b"original"),
            TitaniumArtifactKindV1::BuildTool,
            vec![],
        );
        let payload = registry
            .root
            .join("trees")
            .join(artifact.tree_digest.as_str())
            .join("payload/payload");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).expect("make writable");
        fs::write(&payload, b"corrupt!").expect("corrupt payload");
        assert!(matches!(
            registry.read_artifact_closure(&artifact.artifact_digest),
            Err(TitaniumRegistryError::TreeIntegrityMismatch
                | TitaniumRegistryError::TreeChangedDuringPublication)
        ));
        let missing = TitaniumRootRecordV1::new(
            TitaniumRootKindV1::ActiveOperation,
            "missing".to_owned(),
            vec![TitaniumRootTargetV1::Artifact {
                digest: EvidenceDigest::sha256("missing"),
            }],
        )
        .expect("root shape");
        assert!(registry.set_root(&missing).is_err());
    }
}
