use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Seek as _, SeekFrom, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    build::OciDigest,
    build_storage::{
        BUILDKIT_MAX_USED_BYTES, SHARED_BUILD_STORAGE_MIN_BYTES, SHARED_BUILD_STORAGE_ROOT,
        required_host_available_bytes,
    },
    domain::{
        EvidenceDigest, GitCommitId, ProjectId, VerifiedOciOutputPolicy, WorkflowAdapterIdV1,
        WorkflowArtifactKindV1, WorkflowLeaseV1, WorkflowNodeKindV1,
    },
    oci_base::validate_oci_layout,
    rootless_oci::BUILDCTL_EXECUTABLE,
    self_update::CURRENT_ROOTLESS_OCI_BUILD_EXECUTABLE,
};

pub const ROOTLESS_OCI_BUILD_POLICY_SCHEMA_VERSION: u16 = 1;
pub const ROOTLESS_OCI_BUILD_REQUEST_SCHEMA_VERSION: u16 = 1;
pub const ROOTLESS_OCI_BUILD_RESULT_SCHEMA_VERSION: u16 = 1;
pub const ROOTLESS_OCI_BUILD_EXECUTABLE: &str = CURRENT_ROOTLESS_OCI_BUILD_EXECUTABLE;
pub const ROOTLESS_OCI_BUILD_REQUEST_PATH: &str = "/request/oci-build-request.jcs";
pub const ROOTLESS_OCI_BUILD_PREPARED_ROOT: &str = "/prepared/source";
pub const ROOTLESS_OCI_BUILD_DEPENDENCY_ROOT: &str = "/dependencies";
pub const ROOTLESS_OCI_BUILD_OPERATION_ROOT: &str = "/operation";
pub const ROOTLESS_OCI_BUILD_TOOLCHAIN_ROOT: &str = "/toolchains";
pub const ROOTLESS_OCI_BUILD_OUTPUT_ROOT: &str = "/output";
pub const ROOTLESS_OCI_BUILD_SOCKET_PATH: &str = "/buildkit/buildkitd.sock";
pub const ROOTLESS_OCI_RESULT_STORE_ROOT: &str = "/var/lib/rdashboard-build/oci-results";

const REQUEST_PURPOSE: &str = "rdashboard.rootless-oci-build-request.v1";
const RESULT_PURPOSE: &str = "rdashboard.rootless-oci-build-result.v1";
const RESULT_ARCHIVE_FILE: &str = "image.oci.tar";
const RESULT_DOCUMENT_FILE: &str = "result.jcs";
const RESULT_REQUEST_FILE: &str = "request.jcs";
const BUILDKIT_METADATA_FILE: &str = ".buildkit-metadata.json";
const MIN_ARCHIVE_BYTES: u64 = 1024;
const MAX_ARCHIVE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_RESULT_BYTES: u64 = 64 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_DOCKERFILE_BYTES: u64 = 1024 * 1024;
const MAX_OCI_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OCI_ENTRIES: usize = 100_000;
const MAX_OCI_PATH_BYTES: usize = 512;
const MIN_STORE_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORE_ENTRIES: usize = 256;
const SANDBOX_REQUEST_FILE_MODE: u32 = 0o444;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciBuildArgV1 {
    pub key: String,
    pub value: String,
}

impl RootlessOciBuildArgV1 {
    fn validate(&self) -> Result<(), RootlessOciBuildError> {
        if !valid_build_arg_key(&self.key)
            || self.value.len() > 2_048
            || self
                .value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(RootlessOciBuildError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciBaseInputV1 {
    pub source: String,
    pub layout_name: String,
    pub dependency_path: String,
    pub manifest_digest: OciDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciLocalInputV1 {
    pub source: String,
    pub local_name: String,
    pub toolchain_path: String,
}

impl RootlessOciLocalInputV1 {
    fn validate(&self) -> Result<(), RootlessOciBuildError> {
        if !valid_source_reference(&self.source)
            || reserved_buildkit_context_name(&self.source)
            || !valid_token(&self.local_name, 64)
            || reserved_buildkit_context_name(&self.local_name)
            || !valid_relative_path(&self.toolchain_path)
        {
            return Err(RootlessOciBuildError::InvalidPolicy);
        }
        Ok(())
    }
}

impl RootlessOciBaseInputV1 {
    fn validate(&self) -> Result<(), RootlessOciBuildError> {
        if !valid_source_reference(&self.source)
            || reserved_buildkit_context_name(&self.source)
            || !valid_token(&self.layout_name, 64)
            || !valid_relative_path(&self.dependency_path)
            || !self.dependency_path.starts_with("oci-layouts/")
        {
            return Err(RootlessOciBuildError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciBuildPolicyV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub dockerfile_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build_args: Vec<RootlessOciBuildArgV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_inputs: Vec<RootlessOciBaseInputV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_inputs: Vec<RootlessOciLocalInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_output: Option<VerifiedOciOutputPolicy>,
    pub max_archive_bytes: u64,
}

impl RootlessOciBuildPolicyV1 {
    pub fn validate(&self) -> Result<(), RootlessOciBuildError> {
        if self.schema_version != ROOTLESS_OCI_BUILD_POLICY_SCHEMA_VERSION
            || !valid_relative_path(&self.dockerfile_path)
            || self
                .target
                .as_ref()
                .is_some_and(|target| !valid_token(target, 128))
            || self.platform != "linux/amd64"
            || !(MIN_ARCHIVE_BYTES..=MAX_ARCHIVE_BYTES).contains(&self.max_archive_bytes)
            || self.build_args.len() > 64
            || self.base_inputs.len() > 64
            || self.local_inputs.len() > 16
            || self
                .verified_output
                .as_ref()
                .is_some_and(|output| !output.validate())
            || !self.build_args.windows(2).all(|pair| pair[0] < pair[1])
            || !self.base_inputs.windows(2).all(|pair| pair[0] < pair[1])
            || !self.local_inputs.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(RootlessOciBuildError::InvalidPolicy);
        }
        for argument in &self.build_args {
            argument.validate()?;
        }
        for input in &self.base_inputs {
            input.validate()?;
        }
        for input in &self.local_inputs {
            input.validate()?;
        }
        if !strictly_unique(self.build_args.iter().map(|argument| argument.key.as_str()))
            || !strictly_unique(self.base_inputs.iter().map(|input| input.source.as_str()))
            || !strictly_unique(
                self.base_inputs
                    .iter()
                    .map(|input| input.layout_name.as_str()),
            )
            || !strictly_unique(
                self.base_inputs
                    .iter()
                    .map(|input| input.dependency_path.as_str()),
            )
            || !strictly_unique(self.local_inputs.iter().map(|input| input.source.as_str()))
            || !strictly_unique(
                self.local_inputs
                    .iter()
                    .map(|input| input.local_name.as_str())
                    .chain(
                        self.verified_output
                            .iter()
                            .map(|output| output.context_name.as_str()),
                    ),
            )
            || !strictly_unique(
                self.local_inputs
                    .iter()
                    .map(|input| input.toolchain_path.as_str()),
            )
            || !strictly_unique(
                self.base_inputs
                    .iter()
                    .map(|input| input.source.as_str())
                    .chain(self.local_inputs.iter().map(|input| input.source.as_str()))
                    .chain(
                        self.verified_output
                            .iter()
                            .map(|output| output.context_name.as_str()),
                    ),
            )
        {
            return Err(RootlessOciBuildError::InvalidPolicy);
        }
        Ok(())
    }
}

fn strictly_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn reserved_buildkit_context_name(value: &str) -> bool {
    matches!(value, "context" | "dockerfile")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciBuildRequestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub lease_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub workflow_policy_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub expected_input_digest: EvidenceDigest,
    pub dockerfile_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build_args: Vec<RootlessOciBuildArgV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_inputs: Vec<RootlessOciBaseInputV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_inputs: Vec<RootlessOciLocalInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_output: Option<VerifiedOciOutputPolicy>,
    pub max_archive_bytes: u64,
    pub request_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct RootlessOciBuildRequestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lease_digest: &'a EvidenceDigest,
    lease_id: Uuid,
    lease_generation: u32,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    expected_input_digest: &'a EvidenceDigest,
    dockerfile_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: &'a Option<String>,
    platform: &'a str,
    #[serde(skip_serializing_if = "<[RootlessOciBuildArgV1]>::is_empty")]
    build_args: &'a [RootlessOciBuildArgV1],
    #[serde(skip_serializing_if = "<[RootlessOciBaseInputV1]>::is_empty")]
    base_inputs: &'a [RootlessOciBaseInputV1],
    #[serde(skip_serializing_if = "<[RootlessOciLocalInputV1]>::is_empty")]
    local_inputs: &'a [RootlessOciLocalInputV1],
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_output: &'a Option<VerifiedOciOutputPolicy>,
    max_archive_bytes: u64,
}

impl RootlessOciBuildRequestV1 {
    pub fn from_policy(
        lease: &WorkflowLeaseV1,
        policy: &RootlessOciBuildPolicyV1,
    ) -> Result<Self, RootlessOciBuildError> {
        lease.validate()?;
        policy.validate()?;
        if lease.node_kind != WorkflowNodeKindV1::ReleaseBuild
            || lease.adapter_id != WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
            || lease.output_contract != WorkflowArtifactKindV1::ReleaseBuildResult
            || lease.project_id != policy.project_id
            || lease
                .resources
                .as_ref()
                .is_none_or(|resources| policy.max_archive_bytes > resources.output_max_bytes)
        {
            return Err(RootlessOciBuildError::LeaseMismatch);
        }
        let source_identity = lease.required_source_identity()?;
        let mut request = Self {
            purpose: REQUEST_PURPOSE.to_owned(),
            schema_version: ROOTLESS_OCI_BUILD_REQUEST_SCHEMA_VERSION,
            lease_digest: lease.lease_digest.clone(),
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            source_sha: lease.source_sha.clone(),
            source_sequence: source_identity.sequence,
            source_attestation_digest: source_identity.attestation_digest.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
            preparation_key: lease.preparation_key.clone(),
            expected_input_digest: lease.expected_input_digest.clone(),
            dockerfile_path: policy.dockerfile_path.clone(),
            target: policy.target.clone(),
            platform: policy.platform.clone(),
            build_args: policy.build_args.clone(),
            base_inputs: policy.base_inputs.clone(),
            local_inputs: policy.local_inputs.clone(),
            verified_output: policy.verified_output.clone(),
            max_archive_bytes: policy.max_archive_bytes,
            request_digest: EvidenceDigest::sha256([]),
        };
        request.request_digest = request.calculate_digest()?;
        request.validate_for_lease(lease)?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), RootlessOciBuildError> {
        let policy = RootlessOciBuildPolicyV1 {
            schema_version: ROOTLESS_OCI_BUILD_POLICY_SCHEMA_VERSION,
            project_id: self.project_id.clone(),
            dockerfile_path: self.dockerfile_path.clone(),
            target: self.target.clone(),
            platform: self.platform.clone(),
            build_args: self.build_args.clone(),
            base_inputs: self.base_inputs.clone(),
            local_inputs: self.local_inputs.clone(),
            verified_output: self.verified_output.clone(),
            max_archive_bytes: self.max_archive_bytes,
        };
        policy.validate()?;
        if self.purpose != REQUEST_PURPOSE
            || self.schema_version != ROOTLESS_OCI_BUILD_REQUEST_SCHEMA_VERSION
            || self.lease_id.is_nil()
            || self.attempt_id.is_nil()
            || self.lease_generation == 0
            || self.source_sequence == 0
            || self.request_digest != self.calculate_digest()?
        {
            return Err(RootlessOciBuildError::InvalidRequest);
        }
        Ok(())
    }

    pub fn validate_for_lease(&self, lease: &WorkflowLeaseV1) -> Result<(), RootlessOciBuildError> {
        self.validate()?;
        lease.validate()?;
        let source_identity = lease.required_source_identity()?;
        if lease.node_kind != WorkflowNodeKindV1::ReleaseBuild
            || lease.adapter_id != WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
            || lease.output_contract != WorkflowArtifactKindV1::ReleaseBuildResult
            || self.lease_digest != lease.lease_digest
            || self.lease_id != lease.lease_id
            || self.lease_generation != lease.lease_generation
            || self.attempt_id != lease.attempt_id
            || self.project_id != lease.project_id
            || self.source_sha != lease.source_sha
            || self.source_sequence != source_identity.sequence
            || self.source_attestation_digest != source_identity.attestation_digest
            || self.workflow_policy_digest != lease.workflow_policy_digest
            || self.preparation_key != lease.preparation_key
            || self.expected_input_digest != lease.expected_input_digest
            || self.verified_output.is_some() != lease_uses_verified_output(lease)?
            || lease
                .resources
                .as_ref()
                .is_none_or(|resources| self.max_archive_bytes > resources.output_max_bytes)
        {
            return Err(RootlessOciBuildError::LeaseMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RootlessOciBuildError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RootlessOciBuildError> {
        if bytes.is_empty()
            || bytes.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX)
        {
            return Err(RootlessOciBuildError::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&request)? != bytes {
            return Err(RootlessOciBuildError::NoncanonicalRequest);
        }
        request.validate()?;
        Ok(request)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, RootlessOciBuildError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &RootlessOciBuildRequestPayload {
                purpose: REQUEST_PURPOSE,
                schema_version: self.schema_version,
                lease_digest: &self.lease_digest,
                lease_id: self.lease_id,
                lease_generation: self.lease_generation,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                source_sequence: self.source_sequence,
                source_attestation_digest: &self.source_attestation_digest,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                expected_input_digest: &self.expected_input_digest,
                dockerfile_path: &self.dockerfile_path,
                target: &self.target,
                platform: &self.platform,
                build_args: &self.build_args,
                base_inputs: &self.base_inputs,
                local_inputs: &self.local_inputs,
                verified_output: &self.verified_output,
                max_archive_bytes: self.max_archive_bytes,
            },
        )?))
    }
}

fn lease_uses_verified_output(lease: &WorkflowLeaseV1) -> Result<bool, RootlessOciBuildError> {
    let inputs = lease.required_input_artifacts()?;
    let has_verification = inputs
        .iter()
        .any(|input| input.artifact_kind == WorkflowArtifactKindV1::VerificationReceipt);
    if has_verification && (inputs.len() != 2 || lease.operation_state.is_none())
        || !has_verification && (inputs.len() != 1 || lease.operation_state.is_some())
    {
        return Err(RootlessOciBuildError::LeaseMismatch);
    }
    Ok(has_verification)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootlessOciBuildResultV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub request_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub image_manifest_digest: OciDigest,
    pub image_config_digest: OciDigest,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_output_digest: Option<EvidenceDigest>,
    pub result_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct RootlessOciBuildResultPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    request_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    image_manifest_digest: &'a OciDigest,
    image_config_digest: &'a OciDigest,
    archive_digest: &'a EvidenceDigest,
    archive_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_output_digest: &'a Option<EvidenceDigest>,
}

impl RootlessOciBuildResultV1 {
    fn new(
        request: &RootlessOciBuildRequestV1,
        image_manifest_digest: OciDigest,
        image_config_digest: OciDigest,
        archive_digest: EvidenceDigest,
        archive_bytes: u64,
        verified_output_digest: Option<EvidenceDigest>,
    ) -> Result<Self, RootlessOciBuildError> {
        let mut result = Self {
            purpose: RESULT_PURPOSE.to_owned(),
            schema_version: ROOTLESS_OCI_BUILD_RESULT_SCHEMA_VERSION,
            request_digest: request.request_digest.clone(),
            project_id: request.project_id.clone(),
            source_sha: request.source_sha.clone(),
            image_manifest_digest,
            image_config_digest,
            archive_digest,
            archive_bytes,
            verified_output_digest,
            result_digest: EvidenceDigest::sha256([]),
        };
        result.result_digest = result.calculate_digest()?;
        result.validate(request)?;
        Ok(result)
    }

    pub fn validate(
        &self,
        request: &RootlessOciBuildRequestV1,
    ) -> Result<(), RootlessOciBuildError> {
        request.validate()?;
        if self.purpose != RESULT_PURPOSE
            || self.schema_version != ROOTLESS_OCI_BUILD_RESULT_SCHEMA_VERSION
            || self.request_digest != request.request_digest
            || self.project_id != request.project_id
            || self.source_sha != request.source_sha
            || !(MIN_ARCHIVE_BYTES..=request.max_archive_bytes).contains(&self.archive_bytes)
            || self.verified_output_digest.is_some() != request.verified_output.is_some()
            || self.result_digest != self.calculate_digest()?
        {
            return Err(RootlessOciBuildError::InvalidResult);
        }
        Ok(())
    }

    pub fn canonical_bytes(
        &self,
        request: &RootlessOciBuildRequestV1,
    ) -> Result<Vec<u8>, RootlessOciBuildError> {
        self.validate(request)?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(
        bytes: &[u8],
        request: &RootlessOciBuildRequestV1,
    ) -> Result<Self, RootlessOciBuildError> {
        if bytes.is_empty() || bytes.len() > usize::try_from(MAX_RESULT_BYTES).unwrap_or(usize::MAX)
        {
            return Err(RootlessOciBuildError::InvalidResult);
        }
        let result: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&result)? != bytes {
            return Err(RootlessOciBuildError::NoncanonicalResult);
        }
        result.validate(request)?;
        Ok(result)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, RootlessOciBuildError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &RootlessOciBuildResultPayload {
                purpose: RESULT_PURPOSE,
                schema_version: self.schema_version,
                request_digest: &self.request_digest,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                image_manifest_digest: &self.image_manifest_digest,
                image_config_digest: &self.image_config_digest,
                archive_digest: &self.archive_digest,
                archive_bytes: self.archive_bytes,
                verified_output_digest: &self.verified_output_digest,
            },
        )?))
    }
}

#[derive(Debug)]
pub struct ValidatedRootlessOciBuildOutputV1 {
    pub result: RootlessOciBuildResultV1,
    pub archive: File,
}

pub fn buildctl_arguments(
    request: &RootlessOciBuildRequestV1,
) -> Result<Vec<String>, RootlessOciBuildError> {
    request.validate()?;
    let mut arguments = vec![
        format!("--addr=unix://{ROOTLESS_OCI_BUILD_SOCKET_PATH}"),
        "build".to_owned(),
        "--frontend=dockerfile.v0".to_owned(),
        format!("--local=context={ROOTLESS_OCI_BUILD_PREPARED_ROOT}"),
        format!("--local=dockerfile={ROOTLESS_OCI_BUILD_PREPARED_ROOT}"),
        format!("--opt=filename={}", request.dockerfile_path),
        format!("--opt=platform={}", request.platform),
    ];
    if let Some(target) = &request.target {
        arguments.push(format!("--opt=target={target}"));
    }
    for argument in &request.build_args {
        arguments.push(format!(
            "--opt=build-arg:{}={}",
            argument.key, argument.value
        ));
    }
    for input in &request.base_inputs {
        arguments.push(format!(
            "--oci-layout={}={ROOTLESS_OCI_BUILD_DEPENDENCY_ROOT}/{}",
            input.layout_name, input.dependency_path
        ));
        arguments.push(format!(
            "--opt=context:{}=oci-layout://{}@{}",
            input.source,
            input.layout_name,
            input.manifest_digest.as_str()
        ));
    }
    for input in &request.local_inputs {
        arguments.push(format!(
            "--local={}={ROOTLESS_OCI_BUILD_TOOLCHAIN_ROOT}/{}",
            input.local_name, input.toolchain_path
        ));
        arguments.push(format!(
            "--opt=context:{}=local:{}",
            input.source, input.local_name
        ));
    }
    if let Some(output) = &request.verified_output {
        arguments.push(format!(
            "--local={}={ROOTLESS_OCI_BUILD_OPERATION_ROOT}/{}",
            output.context_name,
            output.directory.as_str()
        ));
        arguments.push(format!(
            "--opt=context:{}=local:{}",
            output.context_name, output.context_name
        ));
    }
    arguments.push(format!(
        "--output=type=oci,dest={ROOTLESS_OCI_BUILD_OUTPUT_ROOT}/{RESULT_ARCHIVE_FILE},name=rdashboard.local/{}:{}",
        request.project_id,
        request.source_sha
    ));
    arguments.push(format!(
        "--metadata-file={ROOTLESS_OCI_BUILD_OUTPUT_ROOT}/{BUILDKIT_METADATA_FILE}"
    ));
    Ok(arguments)
}

pub fn execute_installed_rootless_oci_build()
-> Result<RootlessOciBuildResultV1, RootlessOciBuildError> {
    execute_rootless_oci_build(
        Path::new(ROOTLESS_OCI_BUILD_REQUEST_PATH),
        Path::new(ROOTLESS_OCI_BUILD_PREPARED_ROOT),
        Path::new(ROOTLESS_OCI_BUILD_DEPENDENCY_ROOT),
        Path::new(ROOTLESS_OCI_BUILD_TOOLCHAIN_ROOT),
        Path::new(ROOTLESS_OCI_BUILD_OPERATION_ROOT),
        Path::new(ROOTLESS_OCI_BUILD_OUTPUT_ROOT),
        Path::new(BUILDCTL_EXECUTABLE),
    )
}

fn execute_rootless_oci_build(
    request_path: &Path,
    prepared_root: &Path,
    dependency_root: &Path,
    toolchain_root: &Path,
    operation_root: &Path,
    output_root: &Path,
    buildctl: &Path,
) -> Result<RootlessOciBuildResultV1, RootlessOciBuildError> {
    validate_read_only_directory(prepared_root)?;
    validate_read_only_directory(dependency_root)?;
    validate_empty_output_directory(output_root)?;
    let request_bytes = read_stable_file(
        request_path,
        0,
        SANDBOX_REQUEST_FILE_MODE,
        MAX_REQUEST_BYTES,
    )?;
    let request = RootlessOciBuildRequestV1::decode_canonical(&request_bytes)?;
    validate_dockerfile_frontend(prepared_root, &request.dockerfile_path)?;
    for input in &request.base_inputs {
        let layout = dependency_root.join(&input.dependency_path);
        validate_read_only_directory(&layout)?;
        validate_oci_layout(&layout, input.manifest_digest.as_str())
            .map_err(|_| RootlessOciBuildError::UnsafeInput)?;
    }
    for input in &request.local_inputs {
        validate_root_owned_read_only_subdirectory(toolchain_root, &input.toolchain_path)?;
    }
    let verified_before = request
        .verified_output
        .as_ref()
        .map(|output| verified_output_digest(operation_root, output))
        .transpose()?;
    let arguments = buildctl_arguments(&request)?;
    let status = Command::new(buildctl)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(RootlessOciBuildError::BuildctlRejected);
    }
    let verified_after = request
        .verified_output
        .as_ref()
        .map(|output| verified_output_digest(operation_root, output))
        .transpose()?;
    if verified_before != verified_after {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    let metadata_path = output_root.join(BUILDKIT_METADATA_FILE);
    let metadata = read_bounded_file(&metadata_path, MAX_METADATA_BYTES)?;
    let (manifest_digest, config_digest) = parse_buildkit_metadata(&metadata)?;
    let archive_path = output_root.join(RESULT_ARCHIVE_FILE);
    let archive = open_output_archive(&archive_path, request.max_archive_bytes)?;
    let (archive_digest, archive_bytes) = validate_oci_archive(
        &archive,
        request.max_archive_bytes,
        &manifest_digest,
        &config_digest,
    )?;
    let result = RootlessOciBuildResultV1::new(
        &request,
        manifest_digest,
        config_digest,
        archive_digest,
        archive_bytes,
        verified_after,
    )?;
    fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o400))?;
    write_new_read_only_file(
        &output_root.join(RESULT_REQUEST_FILE),
        &request.canonical_bytes()?,
    )?;
    write_new_read_only_file(
        &output_root.join(RESULT_DOCUMENT_FILE),
        &result.canonical_bytes(&request)?,
    )?;
    fs::remove_file(metadata_path)?;
    File::open(output_root)?.sync_all()?;
    let _ = validate_rootless_oci_build_output(output_root, &request, None)?;
    Ok(result)
}

pub fn validate_rootless_oci_build_output(
    output_root: &Path,
    expected_request: &RootlessOciBuildRequestV1,
    expected_owner: Option<(u32, u32)>,
) -> Result<ValidatedRootlessOciBuildOutputV1, RootlessOciBuildError> {
    expected_request.validate()?;
    validate_output_directory(output_root, expected_owner)?;
    let request_bytes = read_output_file(
        &output_root.join(RESULT_REQUEST_FILE),
        expected_owner,
        MAX_REQUEST_BYTES,
    )?;
    let request = RootlessOciBuildRequestV1::decode_canonical(&request_bytes)?;
    if request != *expected_request {
        return Err(RootlessOciBuildError::RequestMismatch);
    }
    let result_bytes = read_output_file(
        &output_root.join(RESULT_DOCUMENT_FILE),
        expected_owner,
        MAX_RESULT_BYTES,
    )?;
    let result = RootlessOciBuildResultV1::decode_canonical(&result_bytes, &request)?;
    let archive = open_validated_output_archive(
        &output_root.join(RESULT_ARCHIVE_FILE),
        expected_owner,
        result.archive_bytes,
    )?;
    let (archive_digest, archive_bytes) = validate_oci_archive(
        &archive,
        request.max_archive_bytes,
        &result.image_manifest_digest,
        &result.image_config_digest,
    )?;
    if archive_digest != result.archive_digest || archive_bytes != result.archive_bytes {
        return Err(RootlessOciBuildError::ArchiveBinding);
    }
    let names = fs::read_dir(output_root)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [
        OsStr::new(RESULT_ARCHIVE_FILE).to_owned(),
        OsStr::new(RESULT_DOCUMENT_FILE).to_owned(),
        OsStr::new(RESULT_REQUEST_FILE).to_owned(),
    ]
    .into_iter()
    .collect();
    if names != expected {
        return Err(RootlessOciBuildError::UnsafeOutput);
    }
    Ok(ValidatedRootlessOciBuildOutputV1 { result, archive })
}

#[derive(Debug, Deserialize)]
struct OciIndex {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    manifests: Vec<OciDescriptor>,
}

#[derive(Debug, Deserialize)]
struct OciManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Debug, Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: OciDigest,
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

#[derive(Debug)]
struct BlobEvidence {
    bytes: u64,
    json: Option<Vec<u8>>,
}

#[allow(clippy::too_many_lines)]
fn validate_oci_archive(
    archive: &File,
    max_bytes: u64,
    manifest_digest: &OciDigest,
    config_digest: &OciDigest,
) -> Result<(EvidenceDigest, u64), RootlessOciBuildError> {
    let metadata = archive.metadata()?;
    if !metadata.is_file()
        || metadata.len() < MIN_ARCHIVE_BYTES
        || metadata.len() > max_bytes
        || metadata.nlink() != 1
    {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let archive_digest = hash_file(archive, metadata.len())?;
    let mut reader = archive.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut tar = tar::Archive::new(reader);
    let mut paths = BTreeSet::new();
    let mut blobs = BTreeMap::new();
    let mut layout = None;
    let mut index = None;
    let mut entry_count = 0_usize;
    for item in tar
        .entries()
        .map_err(|_| RootlessOciBuildError::ArchiveInvalid)?
    {
        let mut entry = item.map_err(|_| RootlessOciBuildError::ArchiveInvalid)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or(RootlessOciBuildError::ArchiveInvalid)?;
        if entry_count > MAX_OCI_ENTRIES {
            return Err(RootlessOciBuildError::ArchiveInvalid);
        }
        let path = entry
            .path()
            .map_err(|_| RootlessOciBuildError::ArchiveInvalid)?
            .into_owned();
        validate_archive_path(&path)?;
        if !paths.insert(path.clone()) {
            return Err(RootlessOciBuildError::ArchiveInvalid);
        }
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(RootlessOciBuildError::ArchiveInvalid);
        }
        let declared = entry.size();
        let rendered = path.to_str().ok_or(RootlessOciBuildError::ArchiveInvalid)?;
        if rendered == "oci-layout" {
            layout = Some(read_tar_json(&mut entry, declared)?);
            continue;
        }
        if rendered == "index.json" {
            index = Some(read_tar_json(&mut entry, declared)?);
            continue;
        }
        if let Some(hex) = rendered.strip_prefix("blobs/sha256/") {
            if hex.len() != 64
                || !hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(RootlessOciBuildError::ArchiveInvalid);
            }
            let mut hasher = Sha256::new();
            let mut json = (declared <= MAX_OCI_JSON_BYTES).then(Vec::new);
            let mut buffer = vec![0_u8; 128 * 1024].into_boxed_slice();
            let mut read = 0_u64;
            loop {
                let bytes = entry.read(&mut buffer)?;
                if bytes == 0 {
                    break;
                }
                read = read
                    .checked_add(
                        u64::try_from(bytes).map_err(|_| RootlessOciBuildError::ArchiveInvalid)?,
                    )
                    .ok_or(RootlessOciBuildError::ArchiveInvalid)?;
                hasher.update(&buffer[..bytes]);
                if let Some(document) = &mut json {
                    document.extend_from_slice(&buffer[..bytes]);
                }
            }
            if read != declared || format!("{:x}", hasher.finalize()) != hex {
                return Err(RootlessOciBuildError::ArchiveBinding);
            }
            blobs.insert(
                format!("sha256:{hex}"),
                BlobEvidence {
                    bytes: declared,
                    json,
                },
            );
            continue;
        }
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let mut trailing = tar.into_inner();
    let mut tail = [0_u8; 8192];
    loop {
        let bytes = trailing.read(&mut tail)?;
        if bytes == 0 {
            break;
        }
        if tail[..bytes].iter().any(|byte| *byte != 0) {
            return Err(RootlessOciBuildError::ArchiveInvalid);
        }
    }
    let layout: OciLayout = serde_json::from_slice(
        layout
            .as_deref()
            .ok_or(RootlessOciBuildError::ArchiveInvalid)?,
    )
    .map_err(|_| RootlessOciBuildError::ArchiveInvalid)?;
    if layout.image_layout_version != "1.0.0" {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let index: OciIndex = serde_json::from_slice(
        index
            .as_deref()
            .ok_or(RootlessOciBuildError::ArchiveInvalid)?,
    )
    .map_err(|_| RootlessOciBuildError::ArchiveInvalid)?;
    if index.schema_version != 2 || index.manifests.is_empty() || index.manifests.len() > 64 {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let descriptor = index
        .manifests
        .iter()
        .find(|descriptor| descriptor.digest == *manifest_digest)
        .ok_or(RootlessOciBuildError::ArchiveBinding)?;
    validate_descriptor(descriptor, &blobs)?;
    if !matches!(
        descriptor.media_type.as_str(),
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
    ) {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let manifest_blob = blobs
        .get(manifest_digest.as_str())
        .and_then(|blob| blob.json.as_deref())
        .ok_or(RootlessOciBuildError::ArchiveInvalid)?;
    let manifest: OciManifest =
        serde_json::from_slice(manifest_blob).map_err(|_| RootlessOciBuildError::ArchiveInvalid)?;
    if manifest.schema_version != 2
        || manifest.config.digest != *config_digest
        || manifest.layers.len() > MAX_OCI_ENTRIES
    {
        return Err(RootlessOciBuildError::ArchiveBinding);
    }
    validate_descriptor(&manifest.config, &blobs)?;
    for layer in &manifest.layers {
        validate_descriptor(layer, &blobs)?;
    }
    Ok((archive_digest, metadata.len()))
}

fn validate_descriptor(
    descriptor: &OciDescriptor,
    blobs: &BTreeMap<String, BlobEvidence>,
) -> Result<(), RootlessOciBuildError> {
    if descriptor.media_type.is_empty() || descriptor.media_type.len() > 256 {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let blob = blobs
        .get(descriptor.digest.as_str())
        .ok_or(RootlessOciBuildError::ArchiveBinding)?;
    if blob.bytes != descriptor.size {
        return Err(RootlessOciBuildError::ArchiveBinding);
    }
    Ok(())
}

fn read_tar_json<R: Read>(reader: &mut R, declared: u64) -> Result<Vec<u8>, RootlessOciBuildError> {
    if declared == 0 || declared > MAX_OCI_JSON_BYTES {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(declared).map_err(|_| RootlessOciBuildError::ArchiveInvalid)?,
    );
    reader
        .take(declared.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(declared) {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    Ok(bytes)
}

fn validate_archive_path(path: &Path) -> Result<(), RootlessOciBuildError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_OCI_PATH_BYTES
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    Ok(())
}

fn parse_buildkit_metadata(bytes: &[u8]) -> Result<(OciDigest, OciDigest), RootlessOciBuildError> {
    let metadata: serde_json::Value = serde_json::from_slice(bytes)?;
    let object = metadata
        .as_object()
        .ok_or(RootlessOciBuildError::InvalidBuildMetadata)?;
    let manifest = object
        .get("containerimage.digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(RootlessOciBuildError::InvalidBuildMetadata)?
        .parse()
        .map_err(|_| RootlessOciBuildError::InvalidBuildMetadata)?;
    let config = object
        .get("containerimage.config.digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(RootlessOciBuildError::InvalidBuildMetadata)?
        .parse()
        .map_err(|_| RootlessOciBuildError::InvalidBuildMetadata)?;
    Ok((manifest, config))
}

#[derive(Clone, Copy, Debug)]
struct ResultFilesystemSnapshot {
    shared_storage_domain: bool,
    total_bytes: u64,
    available_bytes: u64,
    host_available_bytes: u64,
    total_inodes: u64,
    available_inodes: u64,
}

trait ResultFilesystemProbe: Send + Sync {
    fn inspect(&self, root: &File) -> Result<ResultFilesystemSnapshot, RootlessOciBuildError>;
}

#[derive(Debug)]
struct InstalledResultFilesystemProbe {
    root: PathBuf,
}

impl ResultFilesystemProbe for InstalledResultFilesystemProbe {
    fn inspect(&self, root: &File) -> Result<ResultFilesystemSnapshot, RootlessOciBuildError> {
        let stats = rustix::fs::fstatvfs(root).map_err(io::Error::from)?;
        let fragment = if stats.f_frsize == 0 {
            stats.f_bsize
        } else {
            stats.f_frsize
        };
        let shared_root = Path::new(SHARED_BUILD_STORAGE_ROOT);
        let host = fs2::statvfs("/")?;
        let result_metadata = fs::metadata(&self.root)?;
        let shared_metadata = fs::metadata(shared_root)?;
        Ok(ResultFilesystemSnapshot {
            shared_storage_domain: result_metadata.dev() == shared_metadata.dev(),
            total_bytes: stats.f_blocks.saturating_mul(fragment),
            available_bytes: stats.f_bavail.saturating_mul(fragment),
            host_available_bytes: host.available_space(),
            total_inodes: stats.f_files,
            available_inodes: stats.f_favail,
        })
    }
}

pub struct RootlessOciResultStoreV1 {
    root: PathBuf,
    trusted_uid: u32,
    trusted_gid: u32,
    build_uid: u32,
    build_gid: u32,
    root_handle: File,
    operation_lock: Mutex<()>,
    probe: Box<dyn ResultFilesystemProbe>,
}

impl RootlessOciResultStoreV1 {
    pub fn staging_path_for(request: &RootlessOciBuildRequestV1) -> PathBuf {
        Path::new(ROOTLESS_OCI_RESULT_STORE_ROOT).join(format!(
            ".staging-{}-g{}",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    pub fn request_path_for(request: &RootlessOciBuildRequestV1) -> PathBuf {
        Path::new(ROOTLESS_OCI_RESULT_STORE_ROOT).join(format!(
            ".request-{}-g{}.jcs",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    pub fn open_installed(job_uid: u32, job_group: u32) -> Result<Self, RootlessOciBuildError> {
        let root = PathBuf::from(ROOTLESS_OCI_RESULT_STORE_ROOT);
        Self::open_with_probe(
            root.clone(),
            0,
            0,
            job_uid,
            job_group,
            Box::new(InstalledResultFilesystemProbe { root }),
        )
    }

    #[allow(clippy::similar_names)]
    fn open_with_probe(
        root: PathBuf,
        trusted_uid: u32,
        trusted_gid: u32,
        job_uid: u32,
        job_group: u32,
        probe: Box<dyn ResultFilesystemProbe>,
    ) -> Result<Self, RootlessOciBuildError> {
        if trusted_uid == u32::MAX
            || trusted_gid == u32::MAX
            || job_uid == 0
            || job_uid == u32::MAX
            || job_group == 0
            || job_group == u32::MAX
        {
            return Err(RootlessOciBuildError::InvalidStore);
        }
        validate_owned_directory(&root, trusted_uid, trusted_gid, 0o700)?;
        let root_handle = File::open(&root)?;
        fs2::FileExt::try_lock_exclusive(&root_handle).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                RootlessOciBuildError::StoreAlreadyOpen
            } else {
                RootlessOciBuildError::Io(error)
            }
        })?;
        let store = Self {
            root,
            trusted_uid,
            trusted_gid,
            build_uid: job_uid,
            build_gid: job_group,
            root_handle,
            operation_lock: Mutex::new(()),
            probe,
        };
        store.verify_boundary()?;
        store.reconcile()?;
        Ok(store)
    }

    pub fn prepare(
        &self,
        request: &RootlessOciBuildRequestV1,
    ) -> Result<PathBuf, RootlessOciBuildError> {
        request.validate()?;
        let _guard = self.lock()?;
        self.revalidate()?;
        self.verify_boundary()?;
        self.remove_project_result(&request.project_id)?;
        let snapshot = self.probe.inspect(&self.root_handle)?;
        let incoming = request
            .max_archive_bytes
            .checked_add(MIN_STORE_HEADROOM_BYTES)
            .and_then(|bytes| bytes.checked_add(BUILDKIT_MAX_USED_BYTES))
            .ok_or(RootlessOciBuildError::StoreCapacityExceeded)?;
        let required = required_host_available_bytes(incoming)
            .ok_or(RootlessOciBuildError::StoreCapacityExceeded)?;
        if snapshot.available_bytes < incoming
            || snapshot.host_available_bytes < required
            || snapshot.available_inodes < 16
        {
            return Err(RootlessOciBuildError::StoreCapacityExceeded);
        }
        let staging = self.staging_path(request);
        if staging.try_exists()? {
            validate_cleanup_directory(&staging, self.build_uid)?;
            remove_tree(&staging)?;
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&staging)?;
        std::os::unix::fs::chown(&staging, Some(self.build_uid), Some(self.build_gid))?;
        validate_owned_directory(&staging, self.build_uid, self.build_gid, 0o700)?;
        let request_path = self.request_path(request);
        if request_path.try_exists()? {
            validate_owned_regular_file(
                &request_path,
                self.trusted_uid,
                self.trusted_gid,
                SANDBOX_REQUEST_FILE_MODE,
                MAX_REQUEST_BYTES,
            )?;
            fs::remove_file(&request_path)?;
        }
        write_new_trusted_read_only_file(
            &request_path,
            &request.canonical_bytes()?,
            self.trusted_uid,
            self.trusted_gid,
        )?;
        self.root_handle.sync_all()?;
        Ok(staging)
    }

    pub fn promote(
        &self,
        request: &RootlessOciBuildRequestV1,
    ) -> Result<RootlessOciBuildResultV1, RootlessOciBuildError> {
        request.validate()?;
        let _guard = self.lock()?;
        self.revalidate()?;
        self.verify_boundary()?;
        let staging = self.staging_path(request);
        let validated = validate_rootless_oci_build_output(
            &staging,
            request,
            Some((self.build_uid, self.build_gid)),
        )?;
        drop(validated.archive);
        make_tree_trusted_private(&staging, self.build_uid, self.trusted_uid, self.trusted_gid)?;
        let final_path = self.root.join(request.project_id.as_str());
        let deleting = self.root.join(format!(
            ".deleting-{}-{}",
            request.project_id,
            Uuid::new_v4().simple()
        ));
        if final_path.try_exists()? {
            validate_project_result_directory(
                &final_path,
                &request.project_id,
                self.trusted_uid,
                self.trusted_gid,
            )?;
            fs::rename(&final_path, &deleting)?;
            self.root_handle.sync_all()?;
        }
        fs::rename(&staging, &final_path)?;
        self.root_handle.sync_all()?;
        if deleting.try_exists()? {
            remove_tree(&deleting)?;
        }
        let request_path = self.request_path(request);
        validate_owned_regular_file(
            &request_path,
            self.trusted_uid,
            self.trusted_gid,
            SANDBOX_REQUEST_FILE_MODE,
            MAX_REQUEST_BYTES,
        )?;
        fs::remove_file(request_path)?;
        self.root_handle.sync_all()?;
        let promoted = validate_rootless_oci_build_output(
            &final_path,
            request,
            Some((self.trusted_uid, self.trusted_gid)),
        )?;
        Ok(promoted.result)
    }

    pub fn discard(
        &self,
        request: &RootlessOciBuildRequestV1,
    ) -> Result<(), RootlessOciBuildError> {
        let _guard = self.lock()?;
        self.revalidate()?;
        let staging = self.staging_path(request);
        if staging.try_exists()? {
            validate_cleanup_directory(&staging, self.build_uid)?;
            remove_tree(&staging)?;
            self.root_handle.sync_all()?;
        }
        let request_path = self.request_path(request);
        if request_path.try_exists()? {
            validate_owned_regular_file(
                &request_path,
                self.trusted_uid,
                self.trusted_gid,
                SANDBOX_REQUEST_FILE_MODE,
                MAX_REQUEST_BYTES,
            )?;
            fs::remove_file(request_path)?;
            self.root_handle.sync_all()?;
        }
        Ok(())
    }

    fn staging_path(&self, request: &RootlessOciBuildRequestV1) -> PathBuf {
        self.root.join(format!(
            ".staging-{}-g{}",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    fn request_path(&self, request: &RootlessOciBuildRequestV1) -> PathBuf {
        self.root.join(format!(
            ".request-{}-g{}.jcs",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    fn remove_project_result(&self, project_id: &ProjectId) -> Result<(), RootlessOciBuildError> {
        let path = self.root.join(project_id.as_str());
        if !path.try_exists()? {
            return Ok(());
        }
        validate_project_result_directory(&path, project_id, self.trusted_uid, self.trusted_gid)?;
        let deleting = self.root.join(format!(
            ".deleting-{}-{}",
            project_id,
            Uuid::new_v4().simple()
        ));
        fs::rename(&path, &deleting)?;
        self.root_handle.sync_all()?;
        remove_tree(&deleting)
    }

    fn reconcile(&self) -> Result<(), RootlessOciBuildError> {
        let _guard = self.lock()?;
        self.revalidate()?;
        let entries = fs::read_dir(&self.root)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > MAX_STORE_ENTRIES {
            return Err(RootlessOciBuildError::InvalidStore);
        }
        for entry in entries {
            let name = entry.file_name();
            let rendered = name.to_str().ok_or(RootlessOciBuildError::InvalidStore)?;
            if rendered.starts_with(".request-")
                && rendered.as_bytes().strip_suffix(b".jcs").is_some()
            {
                validate_owned_regular_file(
                    &entry.path(),
                    self.trusted_uid,
                    self.trusted_gid,
                    SANDBOX_REQUEST_FILE_MODE,
                    MAX_REQUEST_BYTES,
                )?;
                fs::remove_file(entry.path())?;
                continue;
            }
            if rendered.starts_with(".staging-") || rendered.starts_with(".deleting-") {
                validate_cleanup_directory(&entry.path(), self.build_uid)?;
                remove_tree(&entry.path())?;
                continue;
            }
            let project_id: ProjectId = rendered
                .parse()
                .map_err(|_| RootlessOciBuildError::InvalidStore)?;
            validate_project_result_directory(
                &entry.path(),
                &project_id,
                self.trusted_uid,
                self.trusted_gid,
            )?;
        }
        self.root_handle.sync_all()?;
        Ok(())
    }

    fn verify_boundary(&self) -> Result<(), RootlessOciBuildError> {
        let snapshot = self.probe.inspect(&self.root_handle)?;
        if !snapshot.shared_storage_domain
            || snapshot.total_bytes < SHARED_BUILD_STORAGE_MIN_BYTES
            || snapshot.total_inodes == 0
            || snapshot.available_bytes > snapshot.total_bytes
            || snapshot.available_inodes > snapshot.total_inodes
        {
            return Err(RootlessOciBuildError::InvalidStoreBoundary);
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<(), RootlessOciBuildError> {
        validate_opened_directory(
            &self.root,
            &self.root_handle,
            self.trusted_uid,
            self.trusted_gid,
            0o700,
        )
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, RootlessOciBuildError> {
        self.operation_lock
            .lock()
            .map_err(|_| RootlessOciBuildError::StoreLockPoisoned)
    }
}

impl Drop for RootlessOciResultStoreV1 {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.root_handle);
    }
}

#[allow(clippy::similar_names)]
fn validate_project_result_directory(
    path: &Path,
    project_id: &ProjectId,
    trusted_uid: u32,
    trusted_gid: u32,
) -> Result<(), RootlessOciBuildError> {
    if path.file_name() != Some(OsStr::new(project_id.as_str())) {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    validate_owned_directory(path, trusted_uid, trusted_gid, 0o700)?;
    let names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [
        OsStr::new(RESULT_ARCHIVE_FILE).to_owned(),
        OsStr::new(RESULT_DOCUMENT_FILE).to_owned(),
        OsStr::new(RESULT_REQUEST_FILE).to_owned(),
    ]
    .into_iter()
    .collect();
    if names != expected {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    for name in names {
        validate_owned_regular_file(
            &path.join(name),
            trusted_uid,
            trusted_gid,
            0o400,
            MAX_ARCHIVE_BYTES,
        )?;
    }
    Ok(())
}

#[allow(clippy::similar_names)]
fn make_tree_trusted_private(
    path: &Path,
    build_uid: u32,
    trusted_uid: u32,
    trusted_gid: u32,
) -> Result<(), RootlessOciBuildError> {
    validate_cleanup_directory(path, build_uid)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != build_uid
            || metadata.nlink() != 1
        {
            return Err(RootlessOciBuildError::UnsafeOutput);
        }
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o400))?;
        std::os::unix::fs::chown(entry.path(), Some(trusted_uid), Some(trusted_gid))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::chown(path, Some(trusted_uid), Some(trusted_gid))?;
    validate_owned_directory(path, trusted_uid, trusted_gid, 0o700)
}

fn validate_cleanup_directory(path: &Path, build_uid: u32) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !matches!(metadata.uid(), uid if uid == 0 || uid == build_uid)
        || metadata.nlink() < 2
    {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    Ok(())
}

fn remove_tree(root: &Path) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    let mut directories = vec![(root.to_owned(), false)];
    while let Some((path, visited)) = directories.pop() {
        if visited {
            fs::remove_dir(path)?;
            continue;
        }
        directories.push((path.clone(), true));
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(RootlessOciBuildError::InvalidStore);
            }
            if metadata.is_dir() {
                directories.push((entry.path(), false));
            } else if metadata.is_file() && metadata.nlink() == 1 {
                fs::remove_file(entry.path())?;
            } else {
                return Err(RootlessOciBuildError::InvalidStore);
            }
        }
    }
    Ok(())
}

fn validate_empty_output_directory(path: &Path) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || fs::read_dir(path)?.next().is_some()
    {
        return Err(RootlessOciBuildError::UnsafeOutput);
    }
    Ok(())
}

fn validate_output_directory(
    path: &Path,
    expected_owner: Option<(u32, u32)>,
) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || expected_owner.is_some_and(|(uid, gid)| metadata.uid() != uid || metadata.gid() != gid)
    {
        return Err(RootlessOciBuildError::UnsafeOutput);
    }
    Ok(())
}

fn read_output_file(
    path: &Path,
    expected_owner: Option<(u32, u32)>,
    max_bytes: u64,
) -> Result<Vec<u8>, RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || expected_owner.is_some_and(|(uid, gid)| metadata.uid() != uid || metadata.gid() != gid)
    {
        return Err(RootlessOciBuildError::UnsafeOutput);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file(&metadata, &opened) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if !same_file(&opened, &final_metadata) || u64::try_from(bytes.len()).ok() != Some(opened.len())
    {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    Ok(bytes)
}

fn open_validated_output_archive(
    path: &Path,
    expected_owner: Option<(u32, u32)>,
    expected_bytes: u64,
) -> Result<File, RootlessOciBuildError> {
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || named.nlink() != 1
        || named.permissions().mode() & 0o7777 != 0o400
        || named.len() != expected_bytes
        || expected_owner.is_some_and(|(uid, gid)| named.uid() != uid || named.gid() != gid)
    {
        return Err(RootlessOciBuildError::UnsafeOutput);
    }
    let file = File::open(path)?;
    if !same_file(&named, &file.metadata()?) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    Ok(file)
}

fn open_output_archive(path: &Path, max_bytes: u64) -> Result<File, RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() < MIN_ARCHIVE_BYTES
        || metadata.len() > max_bytes
    {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let file = File::open(path)?;
    if !same_file(&metadata, &file.metadata()?) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    Ok(file)
}

fn write_new_read_only_file(path: &Path, bytes: &[u8]) -> Result<(), RootlessOciBuildError> {
    write_new_file_with_mode(path, bytes, 0o400)
}

fn write_new_file_with_mode(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), RootlessOciBuildError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[allow(clippy::similar_names)]
fn write_new_trusted_read_only_file(
    path: &Path,
    bytes: &[u8],
    trusted_uid: u32,
    trusted_gid: u32,
) -> Result<(), RootlessOciBuildError> {
    write_new_file_with_mode(path, bytes, SANDBOX_REQUEST_FILE_MODE)?;
    validate_owned_regular_file(
        path,
        trusted_uid,
        trusted_gid,
        SANDBOX_REQUEST_FILE_MODE,
        MAX_REQUEST_BYTES,
    )
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(RootlessOciBuildError::InvalidBuildMetadata);
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    Ok(bytes)
}

fn read_stable_file(
    path: &Path,
    expected_uid: u32,
    expected_mode: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, RootlessOciBuildError> {
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || named.uid() != expected_uid
        || named.permissions().mode() & 0o7777 != expected_mode
        || named.nlink() != 1
        || named.len() == 0
        || named.len() > max_bytes
    {
        return Err(RootlessOciBuildError::UnsafeRequest);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file(&named, &opened) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(opened.len())
        || !same_file(&opened, &fs::symlink_metadata(path)?)
    {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    Ok(bytes)
}

fn validate_read_only_directory(path: &Path) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err(RootlessOciBuildError::UnsafeInput);
    }
    Ok(())
}

fn validate_root_owned_read_only_directory(path: &Path) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(RootlessOciBuildError::UnsafeInput);
    }
    Ok(())
}

fn validate_root_owned_read_only_subdirectory(
    root: &Path,
    relative: &str,
) -> Result<(), RootlessOciBuildError> {
    if !valid_relative_path(relative) {
        return Err(RootlessOciBuildError::UnsafeInput);
    }
    validate_root_owned_read_only_directory(root)?;
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(segment) = component else {
            return Err(RootlessOciBuildError::UnsafeInput);
        };
        current.push(segment);
        validate_root_owned_read_only_directory(&current)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct VerifiedOutputInventoryV1 {
    purpose: &'static str,
    entries: Vec<VerifiedOutputEntryV1>,
}

#[derive(Serialize)]
struct VerifiedOutputEntryV1 {
    path: String,
    mode: u32,
    bytes: u64,
    sha256: EvidenceDigest,
}

fn verified_output_digest(
    operation_root: &Path,
    policy: &VerifiedOciOutputPolicy,
) -> Result<EvidenceDigest, RootlessOciBuildError> {
    if !policy.validate() {
        return Err(RootlessOciBuildError::InvalidPolicy);
    }
    let root = operation_root.join(policy.directory.as_str());
    validate_read_only_directory(&root)?;
    let entries = inspect_verified_output(&root, policy)?;
    if entries.is_empty() {
        return Err(RootlessOciBuildError::UnsafeInput);
    }
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &VerifiedOutputInventoryV1 {
            purpose: "rdashboard.verified-oci-output.v1",
            entries,
        },
    )?))
}

fn inspect_verified_output(
    root: &Path,
    policy: &VerifiedOciOutputPolicy,
) -> Result<Vec<VerifiedOutputEntryV1>, RootlessOciBuildError> {
    let maximum_files =
        usize::try_from(policy.max_files).map_err(|_| RootlessOciBuildError::UnsafeInput)?;
    let mut children = Vec::new();
    for child in fs::read_dir(root)? {
        if children.len() >= maximum_files {
            return Err(RootlessOciBuildError::UnsafeInput);
        }
        children.push(child?);
    }
    children.sort_by_key(std::fs::DirEntry::file_name);
    let mut entries = Vec::with_capacity(children.len());
    let mut bytes = 0_u64;
    for child in children {
        let path = child.path();
        let named = fs::symlink_metadata(&path)?;
        if named.file_type().is_symlink()
            || !named.is_file()
            || named.nlink() != 1
            || !matches!(named.permissions().mode() & 0o7777, 0o444 | 0o555)
        {
            return Err(RootlessOciBuildError::UnsafeInput);
        }
        bytes = bytes
            .checked_add(named.len())
            .ok_or(RootlessOciBuildError::UnsafeInput)?;
        if bytes > policy.max_bytes {
            return Err(RootlessOciBuildError::UnsafeInput);
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RootlessOciBuildError::UnsafeInput)?
            .to_str()
            .ok_or(RootlessOciBuildError::UnsafeInput)?
            .to_owned();
        if !valid_relative_path(&relative) {
            return Err(RootlessOciBuildError::UnsafeInput);
        }
        let file = File::open(&path)?;
        let opened = file.metadata()?;
        let sha256 = hash_file(&file, opened.len())?;
        if !same_file(&named, &opened) || !same_file(&opened, &fs::symlink_metadata(&path)?) {
            return Err(RootlessOciBuildError::ConcurrentChange);
        }
        entries.push(VerifiedOutputEntryV1 {
            path: relative,
            mode: named.permissions().mode() & 0o7777,
            bytes: named.len(),
            sha256,
        });
    }
    Ok(entries)
}

fn validate_dockerfile_frontend(
    prepared_root: &Path,
    dockerfile_path: &str,
) -> Result<(), RootlessOciBuildError> {
    let path = prepared_root.join(dockerfile_path);
    let named = fs::symlink_metadata(&path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || named.nlink() != 1
        || !matches!(named.permissions().mode() & 0o7777, 0o444 | 0o555)
        || named.len() == 0
        || named.len() > MAX_DOCKERFILE_BYTES
    {
        return Err(RootlessOciBuildError::UnsafeInput);
    }
    let file = File::open(&path)?;
    let opened = file.metadata()?;
    if !same_file(&named, &opened) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(MAX_DOCKERFILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(opened.len())
        || !same_file(&opened, &fs::symlink_metadata(path)?)
    {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(comment) = line
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .and_then(|offset| line.get(offset..))
            .and_then(|trimmed| trimmed.strip_prefix(b"#"))
        else {
            continue;
        };
        let directive = comment
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .and_then(|offset| comment.get(offset..))
            .unwrap_or_default();
        if directive
            .get(..7)
            .is_some_and(|key| key.eq_ignore_ascii_case(b"syntax="))
        {
            return Err(RootlessOciBuildError::UnsupportedDockerfileFrontend);
        }
    }
    Ok(())
}

fn validate_owned_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    Ok(())
}

fn validate_opened_directory(
    path: &Path,
    opened: &File,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), RootlessOciBuildError> {
    let named = fs::symlink_metadata(path)?;
    let actual = opened.metadata()?;
    if !same_file(&named, &actual)
        || named.uid() != uid
        || named.gid() != gid
        || named.permissions().mode() & 0o7777 != mode
        || !named.is_dir()
    {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    Ok(())
}

fn validate_owned_regular_file(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    max_bytes: u64,
) -> Result<(), RootlessOciBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(RootlessOciBuildError::InvalidStore);
    }
    Ok(())
}

fn hash_file(file: &File, expected_bytes: u64) -> Result<EvidenceDigest, RootlessOciBuildError> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() != expected_bytes {
        return Err(RootlessOciBuildError::ArchiveInvalid);
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024].into_boxed_slice();
    let mut read = 0_u64;
    loop {
        let bytes = reader.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        read = read
            .checked_add(u64::try_from(bytes).map_err(|_| RootlessOciBuildError::ArchiveInvalid)?)
            .ok_or(RootlessOciBuildError::ArchiveInvalid)?;
        hasher.update(&buffer[..bytes]);
    }
    if read != expected_bytes || !same_file(&before, &file.metadata()?) {
        return Err(RootlessOciBuildError::ConcurrentChange);
    }
    format!("{:x}", hasher.finalize())
        .parse()
        .map_err(|_| RootlessOciBuildError::ArchiveInvalid)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

fn valid_build_arg_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_token(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=max).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

fn valid_source_reference(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        })
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    path.components()
        .all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Debug, thiserror::Error)]
pub enum RootlessOciBuildError {
    #[error("rootless OCI build policy is invalid")]
    InvalidPolicy,
    #[error("rootless OCI build lease does not match the installed policy")]
    LeaseMismatch,
    #[error("rootless OCI build request is invalid")]
    InvalidRequest,
    #[error("rootless OCI build request is not canonical JCS")]
    NoncanonicalRequest,
    #[error("rootless OCI build request file is unsafe")]
    UnsafeRequest,
    #[error("rootless OCI prepared or dependency input is unsafe")]
    UnsafeInput,
    #[error("rootless OCI Dockerfile requests an external frontend")]
    UnsupportedDockerfileFrontend,
    #[error("rootless OCI output directory or file is unsafe")]
    UnsafeOutput,
    #[error("rootless OCI output request does not match the authorized request")]
    RequestMismatch,
    #[error("rootless OCI buildctl invocation failed")]
    BuildctlRejected,
    #[error("rootless OCI BuildKit metadata is invalid")]
    InvalidBuildMetadata,
    #[error("rootless OCI archive is invalid")]
    ArchiveInvalid,
    #[error("rootless OCI archive does not match its metadata")]
    ArchiveBinding,
    #[error("rootless OCI build result is invalid")]
    InvalidResult,
    #[error("rootless OCI build result is not canonical JCS")]
    NoncanonicalResult,
    #[error("rootless OCI input or output changed while it was being verified")]
    ConcurrentChange,
    #[error("rootless OCI result store is invalid")]
    InvalidStore,
    #[error("rootless OCI result store is already open")]
    StoreAlreadyOpen,
    #[error("rootless OCI result store lock is poisoned")]
    StoreLockPoisoned,
    #[error("rootless OCI results are outside the fixed shared build domain")]
    InvalidStoreBoundary,
    #[error("rootless OCI result store does not have enough bounded capacity")]
    StoreCapacityExceeded,
    #[error("rootless OCI workflow contract is invalid: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("rootless OCI build JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rootless OCI build I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl RootlessOciBuildError {
    pub fn evidence_digest(&self) -> EvidenceDigest {
        EvidenceDigest::sha256(format!("rootless-oci-build:{}", self.reason_code()))
    }

    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => "rootless_oci_build_policy_invalid",
            Self::LeaseMismatch => "rootless_oci_build_lease_mismatch",
            Self::InvalidRequest | Self::NoncanonicalRequest | Self::UnsafeRequest => {
                "rootless_oci_build_request_invalid"
            }
            Self::UnsafeInput => "rootless_oci_build_input_unsafe",
            Self::UnsupportedDockerfileFrontend => "rootless_oci_dockerfile_frontend_unsupported",
            Self::UnsafeOutput | Self::RequestMismatch => "rootless_oci_build_output_unsafe",
            Self::BuildctlRejected => "rootless_oci_build_failed",
            Self::InvalidBuildMetadata => "rootless_oci_build_metadata_invalid",
            Self::ArchiveInvalid | Self::ArchiveBinding => "rootless_oci_archive_invalid",
            Self::InvalidResult | Self::NoncanonicalResult => "rootless_oci_result_invalid",
            Self::ConcurrentChange => "rootless_oci_build_concurrent_change",
            Self::InvalidStore | Self::StoreAlreadyOpen | Self::StoreLockPoisoned => {
                "rootless_oci_result_store_invalid"
            }
            Self::InvalidStoreBoundary => "rootless_oci_result_store_unbounded",
            Self::StoreCapacityExceeded => "rootless_oci_result_store_full",
            Self::Workflow(_) => "rootless_oci_workflow_contract_invalid",
            Self::Json(_) => "rootless_oci_json_invalid",
            Self::Io(_) => "rootless_oci_io_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use tempfile::tempdir;

    use super::*;
    use crate::domain::{
        WorkflowCacheClassV1, WorkflowExecutionProfileV1, WorkflowLeaseInputV1,
        WorkflowNetworkClassV1, WorkflowNodeActivationV1, WorkflowNodeV1,
        WorkflowResourceEnvelopeV1, WorkflowWorkerPoolV1,
    };

    fn policy() -> RootlessOciBuildPolicyV1 {
        RootlessOciBuildPolicyV1 {
            schema_version: ROOTLESS_OCI_BUILD_POLICY_SCHEMA_VERSION,
            project_id: "project".parse().expect("project ID"),
            dockerfile_path: "Dockerfile".to_owned(),
            target: Some("release".to_owned()),
            platform: "linux/amd64".to_owned(),
            build_args: vec![RootlessOciBuildArgV1 {
                key: "RUBY_VERSION".to_owned(),
                value: "4.0.0".to_owned(),
            }],
            base_inputs: vec![RootlessOciBaseInputV1 {
                source: "docker.io/library/debian:trixie-slim".to_owned(),
                layout_name: "debian".to_owned(),
                dependency_path: "oci-layouts/debian".to_owned(),
                manifest_digest: format!("sha256:{}", "a".repeat(64))
                    .parse()
                    .expect("OCI digest"),
            }],
            local_inputs: Vec::new(),
            verified_output: None,
            max_archive_bytes: 32 * 1024 * 1024,
        }
    }

    fn lease() -> WorkflowLeaseV1 {
        let node = WorkflowNodeV1 {
            node_id: "release".parse().expect("node ID"),
            display_name: "Release".to_owned(),
            kind: WorkflowNodeKindV1::ReleaseBuild,
            activation: WorkflowNodeActivationV1::Always,
            profile_id: "oci".parse().expect("profile ID"),
            depends_on: vec!["prepare".parse().expect("prepare node")],
            input_contracts: vec![WorkflowArtifactKindV1::PreparedRun],
            output_contract: WorkflowArtifactKindV1::ReleaseBuildResult,
        };
        let profile = WorkflowExecutionProfileV1 {
            profile_id: node.profile_id.clone(),
            adapter_id: WorkflowAdapterIdV1::WorkerOciReleaseBuildV1,
            worker_pool: WorkflowWorkerPoolV1::VpsRequired,
            network_class: WorkflowNetworkClassV1::Offline,
            cache_class: WorkflowCacheClassV1::PreparedRun,
            timeout_ms: 60_000,
            resources: Some(WorkflowResourceEnvelopeV1 {
                cpu_millicores: 1_000,
                memory_max_bytes: 1024 * 1024 * 1024,
                tasks_max: 128,
                scratch_max_bytes: 1024 * 1024 * 1024,
                scratch_max_inodes: 100_000,
                output_max_bytes: 64 * 1024 * 1024,
            }),
        };
        let attempt_id = Uuid::from_u128(4);
        let project_id = ProjectId::from_str("project").expect("project ID");
        let source_sha = GitCommitId::from_str(&"b".repeat(40)).expect("source SHA");
        let workflow_policy = EvidenceDigest::sha256("workflow policy");
        let preparation_key = EvidenceDigest::sha256("prepared run");
        WorkflowLeaseV1::new(
            Uuid::from_u128(1),
            1,
            Uuid::from_u128(2),
            attempt_id,
            project_id,
            source_sha,
            7,
            EvidenceDigest::sha256("source attestation"),
            workflow_policy,
            preparation_key,
            &node,
            &profile,
            None,
            vec![WorkflowLeaseInputV1 {
                node_id: "prepare".parse().expect("prepare node"),
                artifact_kind: WorkflowArtifactKindV1::PreparedRun,
                output_digest: EvidenceDigest::sha256("prepared run output"),
            }],
            EvidenceDigest::sha256("expected input"),
            "worker".to_owned(),
            "host".to_owned(),
            100,
            60_100,
        )
        .expect("lease")
    }

    fn verified_policy() -> RootlessOciBuildPolicyV1 {
        let mut policy = policy();
        policy.local_inputs = vec![RootlessOciLocalInputV1 {
            source: "native".to_owned(),
            local_name: "native".to_owned(),
            toolchain_path: "rimg-native/opt/4u".to_owned(),
        }];
        policy.verified_output = Some(VerifiedOciOutputPolicy {
            context_name: "verified-release".to_owned(),
            directory: "release".parse().expect("release directory"),
            max_bytes: 64 * 1024 * 1024,
            max_files: 1,
        });
        policy
    }

    fn verified_lease() -> WorkflowLeaseV1 {
        let base = lease();
        let source_identity = base
            .source_identity
            .as_ref()
            .expect("source identity")
            .clone();
        let node = WorkflowNodeV1 {
            node_id: "release".parse().expect("node ID"),
            display_name: "Release verified output".to_owned(),
            kind: WorkflowNodeKindV1::ReleaseBuild,
            activation: WorkflowNodeActivationV1::Always,
            profile_id: "oci".parse().expect("profile ID"),
            depends_on: vec![
                "prepare".parse().expect("prepare node"),
                "verify".parse().expect("verify node"),
            ],
            input_contracts: vec![
                WorkflowArtifactKindV1::PreparedRun,
                WorkflowArtifactKindV1::VerificationReceipt,
            ],
            output_contract: WorkflowArtifactKindV1::ReleaseBuildResult,
        };
        let profile = WorkflowExecutionProfileV1 {
            profile_id: node.profile_id.clone(),
            adapter_id: WorkflowAdapterIdV1::WorkerOciReleaseBuildV1,
            worker_pool: WorkflowWorkerPoolV1::VpsRequired,
            network_class: WorkflowNetworkClassV1::Offline,
            cache_class: WorkflowCacheClassV1::PreparedRun,
            timeout_ms: 60_000,
            resources: base.resources.clone(),
        };
        let state = crate::domain::WorkflowOperationStateV1::new(
            base.attempt_id,
            &base.project_id,
            &base.source_sha,
            &base.workflow_policy_digest,
            &base.preparation_key,
            &base.worker_id,
            &base.host_id,
            vec![node.node_id.clone()],
            1024 * 1024 * 1024,
            100_000,
        )
        .expect("operation state");
        WorkflowLeaseV1::new(
            base.lease_id,
            base.lease_generation,
            base.request_id,
            base.attempt_id,
            base.project_id,
            base.source_sha,
            source_identity.sequence,
            source_identity.attestation_digest,
            base.workflow_policy_digest,
            base.preparation_key,
            &node,
            &profile,
            None,
            vec![
                base.input_artifacts[0].clone(),
                WorkflowLeaseInputV1 {
                    node_id: "verify".parse().expect("verify node"),
                    artifact_kind: WorkflowArtifactKindV1::VerificationReceipt,
                    output_digest: EvidenceDigest::sha256("verified bin/ci"),
                },
            ],
            EvidenceDigest::sha256("prepared plus verified"),
            base.worker_id,
            base.host_id,
            base.leased_at_ms,
            base.expires_at_ms,
        )
        .and_then(|lease| lease.with_operation_state(state))
        .expect("verified OCI lease")
    }

    #[test]
    fn request_is_canonical_and_buildctl_argv_is_fixed() {
        let lease = lease();
        let request = RootlessOciBuildRequestV1::from_policy(&lease, &policy()).expect("request");
        let bytes = request.canonical_bytes().expect("canonical request");
        assert_eq!(
            RootlessOciBuildRequestV1::decode_canonical(&bytes).expect("decode request"),
            request
        );
        let arguments = buildctl_arguments(&request).expect("buildctl arguments");
        assert_eq!(arguments[0], "--addr=unix:///buildkit/buildkitd.sock");
        assert_eq!(arguments[1], "build");
        assert!(arguments.iter().any(|argument| {
            argument == "--oci-layout=debian=/dependencies/oci-layouts/debian"
        }));
        assert!(arguments.iter().any(|argument| {
            argument
                == &format!(
                    "--opt=context:docker.io/library/debian:trixie-slim=oci-layout://debian@sha256:{}",
                    "a".repeat(64)
                )
        }));
        assert!(arguments.iter().all(|argument| {
            !argument.contains("--allow")
                && !argument.contains("--secret")
                && !argument.contains("--ssh")
                && !argument.contains("registry")
                && !argument.contains("cache-to")
        }));
    }

    #[test]
    fn verified_output_and_shared_toolchain_are_explicit_read_only_contexts() {
        let request = RootlessOciBuildRequestV1::from_policy(&verified_lease(), &verified_policy())
            .expect("verified request");
        let arguments = buildctl_arguments(&request).expect("buildctl arguments");
        assert!(
            arguments
                .iter()
                .any(|argument| { argument == "--local=native=/toolchains/rimg-native/opt/4u" })
        );
        assert!(
            arguments
                .iter()
                .any(|argument| { argument == "--opt=context:native=local:native" })
        );
        assert!(
            arguments
                .iter()
                .any(|argument| { argument == "--local=verified-release=/operation/release" })
        );
        assert!(arguments.iter().any(|argument| {
            argument == "--opt=context:verified-release=local:verified-release"
        }));
    }

    #[test]
    fn verified_output_inventory_is_flat_bounded_and_read_only() {
        let directory = tempdir().expect("temporary directory");
        let release = directory.path().join("release");
        fs::create_dir(&release).expect("release directory");
        fs::write(release.join("rimg"), b"verified binary").expect("release binary");
        fs::set_permissions(release.join("rimg"), fs::Permissions::from_mode(0o555))
            .expect("binary mode");
        fs::set_permissions(&release, fs::Permissions::from_mode(0o555)).expect("release mode");
        let policy = verified_policy().verified_output.expect("verified output");
        let first = verified_output_digest(directory.path(), &policy).expect("output digest");
        assert_eq!(first.as_str().len(), 64);

        fs::set_permissions(&release, fs::Permissions::from_mode(0o755))
            .expect("writable release mode");
        assert!(matches!(
            verified_output_digest(directory.path(), &policy),
            Err(RootlessOciBuildError::UnsafeInput)
        ));

        fs::set_permissions(&release, fs::Permissions::from_mode(0o755))
            .expect("open release directory");
        fs::write(release.join("extra"), b"unexpected payload").expect("extra file");
        fs::set_permissions(release.join("extra"), fs::Permissions::from_mode(0o444))
            .expect("extra file mode");
        fs::set_permissions(&release, fs::Permissions::from_mode(0o555))
            .expect("seal release directory");
        assert!(matches!(
            verified_output_digest(directory.path(), &policy),
            Err(RootlessOciBuildError::UnsafeInput)
        ));
        fs::set_permissions(&release, fs::Permissions::from_mode(0o755))
            .expect("open release directory");
        fs::remove_file(release.join("extra")).expect("remove extra file");
        fs::create_dir(release.join("nested")).expect("nested directory");
        fs::set_permissions(release.join("nested"), fs::Permissions::from_mode(0o555))
            .expect("nested directory mode");
        fs::set_permissions(&release, fs::Permissions::from_mode(0o555))
            .expect("seal release directory");
        let mut nested_policy = policy.clone();
        nested_policy.max_files = 2;
        assert!(matches!(
            verified_output_digest(directory.path(), &nested_policy),
            Err(RootlessOciBuildError::UnsafeInput)
        ));
    }

    #[test]
    fn policy_rejects_duplicate_or_unsafe_dynamic_inputs() {
        let mut policy = policy();
        policy.build_args.push(policy.build_args[0].clone());
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        let mut policy = super::tests::policy();
        policy.base_inputs[0].dependency_path = "../escape".to_owned();
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        let mut policy = super::tests::policy();
        policy.build_args[0].value = "$(touch /tmp/no)\n".to_owned();
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        let mut policy = verified_policy();
        policy.local_inputs[0].local_name = "context".to_owned();
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        let mut policy = verified_policy();
        policy
            .verified_output
            .as_mut()
            .expect("verified output")
            .context_name = "dockerfile".to_owned();
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        let mut policy = verified_policy();
        policy.local_inputs[0].local_name = "verified-release".to_owned();
        assert!(matches!(
            policy.validate(),
            Err(RootlessOciBuildError::InvalidPolicy)
        ));
        for reserved_source in ["context", "dockerfile"] {
            let mut policy = super::tests::policy();
            policy.base_inputs[0].source = reserved_source.to_owned();
            assert!(matches!(
                policy.validate(),
                Err(RootlessOciBuildError::InvalidPolicy)
            ));
            let mut policy = verified_policy();
            policy.local_inputs[0].source = reserved_source.to_owned();
            assert!(matches!(
                policy.validate(),
                Err(RootlessOciBuildError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn dockerfile_frontend_is_builtin_only_and_checked_before_buildctl() {
        let directory = tempdir().expect("temporary directory");
        let prepared = directory.path().join("prepared");
        fs::create_dir(&prepared).expect("prepared directory");
        let dockerfile = prepared.join("Dockerfile");
        fs::write(&dockerfile, b"FROM scratch\n").expect("write Dockerfile");
        fs::set_permissions(&dockerfile, fs::Permissions::from_mode(0o444))
            .expect("seal Dockerfile");
        fs::set_permissions(&prepared, fs::Permissions::from_mode(0o555))
            .expect("seal prepared directory");
        validate_dockerfile_frontend(&prepared, "Dockerfile").expect("builtin Dockerfile");

        fs::set_permissions(&dockerfile, fs::Permissions::from_mode(0o644))
            .expect("make Dockerfile writable for fixture update");
        fs::write(&dockerfile, b"# SyNtAx=docker/dockerfile:1\nFROM scratch\n")
            .expect("write external frontend directive");
        fs::set_permissions(&dockerfile, fs::Permissions::from_mode(0o444))
            .expect("reseal Dockerfile");
        assert!(matches!(
            validate_dockerfile_frontend(&prepared, "Dockerfile"),
            Err(RootlessOciBuildError::UnsupportedDockerfileFrontend)
        ));
    }

    #[test]
    fn malformed_oci_json_has_the_archive_reason_code() {
        let directory = tempdir().expect("temporary directory");
        let archive_path = directory.path().join("invalid.oci.tar");
        write_oci_archive(&archive_path, "not-json", &[]);
        let archive = File::open(archive_path).expect("open invalid archive");
        let digest: OciDigest = format!("sha256:{}", "a".repeat(64))
            .parse()
            .expect("OCI digest");
        assert!(matches!(
            validate_oci_archive(&archive, MAX_ARCHIVE_BYTES, &digest, &digest),
            Err(RootlessOciBuildError::ArchiveInvalid)
        ));
    }

    #[test]
    fn output_validation_binds_request_result_and_oci_graph() {
        let directory = tempdir().expect("temporary directory");
        let output = directory.path().join("output");
        fs::create_dir(&output).expect("output directory");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).expect("output mode");
        let request = RootlessOciBuildRequestV1::from_policy(&lease(), &policy()).expect("request");
        let result = write_valid_output(&output, &request);
        let archive_path = output.join(RESULT_ARCHIVE_FILE);
        let validated =
            validate_rootless_oci_build_output(&output, &request, None).expect("validate output");
        assert_eq!(validated.result, result);

        fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o600))
            .expect("make archive writable for tamper");
        let mut tampered = fs::OpenOptions::new()
            .write(true)
            .open(&archive_path)
            .expect("open archive for tamper");
        tampered.write_all(b"x").expect("tamper archive");
        drop(tampered);
        fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o400))
            .expect("restore archive mode");
        assert!(matches!(
            validate_rootless_oci_build_output(&output, &request, None),
            Err(RootlessOciBuildError::ArchiveBinding
                | RootlessOciBuildError::ArchiveInvalid
                | RootlessOciBuildError::ConcurrentChange)
        ));
    }

    fn write_valid_output(
        output: &Path,
        request: &RootlessOciBuildRequestV1,
    ) -> RootlessOciBuildResultV1 {
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let config_digest: OciDigest = format!("sha256:{}", hex_sha256(config))
            .parse()
            .expect("config digest");
        let layer = b"layer";
        let layer_digest = format!("sha256:{}", hex_sha256(layer));
        let manifest = format!(
            "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{}\",\"size\":{}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{}\",\"size\":{}}}]}}",
            config_digest.as_str(),
            config.len(),
            layer_digest,
            layer.len()
        );
        let manifest_digest: OciDigest = format!("sha256:{}", hex_sha256(manifest.as_bytes()))
            .parse()
            .expect("manifest digest");
        let index = format!(
            "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{}\",\"size\":{}}}]}}",
            manifest_digest.as_str(),
            manifest.len()
        );
        let archive_path = output.join(RESULT_ARCHIVE_FILE);
        write_oci_archive(
            &archive_path,
            &index,
            &[
                (config_digest.as_str(), config.as_slice()),
                (&layer_digest, layer.as_slice()),
                (manifest_digest.as_str(), manifest.as_bytes()),
            ],
        );
        let archive = File::open(&archive_path).expect("open archive");
        let archive_bytes = archive.metadata().expect("archive metadata").len();
        let archive_digest = hash_file(&archive, archive_bytes).expect("archive digest");
        let result = RootlessOciBuildResultV1::new(
            request,
            manifest_digest,
            config_digest,
            archive_digest,
            archive_bytes,
            None,
        )
        .expect("result");
        fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o400))
            .expect("archive mode");
        write_new_read_only_file(
            &output.join(RESULT_REQUEST_FILE),
            &request.canonical_bytes().expect("request bytes"),
        )
        .expect("write request");
        write_new_read_only_file(
            &output.join(RESULT_DOCUMENT_FILE),
            &result.canonical_bytes(request).expect("result bytes"),
        )
        .expect("write result");
        result
    }

    #[derive(Clone, Copy)]
    struct FixedResultFilesystemProbe {
        available_bytes: u64,
        host_available_bytes: u64,
    }

    impl ResultFilesystemProbe for FixedResultFilesystemProbe {
        fn inspect(&self, _root: &File) -> Result<ResultFilesystemSnapshot, RootlessOciBuildError> {
            Ok(ResultFilesystemSnapshot {
                shared_storage_domain: true,
                total_bytes: 64 * 1024 * 1024 * 1024,
                available_bytes: self.available_bytes,
                host_available_bytes: self.host_available_bytes,
                total_inodes: 1_000_000,
                available_inodes: 1_000_000,
            })
        }
    }

    #[test]
    fn result_store_promotes_one_verified_project_result_and_cleans_staging() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("oci-results");
        fs::create_dir(&root).expect("result root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("result root mode");
        let metadata = fs::metadata(&root).expect("result root metadata");
        assert_ne!(
            metadata.uid(),
            0,
            "test must run without root-owned fixtures"
        );
        let request = RootlessOciBuildRequestV1::from_policy(&lease(), &policy()).expect("request");
        let store = RootlessOciResultStoreV1::open_with_probe(
            root.clone(),
            metadata.uid(),
            metadata.gid(),
            metadata.uid(),
            metadata.gid(),
            Box::new(FixedResultFilesystemProbe {
                available_bytes: 32 * 1024 * 1024 * 1024,
                host_available_bytes: 64 * 1024 * 1024 * 1024,
            }),
        )
        .expect("open result store");
        let staging = store.prepare(&request).expect("prepare staging");
        let request_path = store.request_path(&request);
        let request_mode = fs::metadata(&request_path)
            .expect("authorized request metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(request_mode, SANDBOX_REQUEST_FILE_MODE);
        assert_ne!(
            request_mode & 0o004,
            0,
            "the sandbox build UID is not the root-owned request file owner"
        );
        assert_eq!(
            read_stable_file(
                &request_path,
                metadata.uid(),
                SANDBOX_REQUEST_FILE_MODE,
                MAX_REQUEST_BYTES,
            )
            .expect("sandbox-readable stable request"),
            request.canonical_bytes().expect("canonical request bytes")
        );
        let expected = write_valid_output(&staging, &request);
        let promoted = store.promote(&request).expect("promote result");
        assert_eq!(promoted, expected);
        assert!(!staging.exists());
        assert!(!request_path.exists());
        let final_path = root.join(request.project_id.as_str());
        let validated = validate_rootless_oci_build_output(
            &final_path,
            &request,
            Some((metadata.uid(), metadata.gid())),
        )
        .expect("validate promoted result");
        assert_eq!(validated.result, expected);

        let replacement = store.prepare(&request).expect("prepare replacement");
        assert!(!final_path.exists());
        store.discard(&request).expect("discard replacement");
        assert!(!replacement.exists());
        assert!(!store.request_path(&request).exists());
    }

    #[test]
    fn result_store_rejects_capacity_before_creating_staging() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("oci-results");
        fs::create_dir(&root).expect("result root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("result root mode");
        let metadata = fs::metadata(&root).expect("result root metadata");
        let request = RootlessOciBuildRequestV1::from_policy(&lease(), &policy()).expect("request");
        let store = RootlessOciResultStoreV1::open_with_probe(
            root,
            metadata.uid(),
            metadata.gid(),
            metadata.uid(),
            metadata.gid(),
            Box::new(FixedResultFilesystemProbe {
                available_bytes: request.max_archive_bytes,
                host_available_bytes: 64 * 1024 * 1024 * 1024,
            }),
        )
        .expect("open result store");
        assert!(matches!(
            store.prepare(&request),
            Err(RootlessOciBuildError::StoreCapacityExceeded)
        ));
        assert!(!store.staging_path(&request).exists());
        assert!(!store.request_path(&request).exists());
    }

    #[test]
    fn result_store_reserves_engine_and_archive_peak_above_the_host_floor() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("oci-results");
        fs::create_dir(&root).expect("result root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("result root mode");
        let metadata = fs::metadata(&root).expect("result root metadata");
        let request = RootlessOciBuildRequestV1::from_policy(&lease(), &policy()).expect("request");
        let peak = request
            .max_archive_bytes
            .checked_add(MIN_STORE_HEADROOM_BYTES)
            .and_then(|bytes| bytes.checked_add(BUILDKIT_MAX_USED_BYTES))
            .expect("bounded peak");
        let required = required_host_available_bytes(peak).expect("required host capacity");
        let store = RootlessOciResultStoreV1::open_with_probe(
            root,
            metadata.uid(),
            metadata.gid(),
            metadata.uid(),
            metadata.gid(),
            Box::new(FixedResultFilesystemProbe {
                available_bytes: 32 * 1024 * 1024 * 1024,
                host_available_bytes: required - 1,
            }),
        )
        .expect("open result store");

        assert!(matches!(
            store.prepare(&request),
            Err(RootlessOciBuildError::StoreCapacityExceeded)
        ));
        assert!(!store.staging_path(&request).exists());
        assert!(!store.request_path(&request).exists());
    }

    fn write_oci_archive(path: &Path, index: &str, blobs: &[(&str, &[u8])]) {
        let file = File::create(path).expect("create archive");
        let mut builder = tar::Builder::new(file);
        append_tar(
            &mut builder,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        append_tar(&mut builder, "index.json", index.as_bytes());
        for (digest, bytes) in blobs {
            append_tar(
                &mut builder,
                &format!("blobs/sha256/{}", digest.trim_start_matches("sha256:")),
                bytes,
            );
        }
        builder.finish().expect("finish archive");
    }

    fn append_tar(builder: &mut tar::Builder<File>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len()).expect("entry size"));
        header.set_mode(0o444);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append archive entry");
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn installed_constants_do_not_expose_host_runtime_or_registry() {
        assert_eq!(BUILDCTL_EXECUTABLE, "/usr/libexec/rdashboard/buildctl");
        assert_eq!(
            crate::rootless_oci::BUILDKIT_SOCKET_PATH,
            "/run/rdashboard-buildkit/buildkitd.sock"
        );
        assert!(ROOTLESS_OCI_RESULT_STORE_ROOT.starts_with("/var/lib/rdashboard-build/"));
        assert_eq!(
            fs::metadata(".").expect("workspace metadata").uid(),
            fs::metadata(".").expect("workspace metadata").uid()
        );
    }
}
