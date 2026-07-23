use std::{
    collections::BTreeSet,
    fs::{self, DirBuilder, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{EvidenceDigest, GitCommitId, ProjectId, WorkflowAdapterIdV1},
    installed_workflow::{INSTALLED_WORKFLOW_CATALOG_PATH, InstalledWorkflowCatalogV1},
    self_release_build::{
        SELF_RELEASE_BOOTSTRAP_SIGNING_CREDENTIAL_PATH, SelfReleaseBuildPolicyV1,
        load_bootstrap_self_release_signing_key, versioned_self_release_binaries,
    },
    self_update::{
        BuiltSelfReleaseV1, InstalledSelfUpdatePolicyInputV1, InstalledSelfUpdatePolicyV1,
        SelfReleaseFileV1, SelfReleaseManifestInputV1, SelfReleaseSignatureInputV1,
        SelfReleaseSourceV1, SelfReleaseStoreV1, SelfUpdateFilePolicyV1,
        VERSIONED_SELF_RELEASE_BINARIES, build_signed_self_release,
        load_installed_self_update_policy_from,
    },
    self_update_runtime::{
        SELF_RELEASE_ROOT, SELF_UPDATE_BACKUP_ROOT, SELF_UPDATE_CURRENT_LINK,
        SELF_UPDATE_JOURNAL_ROOT, SELF_UPDATE_LKG_LINK, SELF_UPDATE_ROOT, SelfUpdateRuntimePathsV1,
        initialize_release_pointers, installed_self_update_runtime_contract_digest,
        read_current_release, read_last_known_good_release,
    },
    unix_time_ms,
    workflow_launcher::{
        WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION, WorkflowLauncherPolicyV1,
        WorkflowLauncherVerificationKeyConfigV1,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

const SELF_UPDATE_POLICY_PATH: &str = "/etc/rdashboard/self-update-policy.jcs";
const SELF_RELEASE_SEED_PATH: &str = SELF_RELEASE_BOOTSTRAP_SIGNING_CREDENTIAL_PATH;
const WORKFLOW_GRANT_SEED_PATH: &str = "/etc/rdashboard/credentials/workflow-grant-seed";
const INITIAL_RELEASE_PLAN_PATH: &str = "/etc/rdashboard/initial-self-release.jcs";
const INITIAL_RELEASE_PAYLOAD_ROOT: &str = "/usr/libexec/rdashboard/initial-release";
const INITIAL_RELEASE_WORK_ROOT: &str = "/var/lib/rdashboard-bootstrap/.initial-release-build";
const POLICY_BUNDLE_PURPOSE: &str = "rdashboard.self-update-policy-bundle.v1";
const POLICY_BUNDLE_SCHEMA_VERSION: u16 = 1;
const INITIAL_RELEASE_PLAN_PURPOSE: &str = "rdashboard.initial-self-release-plan.v1";
const INITIAL_RELEASE_PLAN_SCHEMA_VERSION: u16 = 1;
const SELF_UPDATE_STATE_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_RELEASE_BYTES: u64 = 128 * 1024 * 1024;
const SIGNATURE_VALIDITY_MS: i64 = 15 * 60 * 1_000;
const MAX_POLICY_INPUT_BYTES: u64 = 512 * 1024;
const MAX_INITIAL_PLAN_BYTES: u64 = 64 * 1024;
const INITIAL_RELEASE_OUTPUT_STEM: &str = "initial";
const INITIAL_RELEASE_ARCHIVE_FILE: &str = "initial.tar";
const INITIAL_RELEASE_DESCRIPTOR_FILE: &str = "initial.jcs";
const WORKFLOW_BOOTSTRAP_PURPOSE: &str = "rdashboard.workflow-bootstrap-bundle.v1";
const WORKFLOW_BOOTSTRAP_SCHEMA_VERSION: u16 = 1;
const WORKER_ID: &str = "shared-vps-worker-1";
const HOST_ID: &str = "production-vps";
const GRANT_ISSUER: &str = "workflow-gateway";
const LAUNCHER_AUDIENCE: &str = "workflow-launcher";

fn main() {
    match run(&std::env::args().collect::<Vec<_>>()) {
        Ok(output) => {
            if let Err(error) = std::io::stdout().write_all(&output) {
                fail(&ConfigError::Io(error));
            }
        }
        Err(error) => fail(&error),
    }
}

fn fail(error: &ConfigError) -> ! {
    eprintln!(
        "{}",
        serde_json::json!({
            "reason_code": error.reason_code(),
            "status": "failed",
            "summary": error.to_string(),
        })
    );
    std::process::exit(1);
}

fn run(arguments: &[String]) -> Result<Vec<u8>, ConfigError> {
    match parse_command(arguments)? {
        Command::BuildPolicies {
            key_epoch,
            reader_gid,
        } => {
            require_root()?;
            let launcher = WorkflowLauncherPolicyV1::decode_canonical(&read_stdin_bounded(
                MAX_POLICY_INPUT_BYTES,
            )?)?;
            let seed = read_root_seed(Path::new(SELF_RELEASE_SEED_PATH))?;
            let bundle = SelfUpdatePolicyBundleV1::new(launcher, &seed, key_epoch, reader_gid)?;
            bundle.canonical_bytes()
        }
        Command::BuildWorkflowBootstrap(input) => {
            require_root()?;
            let seed = read_root_seed(Path::new(WORKFLOW_GRANT_SEED_PATH))?;
            WorkflowBootstrapBundleV1::new(input, &seed)?.canonical_bytes()
        }
        Command::ExtractBaseLauncher => {
            let bundle = read_workflow_bootstrap_bundle()?;
            Ok(bundle.launcher_policy.canonical_bytes()?)
        }
        Command::RenderWorkflowGateway => {
            let bundle = read_workflow_bootstrap_bundle()?;
            Ok(bundle.gateway.render().into_bytes())
        }
        Command::RenderWorkflowWorker => {
            let bundle = read_workflow_bootstrap_bundle()?;
            Ok(bundle.worker.render().into_bytes())
        }
        Command::ExtractLauncher => {
            let bundle = read_policy_bundle()?;
            Ok(bundle.launcher_policy.canonical_bytes()?)
        }
        Command::ExtractSelfUpdate => {
            let bundle = read_policy_bundle()?;
            Ok(bundle.self_update_policy.canonical_bytes()?)
        }
        Command::RenderEnvironment => {
            let bundle = read_policy_bundle()?;
            Ok(format!(
                "RDASHBOARD_SELF_RELEASE_GID={}\n",
                bundle.self_release_reader_gid
            )
            .into_bytes())
        }
        Command::BuildInitialPlan => {
            require_root()?;
            let bytes = read_stdin_bounded(MAX_INITIAL_PLAN_BYTES)?;
            let input: InitialSelfReleasePlanInputV1 = serde_json::from_slice(&bytes)?;
            let payload = load_initial_release_payload(Path::new(INITIAL_RELEASE_PAYLOAD_ROOT), 0)?;
            InitialSelfReleasePlanV1::new(input, payload.files)?.canonical_bytes()
        }
        Command::Initialize => {
            require_root()?;
            Ok(serde_jcs::to_vec(&initialize_installed_release()?)?)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    BuildWorkflowBootstrap(WorkflowBootstrapInputV1),
    ExtractBaseLauncher,
    RenderWorkflowGateway,
    RenderWorkflowWorker,
    BuildPolicies { key_epoch: u64, reader_gid: u32 },
    ExtractLauncher,
    ExtractSelfUpdate,
    RenderEnvironment,
    BuildInitialPlan,
    Initialize,
}

fn parse_command(arguments: &[String]) -> Result<Command, ConfigError> {
    match arguments {
        [
            _,
            command,
            key_epoch,
            worker_user_id,
            build_user_id,
            build_group_id,
            source_user_id,
            build_reader_group_id,
            dependency_fetcher_user_id,
            dependency_fetch_group_id,
        ] if command == "build-workflow-bootstrap" => {
            Ok(Command::BuildWorkflowBootstrap(WorkflowBootstrapInputV1 {
                key_epoch: parse_nonzero_u64(key_epoch)?,
                worker_uid: parse_nonzero_u32(worker_user_id)?,
                build_uid: parse_nonzero_u32(build_user_id)?,
                build_gid: parse_nonzero_u32(build_group_id)?,
                source_uid: parse_nonzero_u32(source_user_id)?,
                build_reader_gid: parse_nonzero_u32(build_reader_group_id)?,
                dependency_fetcher_uid: parse_nonzero_u32(dependency_fetcher_user_id)?,
                dependency_fetch_gid: parse_nonzero_u32(dependency_fetch_group_id)?,
            }))
        }
        [_, command] if command == "extract-base-launcher" => Ok(Command::ExtractBaseLauncher),
        [_, command] if command == "render-workflow-gateway" => Ok(Command::RenderWorkflowGateway),
        [_, command] if command == "render-workflow-worker" => Ok(Command::RenderWorkflowWorker),
        [_, command, key_epoch, reader_gid] if command == "build-policies" => {
            let key_epoch = key_epoch
                .parse::<u64>()
                .map_err(|_| ConfigError::InvalidInvocation)?;
            let reader_gid = reader_gid
                .parse::<u32>()
                .map_err(|_| ConfigError::InvalidInvocation)?;
            if key_epoch == 0 || reader_gid == 0 || reader_gid == u32::MAX {
                return Err(ConfigError::InvalidInvocation);
            }
            Ok(Command::BuildPolicies {
                key_epoch,
                reader_gid,
            })
        }
        [_, command] if command == "extract-launcher" => Ok(Command::ExtractLauncher),
        [_, command] if command == "extract-self-update" => Ok(Command::ExtractSelfUpdate),
        [_, command] if command == "render-environment" => Ok(Command::RenderEnvironment),
        [_, command] if command == "build-initial-plan" => Ok(Command::BuildInitialPlan),
        [_, command] if command == "initialize" => Ok(Command::Initialize),
        _ => Err(ConfigError::InvalidInvocation),
    }
}

fn parse_nonzero_u32(value: &str) -> Result<u32, ConfigError> {
    let value = value
        .parse::<u32>()
        .map_err(|_| ConfigError::InvalidInvocation)?;
    if value == 0 || value == u32::MAX {
        return Err(ConfigError::InvalidInvocation);
    }
    Ok(value)
}

fn parse_nonzero_u64(value: &str) -> Result<u64, ConfigError> {
    let value = value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidInvocation)?;
    if value == 0 || value > i64::MAX.unsigned_abs() {
        return Err(ConfigError::InvalidInvocation);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkflowBootstrapInputV1 {
    key_epoch: u64,
    worker_uid: u32,
    build_uid: u32,
    build_gid: u32,
    source_uid: u32,
    build_reader_gid: u32,
    dependency_fetcher_uid: u32,
    dependency_fetch_gid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowGatewayEnvironmentV1 {
    worker_uid: u32,
    worker_id: String,
    host_id: String,
    grant_issuer: String,
    launcher_audience: String,
    grant_key_id: String,
    grant_key_epoch: u64,
    grant_public_key: String,
}

impl WorkflowGatewayEnvironmentV1 {
    fn render(&self) -> String {
        format!(
            concat!(
                "RDASHBOARD_WORKER_UID={}\n",
                "RDASHBOARD_WORKER_ID={}\n",
                "RDASHBOARD_WORKER_HOST_ID={}\n",
                "RDASHBOARD_WORKFLOW_GRANT_ISSUER={}\n",
                "RDASHBOARD_WORKFLOW_GRANT_LAUNCHER_AUDIENCE={}\n",
                "RDASHBOARD_WORKFLOW_GRANT_KEY_ID={}\n",
                "RDASHBOARD_WORKFLOW_GRANT_KEY_EPOCH={}\n",
                "RDASHBOARD_WORKFLOW_GRANT_PUBLIC_KEY={}\n"
            ),
            self.worker_uid,
            self.worker_id,
            self.host_id,
            self.grant_issuer,
            self.launcher_audience,
            self.grant_key_id,
            self.grant_key_epoch,
            self.grant_public_key,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowWorkerEnvironmentV1 {
    worker_uid: u32,
    worker_id: String,
    host_id: String,
    source_uid: u32,
    build_reader_gid: u32,
    dependency_fetcher_uid: u32,
    dependency_fetch_gid: u32,
}

impl WorkflowWorkerEnvironmentV1 {
    fn render(&self) -> String {
        format!(
            concat!(
                "RDASHBOARD_WORKER_UID={}\n",
                "RDASHBOARD_WORKER_ID={}\n",
                "RDASHBOARD_WORKER_HOST_ID={}\n",
                "RDASHBOARD_WORKER_SLOTS=1\n",
                "RDASHBOARD_SOURCE_UID={}\n",
                "RDASHBOARD_BUILD_READER_GID={}\n",
                "RDASHBOARD_DEPENDENCY_FETCHER_UID={}\n",
                "RDASHBOARD_DEPENDENCY_FETCH_GID={}\n"
            ),
            self.worker_uid,
            self.worker_id,
            self.host_id,
            self.source_uid,
            self.build_reader_gid,
            self.dependency_fetcher_uid,
            self.dependency_fetch_gid,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowBootstrapBundleV1 {
    purpose: String,
    schema_version: u16,
    launcher_policy: WorkflowLauncherPolicyV1,
    gateway: WorkflowGatewayEnvironmentV1,
    worker: WorkflowWorkerEnvironmentV1,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowBootstrapBundlePayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    launcher_policy: &'a WorkflowLauncherPolicyV1,
    gateway: &'a WorkflowGatewayEnvironmentV1,
    worker: &'a WorkflowWorkerEnvironmentV1,
}

impl WorkflowBootstrapBundleV1 {
    fn new(input: WorkflowBootstrapInputV1, seed: &[u8]) -> Result<Self, ConfigError> {
        let identities = [
            input.worker_uid,
            input.build_uid,
            input.source_uid,
            input.dependency_fetcher_uid,
        ];
        if identities.into_iter().collect::<BTreeSet<_>>().len() != identities.len()
            || input.build_gid == input.build_reader_gid
            || input.build_gid == input.dependency_fetch_gid
            || input.build_reader_gid == input.dependency_fetch_gid
        {
            return Err(ConfigError::InvalidWorkflowBootstrap);
        }
        let mut seed_bytes: [u8; 32] =
            seed.try_into().map_err(|_| ConfigError::UnsafeCredential)?;
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        seed_bytes.zeroize();
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_base64url = URL_SAFE_NO_PAD.encode(public_key);
        let key_id = format!(
            "workflow-key-{}",
            &EvidenceDigest::sha256(public_key).as_str()[..16]
        );
        let launcher_policy = WorkflowLauncherPolicyV1 {
            schema_version: WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION,
            worker_uid: input.worker_uid,
            build_uid: input.build_uid,
            build_gid: input.build_gid,
            worker_id: WORKER_ID.to_owned(),
            host_id: HOST_ID.to_owned(),
            grant_issuer: GRANT_ISSUER.to_owned(),
            launcher_audience: LAUNCHER_AUDIENCE.to_owned(),
            minimum_grant_key_epoch: input.key_epoch,
            grant_verification_keys: vec![WorkflowLauncherVerificationKeyConfigV1 {
                key_id: key_id.clone(),
                key_epoch: input.key_epoch,
                public_key_base64url: public_key_base64url.clone(),
                active_from_ms: 0,
                signing_retired_at_ms: None,
                verify_until_ms: None,
                revoked_at_ms: None,
            }],
            allowed_adapters: vec![WorkflowAdapterIdV1::WorkerBareBinCiV1],
            rootless_oci: None,
            rootless_oci_builds: Vec::new(),
            self_release_build: None,
            self_release_reader_gid: None,
            max_concurrent_jobs: 1,
            max_journal_records: 1_024,
        };
        launcher_policy.validate()?;
        let gateway = WorkflowGatewayEnvironmentV1 {
            worker_uid: input.worker_uid,
            worker_id: WORKER_ID.to_owned(),
            host_id: HOST_ID.to_owned(),
            grant_issuer: GRANT_ISSUER.to_owned(),
            launcher_audience: LAUNCHER_AUDIENCE.to_owned(),
            grant_key_id: key_id,
            grant_key_epoch: input.key_epoch,
            grant_public_key: public_key_base64url,
        };
        let worker = WorkflowWorkerEnvironmentV1 {
            worker_uid: input.worker_uid,
            worker_id: WORKER_ID.to_owned(),
            host_id: HOST_ID.to_owned(),
            source_uid: input.source_uid,
            build_reader_gid: input.build_reader_gid,
            dependency_fetcher_uid: input.dependency_fetcher_uid,
            dependency_fetch_gid: input.dependency_fetch_gid,
        };
        let mut bundle = Self {
            purpose: WORKFLOW_BOOTSTRAP_PURPOSE.to_owned(),
            schema_version: WORKFLOW_BOOTSTRAP_SCHEMA_VERSION,
            launcher_policy,
            gateway,
            worker,
            document_digest: EvidenceDigest::sha256([]),
        };
        bundle.document_digest = bundle.calculate_digest()?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.launcher_policy.validate()?;
        let [key] = self.launcher_policy.grant_verification_keys.as_slice() else {
            return Err(ConfigError::InvalidWorkflowBootstrap);
        };
        if self.purpose != WORKFLOW_BOOTSTRAP_PURPOSE
            || self.schema_version != WORKFLOW_BOOTSTRAP_SCHEMA_VERSION
            || self.launcher_policy.allowed_adapters != [WorkflowAdapterIdV1::WorkerBareBinCiV1]
            || self.launcher_policy.rootless_oci.is_some()
            || !self.launcher_policy.rootless_oci_builds.is_empty()
            || self.launcher_policy.self_release_build.is_some()
            || self.launcher_policy.self_release_reader_gid.is_some()
            || self.launcher_policy.max_concurrent_jobs != 1
            || self.gateway.worker_uid != self.launcher_policy.worker_uid
            || self.gateway.worker_id != self.launcher_policy.worker_id
            || self.gateway.host_id != self.launcher_policy.host_id
            || self.gateway.grant_issuer != self.launcher_policy.grant_issuer
            || self.gateway.launcher_audience != self.launcher_policy.launcher_audience
            || self.gateway.grant_key_id != key.key_id
            || self.gateway.grant_key_epoch != key.key_epoch
            || self.gateway.grant_public_key != key.public_key_base64url
            || self.worker.worker_uid != self.launcher_policy.worker_uid
            || self.worker.worker_id != self.launcher_policy.worker_id
            || self.worker.host_id != self.launcher_policy.host_id
            || self.worker.source_uid == self.worker.worker_uid
            || self.worker.dependency_fetcher_uid == self.worker.worker_uid
            || self.worker.dependency_fetcher_uid == self.worker.source_uid
            || self.worker.build_reader_gid == self.worker.dependency_fetch_gid
            || self.document_digest != self.calculate_digest()?
        {
            return Err(ConfigError::InvalidWorkflowBootstrap);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ConfigError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowBootstrapBundlePayload {
                purpose: WORKFLOW_BOOTSTRAP_PURPOSE,
                schema_version: WORKFLOW_BOOTSTRAP_SCHEMA_VERSION,
                launcher_policy: &self.launcher_policy,
                gateway: &self.gateway,
                worker: &self.worker,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, ConfigError> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&bundle)? != bytes {
            return Err(ConfigError::NoncanonicalDocument);
        }
        bundle.validate()?;
        Ok(bundle)
    }
}

fn read_workflow_bootstrap_bundle() -> Result<WorkflowBootstrapBundleV1, ConfigError> {
    WorkflowBootstrapBundleV1::decode_canonical(&read_stdin_bounded(MAX_POLICY_INPUT_BYTES)?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SelfUpdatePolicyBundleV1 {
    purpose: String,
    schema_version: u16,
    launcher_policy: WorkflowLauncherPolicyV1,
    self_update_policy: InstalledSelfUpdatePolicyV1,
    self_release_reader_gid: u32,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfUpdatePolicyBundlePayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    launcher_policy: &'a WorkflowLauncherPolicyV1,
    self_update_policy: &'a InstalledSelfUpdatePolicyV1,
    self_release_reader_gid: u32,
}

impl SelfUpdatePolicyBundleV1 {
    fn new(
        mut launcher_policy: WorkflowLauncherPolicyV1,
        seed: &[u8],
        key_epoch: u64,
        reader_gid: u32,
    ) -> Result<Self, ConfigError> {
        launcher_policy.validate()?;
        if launcher_policy.self_release_build.is_some()
            || launcher_policy.self_release_reader_gid.is_some()
            || launcher_policy
                .allowed_adapters
                .contains(&WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1)
        {
            return Err(ConfigError::SelfReleaseAlreadyConfigured);
        }
        let mut seed_bytes: [u8; 32] =
            seed.try_into().map_err(|_| ConfigError::UnsafeCredential)?;
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        seed_bytes.zeroize();
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_digest = EvidenceDigest::sha256(public_key);
        let self_update_policy =
            InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
                key_id: format!("self-release-{}", &public_key_digest.as_str()[..16]),
                key_epoch,
                public_key: URL_SAFE_NO_PAD.encode(public_key),
                runtime_contract_digest: installed_self_update_runtime_contract_digest(),
                minimum_state_schema_version: SELF_UPDATE_STATE_SCHEMA_VERSION,
                maximum_state_schema_version: SELF_UPDATE_STATE_SCHEMA_VERSION,
                maximum_release_bytes: MAXIMUM_RELEASE_BYTES,
                files: VERSIONED_SELF_RELEASE_BINARIES
                    .iter()
                    .map(|binary| SelfUpdateFilePolicyV1 {
                        path: format!("bin/{binary}"),
                        mode: 0o555,
                    })
                    .collect(),
            })?;
        let build_policy = SelfReleaseBuildPolicyV1::new(
            self_update_policy.clone(),
            SELF_UPDATE_STATE_SCHEMA_VERSION,
            SIGNATURE_VALIDITY_MS,
            versioned_self_release_binaries(),
        )?;
        launcher_policy
            .allowed_adapters
            .push(WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1);
        launcher_policy.allowed_adapters.sort();
        launcher_policy.self_release_build = Some(build_policy);
        launcher_policy.self_release_reader_gid = Some(reader_gid);
        launcher_policy.validate()?;
        let mut bundle = Self {
            purpose: POLICY_BUNDLE_PURPOSE.to_owned(),
            schema_version: POLICY_BUNDLE_SCHEMA_VERSION,
            launcher_policy,
            self_update_policy,
            self_release_reader_gid: reader_gid,
            document_digest: EvidenceDigest::sha256([]),
        };
        bundle.document_digest = bundle.calculate_digest()?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.launcher_policy.validate()?;
        self.self_update_policy
            .validate_versioned_application_payload()?;
        let build_policy = self
            .launcher_policy
            .self_release_build
            .as_ref()
            .ok_or(ConfigError::PolicyMismatch)?;
        if self.purpose != POLICY_BUNDLE_PURPOSE
            || self.schema_version != POLICY_BUNDLE_SCHEMA_VERSION
            || build_policy.self_update_policy != self.self_update_policy
            || self.launcher_policy.self_release_reader_gid != Some(self.self_release_reader_gid)
            || !self
                .launcher_policy
                .allowed_adapters
                .contains(&WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1)
            || build_policy.state_schema_version != SELF_UPDATE_STATE_SCHEMA_VERSION
            || build_policy.signature_validity_ms != SIGNATURE_VALIDITY_MS
            || self.self_update_policy.runtime_contract_digest
                != installed_self_update_runtime_contract_digest()
            || self.self_update_policy.minimum_state_schema_version
                != SELF_UPDATE_STATE_SCHEMA_VERSION
            || self.self_update_policy.maximum_state_schema_version
                != SELF_UPDATE_STATE_SCHEMA_VERSION
            || self.self_update_policy.maximum_release_bytes != MAXIMUM_RELEASE_BYTES
            || self.document_digest != self.calculate_digest()?
        {
            return Err(ConfigError::PolicyMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ConfigError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfUpdatePolicyBundlePayload {
                purpose: POLICY_BUNDLE_PURPOSE,
                schema_version: POLICY_BUNDLE_SCHEMA_VERSION,
                launcher_policy: &self.launcher_policy,
                self_update_policy: &self.self_update_policy,
                self_release_reader_gid: self.self_release_reader_gid,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, ConfigError> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&bundle)? != bytes {
            return Err(ConfigError::NoncanonicalDocument);
        }
        bundle.validate()?;
        Ok(bundle)
    }
}

fn read_policy_bundle() -> Result<SelfUpdatePolicyBundleV1, ConfigError> {
    SelfUpdatePolicyBundleV1::decode_canonical(&read_stdin_bounded(MAX_POLICY_INPUT_BYTES)?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct InitialSelfReleasePlanInputV1 {
    source_head: GitCommitId,
    source_sequence: u64,
    source_attestation_digest: EvidenceDigest,
    workflow_policy_digest: EvidenceDigest,
    verification_receipt_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InitialSelfReleasePlanV1 {
    purpose: String,
    schema_version: u16,
    source_head: GitCommitId,
    source_sequence: u64,
    source_attestation_digest: EvidenceDigest,
    workflow_policy_digest: EvidenceDigest,
    verification_receipt_digest: EvidenceDigest,
    files: Vec<SelfReleaseFileV1>,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct InitialSelfReleasePlanPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    source_head: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    workflow_policy_digest: &'a EvidenceDigest,
    verification_receipt_digest: &'a EvidenceDigest,
    files: &'a [SelfReleaseFileV1],
}

impl InitialSelfReleasePlanV1 {
    fn new(
        input: InitialSelfReleasePlanInputV1,
        mut files: Vec<SelfReleaseFileV1>,
    ) -> Result<Self, ConfigError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut plan = Self {
            purpose: INITIAL_RELEASE_PLAN_PURPOSE.to_owned(),
            schema_version: INITIAL_RELEASE_PLAN_SCHEMA_VERSION,
            source_head: input.source_head,
            source_sequence: input.source_sequence,
            source_attestation_digest: input.source_attestation_digest,
            workflow_policy_digest: input.workflow_policy_digest,
            verification_receipt_digest: input.verification_receipt_digest,
            files,
            document_digest: EvidenceDigest::sha256([]),
        };
        plan.document_digest = plan.calculate_digest()?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.purpose != INITIAL_RELEASE_PLAN_PURPOSE
            || self.schema_version != INITIAL_RELEASE_PLAN_SCHEMA_VERSION
            || self.source_sequence == 0
            || !valid_initial_plan_files(&self.files)
            || self.document_digest != self.calculate_digest()?
        {
            return Err(ConfigError::InvalidInitialPlan);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ConfigError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InitialSelfReleasePlanPayload {
                purpose: INITIAL_RELEASE_PLAN_PURPOSE,
                schema_version: INITIAL_RELEASE_PLAN_SCHEMA_VERSION,
                source_head: &self.source_head,
                source_sequence: self.source_sequence,
                source_attestation_digest: &self.source_attestation_digest,
                workflow_policy_digest: &self.workflow_policy_digest,
                verification_receipt_digest: &self.verification_receipt_digest,
                files: &self.files,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, ConfigError> {
        let plan: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&plan)? != bytes {
            return Err(ConfigError::NoncanonicalDocument);
        }
        plan.validate()?;
        Ok(plan)
    }

    fn matches_manifest(&self, manifest: &rdashboard::self_update::SelfReleaseManifestV1) -> bool {
        manifest.source_head == self.source_head
            && manifest.source_sequence == self.source_sequence
            && manifest.source_attestation_digest == self.source_attestation_digest
            && manifest.workflow_policy_digest == self.workflow_policy_digest
            && manifest.verification_receipt_digest == self.verification_receipt_digest
            && manifest.files == self.files
            && manifest.runtime_contract_digest == installed_self_update_runtime_contract_digest()
            && manifest.state_schema_version == SELF_UPDATE_STATE_SCHEMA_VERSION
    }
}

fn valid_initial_plan_files(files: &[SelfReleaseFileV1]) -> bool {
    if files.len() != VERSIONED_SELF_RELEASE_BINARIES.len() {
        return false;
    }
    let mut total_bytes = 0_u64;
    for (file, binary) in files.iter().zip(VERSIONED_SELF_RELEASE_BINARIES) {
        if file.path != format!("bin/{binary}") || file.mode != 0o555 || file.bytes == 0 {
            return false;
        }
        let Some(total) = total_bytes.checked_add(file.bytes) else {
            return false;
        };
        total_bytes = total;
    }
    total_bytes <= MAXIMUM_RELEASE_BYTES
}

#[derive(Serialize)]
struct InitialReleaseResultV1 {
    purpose: &'static str,
    status: &'static str,
    release_digest: EvidenceDigest,
    source_head: GitCommitId,
    source_sequence: u64,
}

fn initialize_installed_release() -> Result<InitialReleaseResultV1, ConfigError> {
    let launcher = WorkflowLauncherPolicyV1::load_root_owned()?;
    let build_policy = launcher
        .self_release_build
        .as_ref()
        .ok_or(ConfigError::PolicyMismatch)?;
    let reader_gid = launcher
        .self_release_reader_gid
        .ok_or(ConfigError::PolicyMismatch)?;
    let self_update_policy =
        load_installed_self_update_policy_from(Path::new(SELF_UPDATE_POLICY_PATH), 0)?;
    validate_installed_policy_pair(&launcher, &self_update_policy)?;
    let signing_key = load_bootstrap_self_release_signing_key(build_policy)?;
    let plan = load_initial_plan(Path::new(INITIAL_RELEASE_PLAN_PATH))?;
    validate_initial_workflow_plan(&plan)?;

    prepare_runtime_directories()?;
    reconcile_initial_work(Path::new(INITIAL_RELEASE_WORK_ROOT), reader_gid)?;
    let journal = rdashboard::self_update::SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    if !journal.records()?.is_empty() {
        return Err(ConfigError::RuntimeAlreadyUsed);
    }
    let paths = SelfUpdateRuntimePathsV1::installed();
    let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, reader_gid)?;
    if let Some(result) =
        resume_existing_initial_release(&paths, &store, &self_update_policy, &plan)?
    {
        return Ok(result);
    }

    let payload = load_initial_release_payload(Path::new(INITIAL_RELEASE_PAYLOAD_ROOT), 0)?;
    if payload.files != plan.files {
        return Err(ConfigError::InitialReleaseMismatch);
    }
    create_initial_work(Path::new(INITIAL_RELEASE_WORK_ROOT), reader_gid)?;
    let now_ms = unix_time_ms()?;
    let expires_at_ms = now_ms
        .checked_add(build_policy.signature_validity_ms)
        .ok_or(ConfigError::InvalidClock)?;
    let built = build_signed_self_release(
        Path::new(INITIAL_RELEASE_WORK_ROOT),
        INITIAL_RELEASE_OUTPUT_STEM,
        SelfReleaseManifestInputV1 {
            source_head: plan.source_head.clone(),
            source_sequence: plan.source_sequence,
            source_attestation_digest: plan.source_attestation_digest.clone(),
            workflow_policy_digest: plan.workflow_policy_digest.clone(),
            verification_receipt_digest: plan.verification_receipt_digest.clone(),
            runtime_contract_digest: self_update_policy.runtime_contract_digest.clone(),
            state_schema_version: build_policy.state_schema_version,
        },
        payload.sources,
        SelfReleaseSignatureInputV1 {
            key_id: self_update_policy.key_id.clone(),
            key_epoch: self_update_policy.key_epoch,
            archive_digest: EvidenceDigest::sha256([]),
            archive_bytes: 1,
            issued_at_ms: now_ms,
            expires_at_ms,
        },
        &signing_key,
        0,
        reader_gid,
    )?;
    built.descriptor.verify(&self_update_policy, now_ms)?;
    let release_digest =
        stage_or_reuse_initial_release(&paths, &store, &built, &self_update_policy, &plan, now_ms)?;
    initialize_release_pointers(&paths, 0, &store, &release_digest)?;
    reconcile_initial_work(Path::new(INITIAL_RELEASE_WORK_ROOT), reader_gid)?;
    Ok(initial_result("initialized", release_digest, &plan))
}

fn stage_or_reuse_initial_release(
    paths: &SelfUpdateRuntimePathsV1,
    store: &SelfReleaseStoreV1,
    built: &BuiltSelfReleaseV1,
    policy: &InstalledSelfUpdatePolicyV1,
    plan: &InitialSelfReleasePlanV1,
    now_ms: i64,
) -> Result<EvidenceDigest, ConfigError> {
    let release_digest = built.descriptor.manifest.manifest_digest.clone();
    let release_path = paths.releases.join(release_digest.as_str());
    match fs::symlink_metadata(release_path) {
        Ok(_) => {
            let staged = store.verify_staged(&release_digest)?;
            staged.verify(policy, now_ms.min(staged.expires_at_ms))?;
            if !plan.matches_manifest(&staged.manifest) {
                return Err(ConfigError::InitialReleaseMismatch);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let staged =
                store.stage(&built.descriptor_path, &built.archive_path, policy, now_ms)?;
            if staged.manifest_digest != release_digest {
                return Err(ConfigError::InitialReleaseMismatch);
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(release_digest)
}

fn validate_initial_workflow_plan(plan: &InitialSelfReleasePlanV1) -> Result<(), ConfigError> {
    let workflows = load_installed_workflow_catalog_as_root()?;
    let rdashboard = ProjectId::from_str("rdashboard").map_err(|_| ConfigError::PolicyMismatch)?;
    if workflows
        .project(&rdashboard)
        .is_none_or(|project| project.workflow_policy_digest != plan.workflow_policy_digest)
    {
        return Err(ConfigError::InitialReleaseMismatch);
    }
    Ok(())
}

fn resume_existing_initial_release(
    paths: &SelfUpdateRuntimePathsV1,
    store: &SelfReleaseStoreV1,
    policy: &InstalledSelfUpdatePolicyV1,
    plan: &InitialSelfReleasePlanV1,
) -> Result<Option<InitialReleaseResultV1>, ConfigError> {
    let current = optional_current(paths, store)?;
    let last_known_good = optional_last_known_good(paths, store)?;
    let Some(release_digest) = current.clone().or_else(|| last_known_good.clone()) else {
        return Ok(None);
    };
    if current.is_some() && current != last_known_good {
        return Err(ConfigError::UnsafeInitialState);
    }
    let descriptor = store.verify_staged(&release_digest)?;
    descriptor.verify(policy, unix_time_ms()?.min(descriptor.expires_at_ms))?;
    if !plan.matches_manifest(&descriptor.manifest) {
        return Err(ConfigError::InitialReleaseMismatch);
    }
    let status = if current.is_some() {
        "already_initialized"
    } else {
        initialize_release_pointers(paths, 0, store, &release_digest)?;
        "resumed_initialization"
    };
    Ok(Some(initial_result(status, release_digest, plan)))
}

fn validate_installed_policy_pair(
    launcher: &WorkflowLauncherPolicyV1,
    self_update: &InstalledSelfUpdatePolicyV1,
) -> Result<(), ConfigError> {
    launcher.validate()?;
    self_update.validate_versioned_application_payload()?;
    let build_policy = launcher
        .self_release_build
        .as_ref()
        .ok_or(ConfigError::PolicyMismatch)?;
    if build_policy.self_update_policy != *self_update
        || launcher.self_release_reader_gid.is_none()
        || self_update.runtime_contract_digest != installed_self_update_runtime_contract_digest()
        || self_update.minimum_state_schema_version != SELF_UPDATE_STATE_SCHEMA_VERSION
        || self_update.maximum_state_schema_version != SELF_UPDATE_STATE_SCHEMA_VERSION
        || self_update.maximum_release_bytes != MAXIMUM_RELEASE_BYTES
        || build_policy.state_schema_version != SELF_UPDATE_STATE_SCHEMA_VERSION
        || build_policy.signature_validity_ms != SIGNATURE_VALIDITY_MS
    {
        return Err(ConfigError::PolicyMismatch);
    }
    Ok(())
}

fn initial_result(
    status: &'static str,
    release_digest: EvidenceDigest,
    plan: &InitialSelfReleasePlanV1,
) -> InitialReleaseResultV1 {
    InitialReleaseResultV1 {
        purpose: "rdashboard.initial-self-release-result.v1",
        status,
        release_digest,
        source_head: plan.source_head.clone(),
        source_sequence: plan.source_sequence,
    }
}

fn optional_current(
    paths: &SelfUpdateRuntimePathsV1,
    store: &SelfReleaseStoreV1,
) -> Result<Option<EvidenceDigest>, ConfigError> {
    optional_pointer(Path::new(SELF_UPDATE_CURRENT_LINK), || {
        read_current_release(paths, 0, store)
    })
}

fn optional_last_known_good(
    paths: &SelfUpdateRuntimePathsV1,
    store: &SelfReleaseStoreV1,
) -> Result<Option<EvidenceDigest>, ConfigError> {
    optional_pointer(Path::new(SELF_UPDATE_LKG_LINK), || {
        read_last_known_good_release(paths, 0, store)
    })
}

fn optional_pointer<F>(path: &Path, read: F) -> Result<Option<EvidenceDigest>, ConfigError>
where
    F: FnOnce() -> Result<EvidenceDigest, rdashboard::self_update_runtime::SelfUpdateRuntimeError>,
{
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn prepare_runtime_directories() -> Result<(), ConfigError> {
    ensure_root_directory(Path::new(SELF_UPDATE_ROOT), 0o711)?;
    ensure_root_directory(Path::new(SELF_RELEASE_ROOT), 0o711)?;
    ensure_root_directory(Path::new(SELF_UPDATE_BACKUP_ROOT), 0o700)?;
    ensure_root_directory(Path::new(SELF_UPDATE_JOURNAL_ROOT), 0o700)
}

fn ensure_root_directory(path: &Path, mode: u32) -> Result<(), ConfigError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if mode == 0o711
        && metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == 0
        && metadata.permissions().mode() & 0o7777 == 0o700
    {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    validate_directory(path, 0, None, mode)
}

fn create_initial_work(path: &Path, reader_gid: u32) -> Result<(), ConfigError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    rustix::fs::chown(
        path,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::from_raw(reader_gid)),
    )
    .map_err(std::io::Error::from)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o2750))?;
    validate_directory(path, 0, Some(reader_gid), 0o2750)
}

fn reconcile_initial_work(path: &Path, reader_gid: u32) -> Result<(), ConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != 0 {
        return Err(ConfigError::UnsafeInitialWork);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    let prepared = metadata.gid() == reader_gid && mode == 0o2750;
    let transitional = mode == 0o700 && (metadata.gid() == 0 || metadata.gid() == reader_gid);
    if !prepared && !transitional {
        return Err(ConfigError::UnsafeInitialWork);
    }
    let allowed = [
        INITIAL_RELEASE_DESCRIPTOR_FILE,
        INITIAL_RELEASE_ARCHIVE_FILE,
    ];
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ConfigError::UnsafeInitialWork)?;
        let entry_metadata = fs::symlink_metadata(entry.path())?;
        let file_mode = entry_metadata.permissions().mode() & 0o7777;
        let maximum_bytes = if name == INITIAL_RELEASE_ARCHIVE_FILE {
            MAXIMUM_RELEASE_BYTES
        } else {
            MAX_INITIAL_PLAN_BYTES
        };
        if !prepared
            || !allowed.contains(&name.as_str())
            || entry_metadata.file_type().is_symlink()
            || !entry_metadata.is_file()
            || entry_metadata.uid() != 0
            || entry_metadata.gid() != reader_gid
            || entry_metadata.nlink() != 1
            || !matches!(file_mode, 0o600 | 0o440)
            || entry_metadata.len() > maximum_bytes
        {
            return Err(ConfigError::UnsafeInitialWork);
        }
        fs::remove_file(entry.path())?;
    }
    File::open(path)?.sync_all()?;
    fs::remove_dir(path)?;
    File::open(Path::new(SELF_UPDATE_ROOT))?.sync_all()?;
    Ok(())
}

struct InitialReleasePayloadV1 {
    sources: Vec<SelfReleaseSourceV1>,
    files: Vec<SelfReleaseFileV1>,
}

fn load_initial_release_payload(
    root: &Path,
    required_uid: u32,
) -> Result<InitialReleasePayloadV1, ConfigError> {
    validate_directory(root, required_uid, None, 0o700)?;
    let bin_root = root.join("bin");
    validate_directory(&bin_root, required_uid, None, 0o700)?;
    let expected = VERSIONED_SELF_RELEASE_BINARIES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(&bin_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ConfigError::UnsafeInitialPayload)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !expected.contains(&name)
            || !observed.insert(name)
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != required_uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o555
            || metadata.len() == 0
        {
            return Err(ConfigError::UnsafeInitialPayload);
        }
    }
    if observed != expected {
        return Err(ConfigError::UnsafeInitialPayload);
    }
    let mut sources = Vec::with_capacity(VERSIONED_SELF_RELEASE_BINARIES.len());
    let mut files = Vec::with_capacity(VERSIONED_SELF_RELEASE_BINARIES.len());
    for binary in VERSIONED_SELF_RELEASE_BINARIES {
        let source = bin_root.join(binary);
        let (bytes, sha256) = hash_initial_payload_file(&source, required_uid)?;
        let path = format!("bin/{binary}");
        sources.push(SelfReleaseSourceV1 {
            path: path.clone(),
            source,
            executable: true,
        });
        files.push(SelfReleaseFileV1 {
            path,
            mode: 0o555,
            bytes,
            sha256,
        });
    }
    if !valid_initial_plan_files(&files) {
        return Err(ConfigError::UnsafeInitialPayload);
    }
    Ok(InitialReleasePayloadV1 { sources, files })
}

fn hash_initial_payload_file(
    path: &Path,
    required_uid: u32,
) -> Result<(u64, EvidenceDigest), ConfigError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o555
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_RELEASE_BYTES
    {
        return Err(ConfigError::UnsafeInitialPayload);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(ConfigError::ConcurrentChange);
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| ConfigError::ConcurrentChange)?)
            .ok_or(ConfigError::UnsafeInitialPayload)?;
        if total > metadata.len() {
            return Err(ConfigError::ConcurrentChange);
        }
        hasher.update(&buffer[..read]);
    }
    let after = fs::symlink_metadata(path)?;
    if total != metadata.len()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
    {
        return Err(ConfigError::ConcurrentChange);
    }
    let sha256 = EvidenceDigest::from_str(&format!("{:x}", hasher.finalize()))
        .map_err(|_| ConfigError::ConcurrentChange)?;
    Ok((total, sha256))
}

fn validate_directory(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
) -> Result<(), ConfigError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || group_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(ConfigError::UnsafeDirectory(path.to_owned()));
    }
    Ok(())
}

fn load_initial_plan(path: &Path) -> Result<InitialSelfReleasePlanV1, ConfigError> {
    InitialSelfReleasePlanV1::decode_canonical(&read_stable_root_file(
        path,
        0o400,
        MAX_INITIAL_PLAN_BYTES,
    )?)
}

fn load_installed_workflow_catalog_as_root() -> Result<InstalledWorkflowCatalogV1, ConfigError> {
    let path = Path::new(INSTALLED_WORKFLOW_CATALOG_PATH);
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != 0 {
        return Err(ConfigError::UnsafeDirectory(path.to_owned()));
    }
    match mode {
        0o700 => Ok(InstalledWorkflowCatalogV1::load_root_owned()?),
        0o750 if metadata.gid() != 0 && metadata.gid() != u32::MAX => Ok(
            InstalledWorkflowCatalogV1::load_root_owned_for_group(metadata.gid())?,
        ),
        _ => Err(ConfigError::UnsafeDirectory(path.to_owned())),
    }
}

fn read_root_seed(path: &Path) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let bytes = read_stable_root_file(path, 0o600, 32)?;
    if bytes.len() != 32 {
        return Err(ConfigError::UnsafeCredential);
    }
    Ok(Zeroizing::new(bytes))
}

fn read_stable_root_file(
    path: &Path,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ConfigError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(ConfigError::UnsafeRootFile(path.to_owned()));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(ConfigError::ConcurrentChange);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || u64::try_from(bytes.len()).ok() != Some(opened.len())
    {
        return Err(ConfigError::ConcurrentChange);
    }
    Ok(bytes)
}

fn read_stdin_bounded(maximum_bytes: u64) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > maximum_bytes) {
        return Err(ConfigError::InvalidInputSize);
    }
    Ok(bytes)
}

fn require_root() -> Result<(), ConfigError> {
    if rustix::process::geteuid().is_root() {
        Ok(())
    } else {
        Err(ConfigError::RootRequired)
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error(
        "usage: rdashboard-self-update-config build-workflow-bootstrap KEY_EPOCH WORKER_UID BUILD_UID BUILD_GID SOURCE_UID BUILD_READER_GID DEPENDENCY_FETCHER_UID DEPENDENCY_FETCH_GID|extract-base-launcher|render-workflow-gateway|render-workflow-worker|build-policies KEY_EPOCH READER_GID|extract-launcher|extract-self-update|render-environment|build-initial-plan|initialize"
    )]
    InvalidInvocation,
    #[error("this command requires root")]
    RootRequired,
    #[error("input is empty or oversized")]
    InvalidInputSize,
    #[error("the self-release signing credential is unsafe")]
    UnsafeCredential,
    #[error("the launcher already contains a self-release policy")]
    SelfReleaseAlreadyConfigured,
    #[error("the launcher and self-update policies do not form the generated exact pair")]
    PolicyMismatch,
    #[error("the workflow bootstrap policy and environments are inconsistent")]
    InvalidWorkflowBootstrap,
    #[error("the document is not canonical JCS")]
    NoncanonicalDocument,
    #[error("the initial self-release plan is invalid")]
    InvalidInitialPlan,
    #[error("the self-update runtime has already recorded an operation")]
    RuntimeAlreadyUsed,
    #[error("the initial release pointers are incomplete or conflicting")]
    UnsafeInitialState,
    #[error("the installed initial release does not match the reviewed plan")]
    InitialReleaseMismatch,
    #[error("the initial release payload is unsafe or incomplete")]
    UnsafeInitialPayload,
    #[error("the initial release work directory is unsafe")]
    UnsafeInitialWork,
    #[error("an installed directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("an installed root-owned file is unsafe: {0}")]
    UnsafeRootFile(PathBuf),
    #[error("an installed input changed while it was read")]
    ConcurrentChange,
    #[error("the system clock cannot represent the release validity interval")]
    InvalidClock,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    SelfUpdate(#[from] rdashboard::self_update::SelfUpdateError),
    #[error(transparent)]
    SelfReleaseBuild(#[from] rdashboard::self_release_build::SelfReleaseBuildError),
    #[error(transparent)]
    Launcher(#[from] rdashboard::workflow_launcher::WorkflowLauncherError),
    #[error(transparent)]
    InstalledWorkflow(#[from] rdashboard::installed_workflow::InstalledWorkflowError),
    #[error(transparent)]
    Runtime(#[from] rdashboard::self_update_runtime::SelfUpdateRuntimeError),
    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),
}

impl ConfigError {
    const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidInvocation => "self_update_config_invocation_invalid",
            Self::RootRequired => "self_update_config_root_required",
            Self::InvalidInputSize | Self::Json(_) | Self::NoncanonicalDocument => {
                "self_update_config_input_invalid"
            }
            Self::UnsafeCredential => "self_update_config_credential_unsafe",
            Self::SelfReleaseAlreadyConfigured | Self::PolicyMismatch => {
                "self_update_config_policy_mismatch"
            }
            Self::InvalidWorkflowBootstrap => "self_update_config_workflow_bootstrap_invalid",
            Self::InvalidInitialPlan => "self_update_config_initial_plan_invalid",
            Self::RuntimeAlreadyUsed => "self_update_config_runtime_already_used",
            Self::UnsafeInitialState => "self_update_config_initial_state_unsafe",
            Self::InitialReleaseMismatch => "self_update_config_initial_release_mismatch",
            Self::UnsafeInitialPayload => "self_update_config_initial_payload_unsafe",
            Self::UnsafeInitialWork => "self_update_config_initial_work_unsafe",
            Self::UnsafeDirectory(_) | Self::UnsafeRootFile(_) => {
                "self_update_config_installed_input_unsafe"
            }
            Self::ConcurrentChange => "self_update_config_concurrent_change",
            Self::InvalidClock | Self::Time(_) => "self_update_config_clock_invalid",
            Self::Io(_) => "self_update_config_io_failed",
            Self::SelfUpdate(_)
            | Self::SelfReleaseBuild(_)
            | Self::Launcher(_)
            | Self::InstalledWorkflow(_) => "self_update_config_contract_failed",
            Self::Runtime(_) => "self_update_config_runtime_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use rdashboard::{
        domain::WorkflowAdapterIdV1,
        workflow_launcher::{
            WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION, WorkflowLauncherVerificationKeyConfigV1,
        },
    };

    use super::*;

    fn digest(label: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    fn test_release_files() -> Vec<SelfReleaseFileV1> {
        VERSIONED_SELF_RELEASE_BINARIES
            .iter()
            .map(|binary| SelfReleaseFileV1 {
                path: format!("bin/{binary}"),
                mode: 0o555,
                bytes: 1,
                sha256: digest(binary),
            })
            .collect()
    }

    fn base_launcher() -> WorkflowLauncherPolicyV1 {
        let grant_key = SigningKey::from_bytes(&[31; 32]);
        WorkflowLauncherPolicyV1 {
            schema_version: WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION,
            worker_uid: 1_001,
            build_uid: 1_002,
            build_gid: 1_003,
            worker_id: "shared-vps-worker-1".to_owned(),
            host_id: "production-vps".to_owned(),
            grant_issuer: "workflow-gateway".to_owned(),
            launcher_audience: "workflow-launcher".to_owned(),
            minimum_grant_key_epoch: 1,
            grant_verification_keys: vec![WorkflowLauncherVerificationKeyConfigV1 {
                key_id: "workflow-key-1".to_owned(),
                key_epoch: 1,
                public_key_base64url: URL_SAFE_NO_PAD.encode(grant_key.verifying_key().as_bytes()),
                active_from_ms: 1,
                signing_retired_at_ms: None,
                verify_until_ms: None,
                revoked_at_ms: None,
            }],
            allowed_adapters: vec![WorkflowAdapterIdV1::WorkerBareBinCiV1],
            rootless_oci: None,
            rootless_oci_builds: Vec::new(),
            self_release_build: None,
            self_release_reader_gid: None,
            max_concurrent_jobs: 2,
            max_journal_records: 128,
        }
    }

    #[test]
    fn workflow_bootstrap_bundle_keeps_policy_and_both_environments_in_lockstep() {
        let input = WorkflowBootstrapInputV1 {
            key_epoch: 3,
            worker_uid: 1_001,
            build_uid: 1_002,
            build_gid: 1_003,
            source_uid: 1_004,
            build_reader_gid: 1_005,
            dependency_fetcher_uid: 1_006,
            dependency_fetch_gid: 1_007,
        };
        let bundle = WorkflowBootstrapBundleV1::new(input, &[29; 32])
            .expect("build workflow bootstrap bundle");
        let bytes = bundle.canonical_bytes().expect("canonical workflow bundle");
        let decoded = WorkflowBootstrapBundleV1::decode_canonical(&bytes)
            .expect("decode workflow bootstrap bundle");
        let key = &decoded.launcher_policy.grant_verification_keys[0];

        assert_eq!(decoded, bundle);
        assert_eq!(key.key_epoch, input.key_epoch);
        assert!(decoded.gateway.render().contains(&format!(
            "RDASHBOARD_WORKFLOW_GRANT_PUBLIC_KEY={}\n",
            key.public_key_base64url
        )));
        assert!(
            decoded
                .worker
                .render()
                .contains("RDASHBOARD_WORKER_SLOTS=1\n")
        );
        assert!(
            decoded
                .worker
                .render()
                .contains("RDASHBOARD_DEPENDENCY_FETCHER_UID=1006\n")
        );
        assert_eq!(decoded.launcher_policy.max_concurrent_jobs, 1);
    }

    #[test]
    fn workflow_bootstrap_rejects_overlapping_service_identities() {
        let result = WorkflowBootstrapBundleV1::new(
            WorkflowBootstrapInputV1 {
                key_epoch: 1,
                worker_uid: 1_001,
                build_uid: 1_001,
                build_gid: 1_003,
                source_uid: 1_004,
                build_reader_gid: 1_005,
                dependency_fetcher_uid: 1_006,
                dependency_fetch_gid: 1_007,
            },
            &[29; 32],
        );

        assert!(matches!(result, Err(ConfigError::InvalidWorkflowBootstrap)));
    }

    #[test]
    fn generated_bundle_binds_one_exact_policy_pair() {
        let seed = [47; 32];
        let bundle = SelfUpdatePolicyBundleV1::new(base_launcher(), &seed, 3, 1_004)
            .expect("build policy bundle");
        let canonical = bundle.canonical_bytes().expect("canonical bundle");
        let decoded =
            SelfUpdatePolicyBundleV1::decode_canonical(&canonical).expect("decode bundle");

        assert_eq!(decoded, bundle);
        assert_eq!(
            decoded
                .launcher_policy
                .self_release_build
                .as_ref()
                .expect("self-release policy")
                .self_update_policy,
            decoded.self_update_policy
        );
        assert_eq!(
            decoded.self_update_policy.files.len(),
            VERSIONED_SELF_RELEASE_BINARIES.len()
        );
        assert_eq!(
            decoded.self_update_policy.runtime_contract_digest,
            installed_self_update_runtime_contract_digest()
        );
    }

    #[test]
    fn generator_refuses_to_silently_replace_an_existing_release_authority() {
        let seed = [47; 32];
        let bundle = SelfUpdatePolicyBundleV1::new(base_launcher(), &seed, 1, 1_004)
            .expect("build policy bundle");
        assert!(matches!(
            SelfUpdatePolicyBundleV1::new(bundle.launcher_policy, &seed, 2, 1_004),
            Err(ConfigError::SelfReleaseAlreadyConfigured)
        ));
    }

    #[test]
    fn initial_plan_is_canonical_and_evidence_bound() {
        let plan = InitialSelfReleasePlanV1::new(
            InitialSelfReleasePlanInputV1 {
                source_head: GitCommitId::from_str(&"a".repeat(40)).expect("source SHA"),
                source_sequence: 7,
                source_attestation_digest: digest("source"),
                workflow_policy_digest: digest("workflow"),
                verification_receipt_digest: digest("verification"),
            },
            test_release_files(),
        )
        .expect("initial plan");
        let bytes = plan.canonical_bytes().expect("canonical plan");
        assert_eq!(
            InitialSelfReleasePlanV1::decode_canonical(&bytes).expect("decode plan"),
            plan
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn staged_initial_release_is_reused_after_a_pre_pointer_crash() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let uid = fs::symlink_metadata(directory.path())
            .expect("temporary metadata")
            .uid();
        let gid = fs::symlink_metadata(directory.path())
            .expect("temporary metadata")
            .gid();
        let releases = directory.path().join("releases");
        fs::create_dir(&releases).expect("create release root");
        fs::set_permissions(&releases, fs::Permissions::from_mode(0o711))
            .expect("protect release root");
        let source_root = directory.path().join("source");
        fs::create_dir(&source_root).expect("create source root");
        let sources = VERSIONED_SELF_RELEASE_BINARIES
            .iter()
            .map(|binary| {
                let source = source_root.join(binary);
                fs::write(&source, binary.as_bytes()).expect("write source binary");
                fs::set_permissions(&source, fs::Permissions::from_mode(0o555))
                    .expect("protect source binary");
                SelfReleaseSourceV1 {
                    path: format!("bin/{binary}"),
                    source,
                    executable: true,
                }
            })
            .collect::<Vec<_>>();
        let first_build = directory.path().join("first-build");
        let second_build = directory.path().join("second-build");
        for root in [&first_build, &second_build] {
            fs::create_dir(root).expect("create build root");
            fs::set_permissions(root, fs::Permissions::from_mode(0o2750))
                .expect("protect build root");
        }
        let seed = [47; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let bundle = SelfUpdatePolicyBundleV1::new(base_launcher(), &seed, 1, 1_004)
            .expect("build policy bundle");
        let plan_input = InitialSelfReleasePlanInputV1 {
            source_head: GitCommitId::from_str(&"b".repeat(40)).expect("source SHA"),
            source_sequence: 9,
            source_attestation_digest: digest("source"),
            workflow_policy_digest: digest("workflow"),
            verification_receipt_digest: digest("verification"),
        };
        let manifest = || SelfReleaseManifestInputV1 {
            source_head: plan_input.source_head.clone(),
            source_sequence: plan_input.source_sequence,
            source_attestation_digest: plan_input.source_attestation_digest.clone(),
            workflow_policy_digest: plan_input.workflow_policy_digest.clone(),
            verification_receipt_digest: plan_input.verification_receipt_digest.clone(),
            runtime_contract_digest: installed_self_update_runtime_contract_digest(),
            state_schema_version: SELF_UPDATE_STATE_SCHEMA_VERSION,
        };
        let signature = |issued_at_ms| SelfReleaseSignatureInputV1 {
            key_id: bundle.self_update_policy.key_id.clone(),
            key_epoch: bundle.self_update_policy.key_epoch,
            archive_digest: digest("replaced by builder"),
            archive_bytes: 1,
            issued_at_ms,
            expires_at_ms: issued_at_ms + SIGNATURE_VALIDITY_MS,
        };
        let first = build_signed_self_release(
            &first_build,
            "first",
            manifest(),
            sources.clone(),
            signature(1_000),
            &signing_key,
            uid,
            gid,
        )
        .expect("build first signed release");
        let plan = InitialSelfReleasePlanV1::new(
            plan_input.clone(),
            first.descriptor.manifest.files.clone(),
        )
        .expect("initial plan");
        let second = build_signed_self_release(
            &second_build,
            "second",
            manifest(),
            sources,
            signature(2_000),
            &signing_key,
            uid,
            gid,
        )
        .expect("build second signed release");
        assert_eq!(
            first.descriptor.manifest.manifest_digest,
            second.descriptor.manifest.manifest_digest
        );
        assert_ne!(first.descriptor, second.descriptor);

        let store = SelfReleaseStoreV1::open(&releases, uid, uid, gid).expect("open release store");
        let staged = store
            .stage(
                &first.descriptor_path,
                &first.archive_path,
                &bundle.self_update_policy,
                1_500,
            )
            .expect("stage first release");
        let paths = SelfUpdateRuntimePathsV1 {
            root: directory.path().to_owned(),
            releases,
            backups: directory.path().join("unused-backups"),
            current_link: directory.path().join("unused-current"),
            last_known_good_link: directory.path().join("unused-lkg"),
            databases: Vec::new(),
        };
        assert_eq!(
            stage_or_reuse_initial_release(
                &paths,
                &store,
                &second,
                &bundle.self_update_policy,
                &plan,
                2_500,
            )
            .expect("reuse staged release"),
            staged.manifest_digest
        );
    }

    #[test]
    fn initial_payload_requires_the_exact_root_without_extra_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let uid = fs::symlink_metadata(directory.path())
            .expect("temporary metadata")
            .uid();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protect payload root");
        let bin = directory.path().join("bin");
        fs::create_dir(&bin).expect("create bin root");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("protect bin root");
        for binary in VERSIONED_SELF_RELEASE_BINARIES {
            let path = bin.join(binary);
            fs::write(&path, binary.as_bytes()).expect("write payload binary");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
                .expect("protect payload binary");
        }
        assert_eq!(
            load_initial_release_payload(directory.path(), uid)
                .expect("exact payload")
                .files
                .len(),
            VERSIONED_SELF_RELEASE_BINARIES.len()
        );
        fs::write(bin.join("unexpected"), b"unexpected").expect("write unexpected file");
        assert!(matches!(
            load_initial_release_payload(directory.path(), uid),
            Err(ConfigError::UnsafeInitialPayload)
        ));
    }

    #[test]
    fn command_surface_has_no_caller_selected_paths() {
        assert_eq!(
            parse_command(&[
                "rdashboard-self-update-config".to_owned(),
                "build-policies".to_owned(),
                "2".to_owned(),
                "1004".to_owned(),
            ])
            .expect("build command"),
            Command::BuildPolicies {
                key_epoch: 2,
                reader_gid: 1_004,
            }
        );
        assert!(matches!(
            parse_command(&[
                "rdashboard-self-update-config".to_owned(),
                "initialize".to_owned(),
                "/tmp/caller-path".to_owned(),
            ]),
            Err(ConfigError::InvalidInvocation)
        ));
    }
}
