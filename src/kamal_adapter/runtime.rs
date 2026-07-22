use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::{IpAddr, SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr as _,
    thread,
    time::Duration,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    KamalAdapterError, KamalDeploymentObservationV1, KamalEffectKindV1, KamalRuntimeV1,
    valid_git_version,
};
use crate::{
    adapter::{
        KAMAL_SECRETS_CREDENTIAL_NAME, KAMAL_SSH_KEY_CREDENTIAL_NAME, fixed_adapter_unit_name,
    },
    build::{
        FIXED_KAMAL_NETWORK_NAME, KamalDeploymentPlanV1, KamalLoggingDriverV1, KamalMountAccessV1,
        KamalPortProtocolV1, OciDigest, ReleaseBundleReader, ReleaseBundleV1,
    },
    domain::{EvidenceDigest, ProjectId},
    oci_handoff::{ROOT_OCI_ARCHIVE_ROOT, verify_promoted_oci_archive},
    phase6::AuthorizedPhaseSpecV1,
    rimg_adapter::runtime::{
        read_stable_private_file, validate_executable, validate_private_directory,
    },
};

pub const KAMAL_ADAPTER_CONFIG_PATH: &str =
    "/etc/rdashboard/projects/rimg/kamal-adapter-runtime.jcs";
const PROJECT_CONFIG_ROOT: &str = "/etc/rdashboard/projects";
pub const KAMAL_EXECUTABLE_PATH: &str = "/usr/libexec/rdashboard/kamal";
pub const DOCKER_EXECUTABLE_PATH: &str = "/usr/bin/docker";
pub const SKOPEO_EXECUTABLE_PATH: &str = "/usr/bin/skopeo";
pub const RELEASE_BUNDLE_ROOT: &str = "/var/lib/rdashboard-executor/release-bundles";

const SYSTEMD_CREDENTIAL_ROOT: &str = "/run/credentials";
const GENERATED_CONFIG_FILE: &str = "kamal-deploy.json";
const GENERATED_RUNTIME_ENV_FILE: &str = "stable-backend.env";
const EXPECTED_KAMAL_VERSION: &str = "2.12.0";
const EPHEMERAL_REGISTRY_CONTAINER: &str = "rdashboard-registry";
const EPHEMERAL_REGISTRY_LABEL: &str = "io.rdashboard.role=ephemeral-registry-v1";
const STABLE_ROUTER_ROLE: &str = "stable-router-v1";
const STABLE_ROUTER_VOLUME_ROLE: &str = "stable-router-state-v1";
const STABLE_BACKEND_ROLE: &str = "stable-backend-v1";
const STABLE_ROUTER_STATE_PATH: &str = "/home/kamal-proxy/.config/kamal-proxy/kamal-proxy.state";
const MIN_REGISTRY_STORAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REGISTRY_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const REGISTRY_START_ATTEMPTS: u8 = 10;
const STABLE_ROUTER_START_ATTEMPTS: u8 = 30;
const MAX_STABLE_NETWORK_CONTAINERS: usize = 256;
const MAX_RUNTIME_CONFIG_BYTES: u64 = 32 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_COMMAND_STDOUT_BYTES: usize = 64 * 1024;
const MAX_SECRET_VALUE_BYTES: usize = 4096;
const KAMAL_COMPLETION_MARGIN_MS: u64 = 30_000;
const VERSION_OBSERVATION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const VERSION_OBSERVATION_ATTEMPTS: u8 = 3;
const MAX_HEALTH_PATH_BYTES: usize = 256;
const MAX_HEALTH_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_STABLE_NAME_BYTES: usize = 160;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledKamalAdapterRuntimeV3 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub installed_kamal_policy_digest: EvidenceDigest,
    pub template_digest: EvidenceDigest,
    pub credential_versions_digest: EvidenceDigest,
    pub kamal_sha256: EvidenceDigest,
    pub docker_sha256: EvidenceDigest,
    pub skopeo_sha256: EvidenceDigest,
    pub registry_image: String,
    pub registry_local_image_id: OciDigest,
    pub registry_storage_bytes: u64,
    pub stable_router_image: String,
    pub stable_router_local_image_id: OciDigest,
    pub secrets_sha256: EvidenceDigest,
    pub ssh_private_key_sha256: EvidenceDigest,
    pub kamal_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledHttpHealthProbeV1 {
    pub path: String,
    pub expected_status: u16,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    pub attempts: u16,
}

impl InstalledHttpHealthProbeV1 {
    fn is_valid(&self) -> bool {
        self.path.starts_with('/')
            && self.path.len() <= MAX_HEALTH_PATH_BYTES
            && !self.path.starts_with("//")
            && self.path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
            })
            && (200..=299).contains(&self.expected_status)
            && (100..=5_000).contains(&self.timeout_ms)
            && (100..=5_000).contains(&self.interval_ms)
            && (1..=120).contains(&self.attempts)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledKamalAdapterRuntimeV4 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub installed_kamal_policy_digest: EvidenceDigest,
    pub template_digest: EvidenceDigest,
    pub credential_versions_digest: EvidenceDigest,
    pub kamal_sha256: EvidenceDigest,
    pub docker_sha256: EvidenceDigest,
    pub skopeo_sha256: EvidenceDigest,
    pub registry_image: String,
    pub registry_local_image_id: OciDigest,
    pub registry_storage_bytes: u64,
    pub stable_router_image: String,
    pub stable_router_local_image_id: OciDigest,
    pub secrets_sha256: EvidenceDigest,
    pub ssh_private_key_sha256: EvidenceDigest,
    pub kamal_version: String,
    pub stable_http_health: InstalledHttpHealthProbeV1,
}

#[derive(Clone, Debug)]
enum InstalledStableHealthV1 {
    Docker,
    Http(InstalledHttpHealthProbeV1),
}

#[derive(Clone, Debug)]
struct InstalledKamalAdapterRuntime {
    project_id: ProjectId,
    installed_rimg_policy_digest: EvidenceDigest,
    installed_kamal_policy_digest: EvidenceDigest,
    template_digest: EvidenceDigest,
    credential_versions_digest: EvidenceDigest,
    kamal_sha256: EvidenceDigest,
    docker_sha256: EvidenceDigest,
    skopeo_sha256: EvidenceDigest,
    registry_image: String,
    registry_local_image_id: OciDigest,
    registry_storage_bytes: u64,
    stable_router_image: String,
    stable_router_local_image_id: OciDigest,
    secrets_sha256: EvidenceDigest,
    ssh_private_key_sha256: EvidenceDigest,
    kamal_version: String,
    stable_health: InstalledStableHealthV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StableRouteIdentityV1 {
    router_container: String,
    router_volume: String,
    proxy_service: String,
    network_alias: String,
    app_port: u16,
}

impl StableRouteIdentityV1 {
    fn from_plan(plan: &KamalDeploymentPlanV1) -> Result<Self, KamalAdapterError> {
        let mut ports = plan
            .ports()
            .iter()
            .filter(|port| port.protocol == KamalPortProtocolV1::Tcp);
        let app_port = ports
            .next()
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?
            .container_port;
        if ports.next().is_some() {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        Self::from_parts(plan.project_id(), plan.network_alias().as_str(), app_port)
    }

    fn from_parts(
        project_id: &ProjectId,
        network_alias: &str,
        app_port: u16,
    ) -> Result<Self, KamalAdapterError> {
        let project = project_id.as_str();
        let route = Self {
            router_container: format!("rdashboard-{project}-router"),
            router_volume: format!("rdashboard-{project}-router-state"),
            proxy_service: format!("{project}-internal"),
            network_alias: network_alias.to_owned(),
            app_port,
        };
        if app_port == 0
            || network_alias.is_empty()
            || [
                &route.router_container,
                &route.router_volume,
                &route.proxy_service,
            ]
            .into_iter()
            .any(|name| name.len() > MAX_STABLE_NAME_BYTES)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        Ok(route)
    }
}

fn installed_runtime_config_path(project_id: &ProjectId) -> PathBuf {
    if project_id.as_str() == "rimg" {
        PathBuf::from(KAMAL_ADAPTER_CONFIG_PATH)
    } else {
        Path::new(PROJECT_CONFIG_ROOT)
            .join(project_id.as_str())
            .join("kamal-adapter-runtime.jcs")
    }
}

impl InstalledKamalAdapterRuntime {
    fn load(
        path: &Path,
        kamal_path: &Path,
        docker_path: &Path,
        skopeo_path: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Self, KamalAdapterError> {
        let bytes = read_stable_private_file(path, required_uid, MAX_RUNTIME_CONFIG_BYTES)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        let schema_version = serde_json::from_slice::<serde_json::Value>(&bytes)?
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?;
        let config = match schema_version {
            3 => {
                let legacy: InstalledKamalAdapterRuntimeV3 = serde_json::from_slice(&bytes)?;
                if serde_jcs::to_vec(&legacy)? != bytes
                    || legacy.purpose != "rdashboard.installed-kamal-adapter-runtime.v3"
                    || legacy.schema_version != 3
                    || legacy.project_id.as_str() != "rimg"
                {
                    return Err(KamalAdapterError::RuntimeConfigMismatch);
                }
                Self::from_v3(legacy)
            }
            4 => {
                let current: InstalledKamalAdapterRuntimeV4 = serde_json::from_slice(&bytes)?;
                if serde_jcs::to_vec(&current)? != bytes
                    || current.purpose != "rdashboard.installed-kamal-adapter-runtime.v4"
                    || current.schema_version != 4
                    || !current.stable_http_health.is_valid()
                {
                    return Err(KamalAdapterError::RuntimeConfigMismatch);
                }
                Self::from_v4(current)
            }
            _ => return Err(KamalAdapterError::RuntimeConfigMismatch),
        };
        if config.project_id != spec.project_id
            || config.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
            || config.kamal_version != EXPECTED_KAMAL_VERSION
            || !valid_registry_image(&config.registry_image)
            || !valid_registry_image(&config.stable_router_image)
            || !(MIN_REGISTRY_STORAGE_BYTES..=MAX_REGISTRY_STORAGE_BYTES)
                .contains(&config.registry_storage_bytes)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        validate_executable(kamal_path, required_uid, &config.kamal_sha256)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        validate_executable(docker_path, required_uid, &config.docker_sha256)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        validate_executable(skopeo_path, required_uid, &config.skopeo_sha256)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        let version = run_bounded_command(kamal_path, &["version"])?;
        if !version.status.success()
            || String::from_utf8(version.stdout)
                .ok()
                .is_none_or(|value| value.trim() != EXPECTED_KAMAL_VERSION)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        Ok(config)
    }

    fn from_v3(config: InstalledKamalAdapterRuntimeV3) -> Self {
        Self {
            project_id: config.project_id,
            installed_rimg_policy_digest: config.installed_rimg_policy_digest,
            installed_kamal_policy_digest: config.installed_kamal_policy_digest,
            template_digest: config.template_digest,
            credential_versions_digest: config.credential_versions_digest,
            kamal_sha256: config.kamal_sha256,
            docker_sha256: config.docker_sha256,
            skopeo_sha256: config.skopeo_sha256,
            registry_image: config.registry_image,
            registry_local_image_id: config.registry_local_image_id,
            registry_storage_bytes: config.registry_storage_bytes,
            stable_router_image: config.stable_router_image,
            stable_router_local_image_id: config.stable_router_local_image_id,
            secrets_sha256: config.secrets_sha256,
            ssh_private_key_sha256: config.ssh_private_key_sha256,
            kamal_version: config.kamal_version,
            stable_health: InstalledStableHealthV1::Docker,
        }
    }

    fn from_v4(config: InstalledKamalAdapterRuntimeV4) -> Self {
        Self {
            project_id: config.project_id,
            installed_rimg_policy_digest: config.installed_rimg_policy_digest,
            installed_kamal_policy_digest: config.installed_kamal_policy_digest,
            template_digest: config.template_digest,
            credential_versions_digest: config.credential_versions_digest,
            kamal_sha256: config.kamal_sha256,
            docker_sha256: config.docker_sha256,
            skopeo_sha256: config.skopeo_sha256,
            registry_image: config.registry_image,
            registry_local_image_id: config.registry_local_image_id,
            registry_storage_bytes: config.registry_storage_bytes,
            stable_router_image: config.stable_router_image,
            stable_router_local_image_id: config.stable_router_local_image_id,
            secrets_sha256: config.secrets_sha256,
            ssh_private_key_sha256: config.ssh_private_key_sha256,
            kamal_version: config.kamal_version,
            stable_health: InstalledStableHealthV1::Http(config.stable_http_health),
        }
    }
}

#[derive(Debug)]
pub struct InstalledKamalRuntimeV1 {
    config: InstalledKamalAdapterRuntime,
    kamal_path: PathBuf,
    docker_path: PathBuf,
    skopeo_path: PathBuf,
    release_bundle_root: PathBuf,
    oci_archive_root: PathBuf,
    secrets_path: PathBuf,
    ssh_key_path: PathBuf,
    job_directory: PathBuf,
    required_uid: u32,
}

impl InstalledKamalRuntimeV1 {
    pub fn new(
        job_directory: &Path,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
    ) -> Result<Self, KamalAdapterError> {
        let unit_name = fixed_adapter_unit_name(spec, sequence)?;
        let credential_root =
            Path::new(SYSTEMD_CREDENTIAL_ROOT).join(format!("{unit_name}.service"));
        let runtime_config_path = installed_runtime_config_path(&spec.project_id);
        Self::new_bound(
            &runtime_config_path,
            Path::new(KAMAL_EXECUTABLE_PATH),
            Path::new(DOCKER_EXECUTABLE_PATH),
            Path::new(SKOPEO_EXECUTABLE_PATH),
            Path::new(RELEASE_BUNDLE_ROOT),
            Path::new(ROOT_OCI_ARCHIVE_ROOT),
            &credential_root.join(KAMAL_SECRETS_CREDENTIAL_NAME),
            &credential_root.join(KAMAL_SSH_KEY_CREDENTIAL_NAME),
            job_directory,
            0,
            spec,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_bound(
        runtime_config_path: &Path,
        kamal_path: &Path,
        docker_path: &Path,
        skopeo_path: &Path,
        release_bundle_root: &Path,
        oci_archive_root: &Path,
        secrets_path: &Path,
        ssh_key_path: &Path,
        job_directory: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Self, KamalAdapterError> {
        validate_private_directory(job_directory, required_uid)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        let config = InstalledKamalAdapterRuntime::load(
            runtime_config_path,
            kamal_path,
            docker_path,
            skopeo_path,
            required_uid,
            spec,
        )?;
        let secrets = read_stable_private_file(secrets_path, required_uid, MAX_CREDENTIAL_BYTES)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        if EvidenceDigest::sha256(&secrets) != config.secrets_sha256 {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        let ssh_key = read_stable_private_file(ssh_key_path, required_uid, MAX_CREDENTIAL_BYTES)
            .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        if EvidenceDigest::sha256(&ssh_key) != config.ssh_private_key_sha256 {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        Ok(Self {
            config,
            kamal_path: kamal_path.to_path_buf(),
            docker_path: docker_path.to_path_buf(),
            skopeo_path: skopeo_path.to_path_buf(),
            release_bundle_root: release_bundle_root.to_path_buf(),
            oci_archive_root: oci_archive_root.to_path_buf(),
            secrets_path: secrets_path.to_path_buf(),
            ssh_key_path: ssh_key_path.to_path_buf(),
            job_directory: job_directory.to_path_buf(),
            required_uid,
        })
    }

    fn load_bundle(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        digest: &EvidenceDigest,
    ) -> Result<ReleaseBundleV1, KamalAdapterError> {
        let reader =
            ReleaseBundleReader::open_for_owner(&self.release_bundle_root, self.required_uid)?;
        let bundle = reader.load(&spec.project_id, digest)?;
        let plan = bundle.deployment_plan();
        if plan.project_id() != &spec.project_id
            || plan.installed_policy() != &spec.installed_policy
            || plan.network().as_str() != FIXED_KAMAL_NETWORK_NAME
            || plan.runtime_policy_digest() != &self.config.installed_kamal_policy_digest
            || plan.template_digest() != &self.config.template_digest
            || plan.credential_versions_digest() != &self.config.credential_versions_digest
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        let secret_bytes =
            read_stable_private_file(&self.secrets_path, self.required_uid, MAX_CREDENTIAL_BYTES)
                .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        validate_secret_credential(plan, &secret_bytes)?;
        Ok(bundle)
    }

    fn generated_config(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        plan: &KamalDeploymentPlanV1,
    ) -> Result<(PathBuf, EvidenceDigest), KamalAdapterError> {
        let document = render_config(
            spec,
            plan,
            &self.config.stable_health,
            path_text(&self.secrets_path)?,
            path_text(&self.ssh_key_path)?,
        )?;
        let bytes = serde_jcs::to_vec(&document)?;
        if bytes.len() > MAX_CONFIG_BYTES
            || bytes
                .windows(2)
                .any(|window| matches!(window, b"<%" | b"%>"))
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        let path = self.job_directory.join(GENERATED_CONFIG_FILE);
        materialize_or_verify(&path, self.required_uid, &bytes)?;
        Ok((path, EvidenceDigest::sha256(bytes)))
    }

    fn import_candidate_image(
        &self,
        bundle: &ReleaseBundleV1,
    ) -> Result<String, KamalAdapterError> {
        let archive_before =
            verify_promoted_oci_archive(&self.oci_archive_root, self.required_uid, bundle)?;
        let source = format!("oci-archive:{}", path_text(&archive_before.path)?);
        if self.inspect_skopeo_digest(&source)? != *bundle.image_registry_digest() {
            return Err(KamalAdapterError::ImageImportMismatch);
        }
        let tag = format!(
            "localhost:5555/{}:{}",
            bundle.deployment_plan().image().as_str(),
            bundle.deployment_plan().source_head().as_str()
        );
        match self.inspect_local_image_id(&tag)? {
            Some(image_id) if image_id == *bundle.local_image_id() => {}
            Some(_) => return Err(KamalAdapterError::ImageImportMismatch),
            None => {
                let destination = format!("docker-daemon:{tag}");
                run_status_command(
                    &self.skopeo_path,
                    &skopeo_docker_import_arguments(&source, &destination),
                )?;
                if self.inspect_local_image_id(&tag)?.as_ref() != Some(bundle.local_image_id()) {
                    return Err(KamalAdapterError::ImageImportMismatch);
                }
            }
        }
        let archive_after =
            verify_promoted_oci_archive(&self.oci_archive_root, self.required_uid, bundle)?;
        if archive_after != archive_before {
            return Err(KamalAdapterError::ImageImportMismatch);
        }
        Ok(source)
    }

    fn inspect_local_image_id(
        &self,
        reference: &str,
    ) -> Result<Option<OciDigest>, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &["image", "inspect", "--format={{.Id}}", reference],
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        let value =
            String::from_utf8(output.stdout).map_err(|_| KamalAdapterError::ImageImportMismatch)?;
        OciDigest::from_str(value.trim())
            .map(Some)
            .map_err(|_| KamalAdapterError::ImageImportMismatch)
    }

    fn inspect_skopeo_digest(&self, reference: &str) -> Result<OciDigest, KamalAdapterError> {
        let arguments = skopeo_inspect_arguments(reference);
        let output = run_bounded_command(&self.skopeo_path, &arguments)?;
        if !output.status.success() {
            return Err(KamalAdapterError::CommandFailed(format!(
                "exit status {}",
                output.status
            )));
        }
        let value =
            String::from_utf8(output.stdout).map_err(|_| KamalAdapterError::ImageImportMismatch)?;
        OciDigest::from_str(value.trim()).map_err(|_| KamalAdapterError::ImageImportMismatch)
    }

    fn start_ephemeral_registry(
        &self,
        bundle: &ReleaseBundleV1,
        archive_source: &str,
    ) -> Result<(), KamalAdapterError> {
        self.remove_ephemeral_registry_if_owned()?;
        if self
            .inspect_local_image_id(&self.config.registry_image)?
            .as_ref()
            != Some(&self.config.registry_local_image_id)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        let storage = format!(
            "/var/lib/registry:rw,noexec,nosuid,nodev,size={}",
            self.config.registry_storage_bytes
        );
        run_status_command(
            &self.docker_path,
            &[
                "run",
                "--detach",
                "--name",
                EPHEMERAL_REGISTRY_CONTAINER,
                "--label",
                EPHEMERAL_REGISTRY_LABEL,
                "--publish",
                "127.0.0.1:5555:5000",
                "--read-only",
                "--memory=128m",
                "--pids-limit=128",
                "--restart=no",
                "--log-driver=none",
                "--tmpfs",
                &storage,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                &self.config.registry_image,
            ],
        )?;
        let result = self.populate_ephemeral_registry(bundle, archive_source);
        if result.is_err() {
            let cleanup = self.remove_ephemeral_registry_if_owned();
            if cleanup.is_err() {
                return Err(KamalAdapterError::RegistryCleanupFailed);
            }
        }
        result
    }

    fn populate_ephemeral_registry(
        &self,
        bundle: &ReleaseBundleV1,
        archive_source: &str,
    ) -> Result<(), KamalAdapterError> {
        let target = format!(
            "docker://localhost:5555/{}:{}",
            bundle.deployment_plan().image().as_str(),
            bundle.deployment_plan().source_head().as_str()
        );
        let mut last_error = None;
        for attempt in 0..REGISTRY_START_ATTEMPTS {
            match run_status_command(
                &self.skopeo_path,
                &skopeo_registry_copy_arguments(archive_source, &target),
            ) {
                Ok(()) => {
                    if self.inspect_skopeo_digest(&target)? == *bundle.image_registry_digest() {
                        return Ok(());
                    }
                    return Err(KamalAdapterError::ImageImportMismatch);
                }
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < REGISTRY_START_ATTEMPTS {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Err(last_error.unwrap_or(KamalAdapterError::RegistryLifecycle))
    }

    fn remove_ephemeral_registry_if_owned(&self) -> Result<(), KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Image}}|{{index .Config.Labels \"io.rdashboard.role\"}}",
                EPHEMERAL_REGISTRY_CONTAINER,
            ],
        )?;
        if !output.status.success() {
            return Ok(());
        }
        let identity =
            String::from_utf8(output.stdout).map_err(|_| KamalAdapterError::RegistryLifecycle)?;
        let expected = format!(
            "{}|ephemeral-registry-v1",
            self.config.registry_local_image_id.as_str()
        );
        if identity.trim() != expected {
            return Err(KamalAdapterError::RegistryOwnershipMismatch);
        }
        run_status_command(
            &self.docker_path,
            &["container", "rm", "--force", EPHEMERAL_REGISTRY_CONTAINER],
        )
    }

    fn stable_backend_name(plan: &KamalDeploymentPlanV1) -> String {
        format!(
            "rdashboard-{}-backend-{}",
            plan.project_id().as_str(),
            plan.source_head().as_str()
        )
    }

    fn stable_runtime_environment(
        &self,
        plan: &KamalDeploymentPlanV1,
    ) -> Result<PathBuf, KamalAdapterError> {
        let secret_bytes =
            read_stable_private_file(&self.secrets_path, self.required_uid, MAX_CREDENTIAL_BYTES)
                .map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
        let expected = plan
            .secret_bindings()
            .iter()
            .map(|binding| binding.secret_name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let secrets = parse_secret_credential_names(&expected, &secret_bytes)?;
        let mut environment = BTreeMap::new();
        for entry in plan.clear_environment() {
            environment.insert(
                entry.key.as_str().to_owned(),
                entry.value.as_str().to_owned(),
            );
        }
        for binding in plan.secret_bindings() {
            let value = secrets
                .get(binding.secret_name.as_str())
                .ok_or(KamalAdapterError::RuntimeConfigMismatch)?;
            if environment
                .insert(binding.environment_key.as_str().to_owned(), value.clone())
                .is_some()
            {
                return Err(KamalAdapterError::RuntimeConfigMismatch);
            }
        }
        let mut bytes = Vec::new();
        for (name, value) in environment {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(b'\n');
        }
        let path = self.job_directory.join(GENERATED_RUNTIME_ENV_FILE);
        materialize_or_verify(&path, self.required_uid, &bytes)?;
        Ok(path)
    }

    fn ensure_stable_backend(&self, bundle: &ReleaseBundleV1) -> Result<String, KamalAdapterError> {
        let plan = bundle.deployment_plan();
        let name = Self::stable_backend_name(plan);
        let expected_identity = format!(
            "{}|{}|{}|{}",
            bundle.local_image_id().as_str(),
            STABLE_BACKEND_ROLE,
            bundle.digest().as_str(),
            plan.digest().as_str()
        );
        let inspected = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Image}}|{{index .Config.Labels \"io.rdashboard.role\"}}|{{index .Config.Labels \"io.rdashboard.release-bundle\"}}|{{index .Config.Labels \"io.rdashboard.deployment-plan\"}}",
                &name,
            ],
        )?;
        if inspected.status.success() {
            let identity = String::from_utf8(inspected.stdout)
                .map_err(|_| KamalAdapterError::StableBackendOwnershipMismatch)?;
            if identity.trim() != expected_identity {
                return Err(KamalAdapterError::StableBackendOwnershipMismatch);
            }
            run_status_command(&self.docker_path, &["container", "start", &name])?;
            self.wait_for_stable_backend_health(&name, plan)?;
            return Ok(name);
        }

        let environment = self.stable_runtime_environment(plan)?;
        let image = format!(
            "localhost:5555/{}:{}",
            plan.image().as_str(),
            plan.source_head().as_str()
        );
        if self.inspect_local_image_id(&image)?.as_ref() != Some(bundle.local_image_id()) {
            return Err(KamalAdapterError::ImageImportMismatch);
        }
        let mut arguments = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--label".to_owned(),
            format!("io.rdashboard.role={STABLE_BACKEND_ROLE}"),
            "--label".to_owned(),
            format!("io.rdashboard.release-bundle={}", bundle.digest().as_str()),
            "--label".to_owned(),
            format!("io.rdashboard.deployment-plan={}", plan.digest().as_str()),
            "--network".to_owned(),
            plan.network().as_str().to_owned(),
            "--user".to_owned(),
            format!("{}:{}", plan.run_as().uid, plan.run_as().gid),
            "--env-file".to_owned(),
            path_text(&environment)?.to_owned(),
            "--restart=unless-stopped".to_owned(),
            "--log-driver=local".to_owned(),
            "--log-opt".to_owned(),
            format!("max-size={}", plan.logging().max_size_bytes),
            "--log-opt".to_owned(),
            format!("max-file={}", plan.logging().max_files),
            "--security-opt=no-new-privileges".to_owned(),
        ];
        for mount in plan.mounts() {
            let mut value = format!(
                "type=bind,source={},target={}",
                mount.host_path.as_str(),
                mount.container_path.as_str()
            );
            if mount.access == KamalMountAccessV1::ReadOnly {
                value.push_str(",readonly");
            }
            arguments.extend(["--mount".to_owned(), value]);
        }
        arguments.push(image);
        run_status_command_owned(&self.docker_path, &arguments)?;
        self.wait_for_stable_backend_health(&name, plan)?;
        Ok(name)
    }

    fn wait_for_stable_backend_health(
        &self,
        name: &str,
        plan: &KamalDeploymentPlanV1,
    ) -> Result<(), KamalAdapterError> {
        match &self.config.stable_health {
            InstalledStableHealthV1::Docker => {
                for attempt in 0..120 {
                    let output = run_bounded_command(
                        &self.docker_path,
                        &[
                            "container",
                            "inspect",
                            "--format={{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}",
                            name,
                        ],
                    )?;
                    if output.status.success() {
                        let status = String::from_utf8(output.stdout)
                            .map_err(|_| KamalAdapterError::StableBackendUnhealthy)?;
                        if status.trim() == "healthy" {
                            return Ok(());
                        }
                        if status.trim() == "unhealthy" || status.trim() == "missing" {
                            return Err(KamalAdapterError::StableBackendUnhealthy);
                        }
                    }
                    if attempt + 1 < 120 {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            InstalledStableHealthV1::Http(probe) => {
                let route = StableRouteIdentityV1::from_plan(plan)?;
                for attempt in 0..probe.attempts {
                    if self.http_health_succeeds(name, route.app_port, probe)? {
                        return Ok(());
                    }
                    if attempt + 1 < probe.attempts {
                        thread::sleep(Duration::from_millis(probe.interval_ms));
                    }
                }
            }
        }
        Err(KamalAdapterError::StableBackendUnhealthy)
    }

    fn http_health_succeeds(
        &self,
        name: &str,
        port: u16,
        probe: &InstalledHttpHealthProbeV1,
    ) -> Result<bool, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{(index .NetworkSettings.Networks \"kamal\").IPAddress}}",
                name,
            ],
        )?;
        if !output.status.success() {
            return Ok(false);
        }
        let address = String::from_utf8(output.stdout)
            .map_err(|_| KamalAdapterError::StableBackendUnhealthy)?;
        let ip = IpAddr::from_str(address.trim())
            .map_err(|_| KamalAdapterError::StableBackendUnhealthy)?;
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(KamalAdapterError::StableBackendUnhealthy);
        }
        probe_http_health(
            SocketAddr::new(ip, port),
            probe,
            Duration::from_millis(probe.timeout_ms),
        )
    }

    fn ensure_stable_router(
        &self,
        plan: &KamalDeploymentPlanV1,
    ) -> Result<StableRouteIdentityV1, KamalAdapterError> {
        let route = StableRouteIdentityV1::from_plan(plan)?;
        let network = plan.network().as_str();
        if self
            .inspect_local_image_id(&self.config.stable_router_image)?
            .as_ref()
            != Some(&self.config.stable_router_local_image_id)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        self.ensure_stable_router_volume(&route)?;
        let inspected = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Image}}|{{index .Config.Labels \"io.rdashboard.role\"}}|{{.HostConfig.NetworkMode}}",
                &route.router_container,
            ],
        )?;
        let expected = format!(
            "{}|{}|{}",
            self.config.stable_router_local_image_id.as_str(),
            STABLE_ROUTER_ROLE,
            network
        );
        if inspected.status.success() {
            let identity = String::from_utf8(inspected.stdout)
                .map_err(|_| KamalAdapterError::StableRouterOwnershipMismatch)?;
            if identity.trim() != expected {
                return Err(KamalAdapterError::StableRouterOwnershipMismatch);
            }
            run_status_command(
                &self.docker_path,
                &["container", "start", &route.router_container],
            )?;
            if self.stable_router_has_network_alias(network, &route)? {
                self.wait_for_stable_router(&route)?;
                return Ok(route);
            }
            run_status_command(
                &self.docker_path,
                &["container", "rm", "--force", &route.router_container],
            )?;
        }
        let state_mount = format!(
            "type=volume,source={},target=/home/kamal-proxy/.config/kamal-proxy",
            route.router_volume
        );
        let http_port = format!("--http-port={}", route.app_port);
        run_status_command(
            &self.docker_path,
            &[
                "run",
                "--detach",
                "--name",
                &route.router_container,
                "--label",
                &format!("io.rdashboard.role={STABLE_ROUTER_ROLE}"),
                "--network",
                network,
                "--network-alias",
                &route.network_alias,
                "--restart=unless-stopped",
                "--read-only",
                "--memory=128m",
                "--pids-limit=128",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--log-driver=local",
                "--log-opt",
                "max-size=16m",
                "--log-opt",
                "max-file=2",
                "--mount",
                &state_mount,
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
                &self.config.stable_router_image,
                "kamal-proxy",
                "run",
                &http_port,
                "--https-port=8443",
            ],
        )?;
        if !self.stable_router_has_network_alias(network, &route)? {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        self.wait_for_stable_router(&route)?;
        Ok(route)
    }

    fn stable_router_has_network_alias(
        &self,
        network: &str,
        route: &StableRouteIdentityV1,
    ) -> Result<bool, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{json .NetworkSettings.Networks}}",
                &route.router_container,
            ],
        )?;
        if !output.status.success() {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        stable_router_has_network_alias(&output.stdout, network, &route.network_alias)
    }

    fn wait_for_stable_router(
        &self,
        route: &StableRouteIdentityV1,
    ) -> Result<(), KamalAdapterError> {
        for attempt in 0..STABLE_ROUTER_START_ATTEMPTS {
            let output = run_bounded_command(
                &self.docker_path,
                &[
                    "container",
                    "exec",
                    &route.router_container,
                    "kamal-proxy",
                    "version",
                ],
            )?;
            if output.status.success() {
                return Ok(());
            }
            if attempt + 1 < STABLE_ROUTER_START_ATTEMPTS {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Err(KamalAdapterError::StableRouterStateMismatch)
    }

    fn require_exclusive_stable_router_alias(
        &self,
        network: &str,
        route: &StableRouteIdentityV1,
    ) -> Result<(), KamalAdapterError> {
        let router = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Id}}",
                &route.router_container,
            ],
        )?;
        if !router.status.success() {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        let router_id = String::from_utf8(router.stdout)
            .map_err(|_| KamalAdapterError::StableRouterOwnershipMismatch)?;
        let router_id = router_id.trim();
        if !valid_docker_container_id(router_id) {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        let members = run_bounded_command(
            &self.docker_path,
            &[
                "network",
                "inspect",
                "--format={{range $id, $_ := .Containers}}{{println $id}}{{end}}",
                network,
            ],
        )?;
        if !members.status.success() {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        let members = String::from_utf8(members.stdout)
            .map_err(|_| KamalAdapterError::StableRouterOwnershipMismatch)?;
        let member_ids = members.lines().collect::<Vec<_>>();
        if member_ids.is_empty() || member_ids.len() > MAX_STABLE_NETWORK_CONTAINERS {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        let mut found_router = false;
        for member_id in member_ids {
            if !valid_docker_container_id(member_id) {
                return Err(KamalAdapterError::StableRouterOwnershipMismatch);
            }
            let inspected = run_bounded_command(
                &self.docker_path,
                &[
                    "container",
                    "inspect",
                    "--format={{json .NetworkSettings.Networks}}",
                    member_id,
                ],
            )?;
            if !inspected.status.success() {
                return Err(KamalAdapterError::StableRouterOwnershipMismatch);
            }
            let has_alias =
                container_has_network_alias(&inspected.stdout, network, &route.network_alias)?;
            if member_id == router_id {
                found_router = has_alias;
            } else if has_alias {
                return Err(KamalAdapterError::StableRouterOwnershipMismatch);
            }
        }
        if found_router {
            Ok(())
        } else {
            Err(KamalAdapterError::StableRouterOwnershipMismatch)
        }
    }

    fn ensure_stable_router_volume(
        &self,
        route: &StableRouteIdentityV1,
    ) -> Result<(), KamalAdapterError> {
        let inspected = run_bounded_command(
            &self.docker_path,
            &[
                "volume",
                "inspect",
                "--format={{index .Labels \"io.rdashboard.role\"}}",
                &route.router_volume,
            ],
        )?;
        if inspected.status.success() {
            let role = String::from_utf8(inspected.stdout)
                .map_err(|_| KamalAdapterError::StableRouterOwnershipMismatch)?;
            return if role.trim() == STABLE_ROUTER_VOLUME_ROLE {
                Ok(())
            } else {
                Err(KamalAdapterError::StableRouterOwnershipMismatch)
            };
        }
        run_status_command(
            &self.docker_path,
            &[
                "volume",
                "create",
                "--label",
                &format!("io.rdashboard.role={STABLE_ROUTER_VOLUME_ROLE}"),
                &route.router_volume,
            ],
        )
    }

    fn stable_router_target(
        &self,
        route: &StableRouteIdentityV1,
    ) -> Result<Option<String>, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "exec",
                &route.router_container,
                "cat",
                STABLE_ROUTER_STATE_PATH,
            ],
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        decode_stable_router_target(&output.stdout, &route.proxy_service)
    }

    fn switch_stable_router(
        &self,
        target: &str,
        route: &StableRouteIdentityV1,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<(), KamalAdapterError> {
        let target = format!("{target}:{}", route.app_port);
        if self.stable_router_target(route)?.as_deref() == Some(target.as_str()) {
            return Ok(());
        }
        let deploy_seconds = spec
            .timeouts
            .deploy_ms
            .checked_sub(KAMAL_COMPLETION_MARGIN_MS)
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?
            .div_ceil(1000);
        let deploy_timeout = format!("--deploy-timeout={deploy_seconds}s");
        let target_argument = format!("--target={target}");
        let health_path = match &self.config.stable_health {
            InstalledStableHealthV1::Docker => "/health/ready",
            InstalledStableHealthV1::Http(probe) => probe.path.as_str(),
        };
        let health_path = format!("--health-check-path={health_path}");
        run_status_command(
            &self.docker_path,
            &[
                "container",
                "exec",
                &route.router_container,
                "kamal-proxy",
                "deploy",
                &route.proxy_service,
                &target_argument,
                &health_path,
                "--health-check-interval=1s",
                "--health-check-timeout=5s",
                &deploy_timeout,
                "--drain-timeout=30s",
                "--target-timeout=30s",
            ],
        )?;
        if self.stable_router_target(route)?.as_deref() == Some(target.as_str()) {
            Ok(())
        } else {
            Err(KamalAdapterError::StableRouterStateMismatch)
        }
    }

    fn stop_owned_stable_backend(&self, bundle: &ReleaseBundleV1) -> Result<(), KamalAdapterError> {
        let name = Self::stable_backend_name(bundle.deployment_plan());
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{index .Config.Labels \"io.rdashboard.role\"}}|{{index .Config.Labels \"io.rdashboard.release-bundle\"}}",
                &name,
            ],
        )?;
        if !output.status.success() {
            return Ok(());
        }
        let expected = format!("{}|{}", STABLE_BACKEND_ROLE, bundle.digest().as_str());
        let identity = String::from_utf8(output.stdout)
            .map_err(|_| KamalAdapterError::StableBackendOwnershipMismatch)?;
        if identity.trim() != expected {
            return Err(KamalAdapterError::StableBackendOwnershipMismatch);
        }
        run_status_command(
            &self.docker_path,
            &["container", "stop", "--time=30", &name],
        )
    }

    fn remove_adopted_bootstrap_container(
        &self,
        bundle: &ReleaseBundleV1,
    ) -> Result<(), KamalAdapterError> {
        let plan = bundle.deployment_plan();
        let expected_name = format!(
            "{}-web-{}",
            plan.service().as_str(),
            plan.source_head().as_str()
        );
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Image}}|{{index .Config.Labels \"service\"}}|{{index .Config.Labels \"role\"}}|{{index .Config.Labels \"destination\"}}",
                &expected_name,
            ],
        )?;
        if !output.status.success() {
            return Ok(());
        }
        let expected = format!(
            "{}|{}|web|",
            bundle.local_image_id().as_str(),
            plan.service().as_str()
        );
        let identity = String::from_utf8(output.stdout)
            .map_err(|_| KamalAdapterError::StableBackendOwnershipMismatch)?;
        if identity.trim() != expected {
            return Err(KamalAdapterError::StableBackendOwnershipMismatch);
        }
        run_status_command(
            &self.docker_path,
            &["container", "rm", "--force", &expected_name],
        )
    }

    fn apply_stable_release(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        bundle: &ReleaseBundleV1,
        effect: KamalEffectKindV1,
    ) -> Result<(), KamalAdapterError> {
        match effect {
            KamalEffectKindV1::Deploy => {
                let Some(crate::phase6::RuntimeReleaseStateV1::Installed {
                    current_release_bundle_digest: current_digest,
                }) = spec.runtime_release_state.as_ref()
                else {
                    return Err(KamalAdapterError::RuntimeConfigMismatch);
                };
                let current = ReleaseBundleReader::open_for_owner(
                    &self.release_bundle_root,
                    self.required_uid,
                )?
                .load(&spec.project_id, current_digest)?;
                let _ = self.import_candidate_image(&current)?;
                let route = self.ensure_stable_router(current.deployment_plan())?;
                if route != StableRouteIdentityV1::from_plan(bundle.deployment_plan())? {
                    return Err(KamalAdapterError::RuntimeConfigMismatch);
                }
                let target_endpoint = format!(
                    "{}:{}",
                    Self::stable_backend_name(bundle.deployment_plan()),
                    route.app_port
                );
                if self.stable_router_target(&route)?.as_deref() == Some(target_endpoint.as_str()) {
                    let _ = self.ensure_stable_backend(bundle)?;
                    self.remove_adopted_bootstrap_container(&current)?;
                    self.require_exclusive_stable_router_alias(
                        current.deployment_plan().network().as_str(),
                        &route,
                    )?;
                    if current.digest() != bundle.digest() {
                        self.stop_owned_stable_backend(&current)?;
                    }
                    return Ok(());
                }
                let current_name = self.ensure_stable_backend(&current)?;
                self.switch_stable_router(&current_name, &route, spec)?;
                self.remove_adopted_bootstrap_container(&current)?;
                self.require_exclusive_stable_router_alias(
                    current.deployment_plan().network().as_str(),
                    &route,
                )?;

                let target_name = self.ensure_stable_backend(bundle)?;
                self.switch_stable_router(&target_name, &route, spec)?;
                if current.digest() != bundle.digest() {
                    self.stop_owned_stable_backend(&current)?;
                }
            }
            KamalEffectKindV1::Rollback => {
                let route = self.ensure_stable_router(bundle.deployment_plan())?;
                self.require_exclusive_stable_router_alias(
                    bundle.deployment_plan().network().as_str(),
                    &route,
                )?;
                let target_name = self.ensure_stable_backend(bundle)?;
                self.switch_stable_router(&target_name, &route, spec)?;
                let failed_digest = spec
                    .release_bundle_digest
                    .as_ref()
                    .ok_or(KamalAdapterError::MissingReleaseBundle)?;
                if failed_digest != bundle.digest() {
                    let failed = ReleaseBundleReader::open_for_owner(
                        &self.release_bundle_root,
                        self.required_uid,
                    )?
                    .load(&spec.project_id, failed_digest)?;
                    self.stop_owned_stable_backend(&failed)?;
                }
            }
            KamalEffectKindV1::Bootstrap => {
                return Err(KamalAdapterError::RuntimeConfigMismatch);
            }
        }
        Ok(())
    }

    fn observe_version(&self, config_path: &Path) -> Result<Option<String>, KamalAdapterError> {
        let output = run_bounded_command(
            &self.kamal_path,
            &[
                "app",
                "version",
                "--quiet",
                "--config-file",
                path_text(config_path)?,
                "--skip-hooks",
            ],
        )?;
        if !output.status.success() {
            return Err(KamalAdapterError::CommandFailed(format!(
                "exit status {}",
                output.status
            )));
        }
        let version = String::from_utf8(output.stdout)
            .map_err(|_| KamalAdapterError::DeploymentObservationMismatch)?;
        let version = version.trim();
        if version.is_empty() {
            return Ok(None);
        }
        if !valid_git_version(version) {
            return Err(KamalAdapterError::DeploymentObservationMismatch);
        }
        Ok(Some(version.to_owned()))
    }

    fn observe_version_before_mutation(
        &self,
        config_path: &Path,
        effect: KamalEffectKindV1,
    ) -> Result<Option<String>, KamalAdapterError> {
        for attempt in 0..VERSION_OBSERVATION_ATTEMPTS {
            let observed = self.observe_version(config_path)?;
            if observed.is_some() {
                return Ok(observed);
            }
            if attempt + 1 < VERSION_OBSERVATION_ATTEMPTS {
                thread::sleep(VERSION_OBSERVATION_RETRY_INTERVAL);
            }
        }
        if effect == KamalEffectKindV1::Bootstrap {
            Ok(None)
        } else {
            Err(KamalAdapterError::DeploymentObservationMismatch)
        }
    }

    fn mutate(
        &self,
        effect: KamalEffectKindV1,
        version: &str,
        config_path: &Path,
    ) -> Result<(), KamalAdapterError> {
        let config = path_text(config_path)?;
        let arguments = match effect {
            KamalEffectKindV1::Bootstrap => vec![
                "setup",
                "--skip-push",
                "--version",
                version,
                "--config-file",
                config,
                "--skip-hooks",
                "--quiet",
            ],
            KamalEffectKindV1::Deploy => vec![
                "deploy",
                "--skip-push",
                "--version",
                version,
                "--config-file",
                config,
                "--skip-hooks",
                "--quiet",
            ],
            KamalEffectKindV1::Rollback => vec![
                "rollback",
                version,
                "--config-file",
                config,
                "--skip-hooks",
                "--quiet",
            ],
        };
        run_status_command(&self.kamal_path, &arguments)
    }
}

impl KamalRuntimeV1 for InstalledKamalRuntimeV1 {
    fn apply_release(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        release_bundle_digest: &EvidenceDigest,
        effect: KamalEffectKindV1,
    ) -> Result<KamalDeploymentObservationV1, KamalAdapterError> {
        if effect == KamalEffectKindV1::Bootstrap
            && matches!(self.config.stable_health, InstalledStableHealthV1::Http(_))
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        let bundle = self.load_bundle(spec, release_bundle_digest)?;
        let plan = bundle.deployment_plan();
        let archive_source = self.import_candidate_image(&bundle)?;
        self.remove_ephemeral_registry_if_owned()?;
        let (config_path, generated_config_digest) = self.generated_config(spec, plan)?;
        let expected_version = plan.source_head().as_str();
        if effect == KamalEffectKindV1::Bootstrap {
            let already_deployed = self
                .observe_version_before_mutation(&config_path, effect)?
                .is_some_and(|version| version == expected_version);
            if !already_deployed {
                self.start_ephemeral_registry(&bundle, &archive_source)?;
                let mutation = self.mutate(effect, expected_version, &config_path);
                let cleanup = self.remove_ephemeral_registry_if_owned();
                match (mutation, cleanup) {
                    (Ok(()), Ok(())) => {}
                    (Err(error), Ok(())) => return Err(error),
                    (_, Err(_)) => return Err(KamalAdapterError::RegistryCleanupFailed),
                }
            }
            let deployed_version = self
                .observe_version(&config_path)?
                .ok_or(KamalAdapterError::DeploymentObservationMismatch)?;
            if deployed_version != expected_version {
                return Err(KamalAdapterError::DeploymentObservationMismatch);
            }
        } else {
            self.apply_stable_release(spec, &bundle, effect)?;
        }
        Ok(KamalDeploymentObservationV1 {
            schema_version: 1,
            effect,
            release_bundle_digest: bundle.digest().clone(),
            deployment_plan_digest: plan.digest().clone(),
            runtime_policy_digest: plan.runtime_policy_digest().clone(),
            generated_config_digest,
            image_registry_digest: plan.image_registry_digest().as_str().to_owned(),
            deployed_version: expected_version.to_owned(),
        })
    }
}

#[derive(Deserialize)]
struct StableRouterStateServiceV1 {
    name: String,
    active_targets: Vec<String>,
}

fn decode_stable_router_target(
    bytes: &[u8],
    expected_service: &str,
) -> Result<Option<String>, KamalAdapterError> {
    let Ok(services) = serde_json::from_slice::<Vec<StableRouterStateServiceV1>>(bytes) else {
        return Ok(None);
    };
    if services.is_empty() {
        return Ok(None);
    }
    if services.len() != 1 || services[0].name != expected_service {
        return Err(KamalAdapterError::StableRouterOwnershipMismatch);
    }
    match services[0].active_targets.as_slice() {
        [target] => Ok(Some(target.clone())),
        _ => Err(KamalAdapterError::StableRouterStateMismatch),
    }
}

fn stable_router_has_network_alias(
    bytes: &[u8],
    network: &str,
    alias: &str,
) -> Result<bool, KamalAdapterError> {
    container_has_network_alias(bytes, network, alias)
}

fn container_has_network_alias(
    bytes: &[u8],
    network: &str,
    alias: &str,
) -> Result<bool, KamalAdapterError> {
    let networks: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| KamalAdapterError::StableRouterOwnershipMismatch)?;
    let aliases = networks
        .get(network)
        .and_then(|settings| settings.get("Aliases"))
        .ok_or(KamalAdapterError::StableRouterOwnershipMismatch)?;
    let Some(aliases) = aliases.as_array() else {
        return if aliases.is_null() {
            Ok(false)
        } else {
            Err(KamalAdapterError::StableRouterOwnershipMismatch)
        };
    };
    Ok(aliases.iter().any(|value| value.as_str() == Some(alias)))
}

fn valid_docker_container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn probe_http_health(
    address: SocketAddr,
    probe: &InstalledHttpHealthProbeV1,
    timeout: Duration,
) -> Result<bool, KamalAdapterError> {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else {
        return Ok(false);
    };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| KamalAdapterError::StableBackendUnhealthy)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| KamalAdapterError::StableBackendUnhealthy)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: health\r\nConnection: close\r\n\r\n",
        probe.path
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(false);
    }
    let mut response = Vec::new();
    if stream
        .take((MAX_HEALTH_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .is_err()
    {
        return Ok(false);
    }
    if response.len() > MAX_HEALTH_RESPONSE_BYTES {
        return Err(KamalAdapterError::StableBackendUnhealthy);
    }
    Ok(http_health_status_matches(&response, probe.expected_status))
}

fn http_health_status_matches(response: &[u8], expected_status: u16) -> bool {
    let Some(status_line) = response.split(|byte| *byte == b'\n').next() else {
        return false;
    };
    let Ok(status_line) = std::str::from_utf8(status_line) else {
        return false;
    };
    let mut fields = status_line.trim_end_matches('\r').split_ascii_whitespace();
    let Some(version) = fields.next() else {
        return false;
    };
    let Some(status) = fields.next() else {
        return false;
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return false;
    }
    let Ok(status) = status.parse::<u16>() else {
        return false;
    };
    status == expected_status
}

#[derive(Serialize)]
struct GeneratedKamalConfigV1<'a> {
    service: &'a str,
    image: &'a str,
    servers: GeneratedServersV1<'a>,
    registry: GeneratedRegistryV1,
    env: GeneratedEnvironmentV1,
    volumes: Vec<String>,
    ssh: GeneratedSshV1<'a>,
    logging: GeneratedLoggingV1,
    secrets_path: &'a str,
    retain_containers: u8,
    deploy_timeout: u64,
    drain_timeout: u16,
    readiness_delay: u8,
    minimum_version: &'static str,
}

#[derive(Serialize)]
struct GeneratedServersV1<'a> {
    web: GeneratedRoleV1<'a>,
}

#[derive(Serialize)]
struct GeneratedRoleV1<'a> {
    hosts: [&'a str; 1],
    proxy: bool,
    options: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct GeneratedRegistryV1 {
    server: &'static str,
}

#[derive(Serialize)]
struct GeneratedEnvironmentV1 {
    clear: BTreeMap<String, String>,
    secret: Vec<String>,
}

#[derive(Serialize)]
struct GeneratedSshV1<'a> {
    user: &'a str,
    port: u16,
    keys: [&'a str; 1],
    keys_only: bool,
    config: bool,
    forward_agent: bool,
}

#[derive(Serialize)]
struct GeneratedLoggingV1 {
    driver: &'static str,
    options: BTreeMap<&'static str, String>,
}

fn render_config<'a>(
    spec: &AuthorizedPhaseSpecV1,
    plan: &'a KamalDeploymentPlanV1,
    stable_health: &InstalledStableHealthV1,
    secrets_path: &'a str,
    ssh_key_path: &'a str,
) -> Result<GeneratedKamalConfigV1<'a>, KamalAdapterError> {
    let (clear, secret) = render_environment(plan);
    let logging = render_logging(plan);
    Ok(GeneratedKamalConfigV1 {
        service: plan.service().as_str(),
        image: plan.image().as_str(),
        servers: GeneratedServersV1 {
            web: GeneratedRoleV1 {
                hosts: [plan.target_host().as_str()],
                proxy: false,
                options: render_server_options(plan, stable_health),
            },
        },
        registry: GeneratedRegistryV1 {
            server: "localhost:5555",
        },
        env: GeneratedEnvironmentV1 { clear, secret },
        volumes: render_volumes(plan),
        ssh: GeneratedSshV1 {
            user: plan.ssh_user().as_str(),
            port: plan.ssh_port(),
            keys: [ssh_key_path],
            keys_only: true,
            config: false,
            forward_agent: false,
        },
        logging,
        secrets_path,
        retain_containers: 2,
        deploy_timeout: spec
            .timeouts
            .deploy_ms
            .checked_sub(KAMAL_COMPLETION_MARGIN_MS)
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?
            .div_ceil(1000),
        drain_timeout: 30,
        readiness_delay: 5,
        minimum_version: EXPECTED_KAMAL_VERSION,
    })
}

fn render_server_options(
    plan: &KamalDeploymentPlanV1,
    stable_health: &InstalledStableHealthV1,
) -> BTreeMap<String, serde_json::Value> {
    let mut options = BTreeMap::from([
        (
            "network-alias".to_owned(),
            serde_json::Value::String(plan.network_alias().as_str().to_owned()),
        ),
        (
            "user".to_owned(),
            serde_json::Value::String(format!("{}:{}", plan.run_as().uid, plan.run_as().gid)),
        ),
    ]);
    if matches!(stable_health, InstalledStableHealthV1::Docker) {
        options.extend([
            (
                "health-cmd".to_owned(),
                serde_json::Value::String("rimg --healthcheck".to_owned()),
            ),
            (
                "health-interval".to_owned(),
                serde_json::Value::String("10s".to_owned()),
            ),
            (
                "health-retries".to_owned(),
                serde_json::Value::Number(12.into()),
            ),
            (
                "health-timeout".to_owned(),
                serde_json::Value::String("5s".to_owned()),
            ),
        ]);
    }
    let publish = plan
        .ports()
        .iter()
        .map(|port| {
            let protocol = match port.protocol {
                KamalPortProtocolV1::Tcp => "tcp",
                KamalPortProtocolV1::Udp => "udp",
            };
            serde_json::Value::String(format!(
                "127.0.0.1:{}:{}/{}",
                port.host_port, port.container_port, protocol
            ))
        })
        .collect::<Vec<_>>();
    if !publish.is_empty() {
        options.insert("publish".to_owned(), serde_json::Value::Array(publish));
    }
    options
}

fn render_environment(plan: &KamalDeploymentPlanV1) -> (BTreeMap<String, String>, Vec<String>) {
    let clear = plan
        .clear_environment()
        .iter()
        .map(|entry| {
            (
                entry.key.as_str().to_owned(),
                entry.value.as_str().to_owned(),
            )
        })
        .collect();
    let secret = plan
        .secret_bindings()
        .iter()
        .map(|binding| {
            if binding.environment_key.as_str() == binding.secret_name.as_str() {
                binding.environment_key.as_str().to_owned()
            } else {
                format!(
                    "{}:{}",
                    binding.environment_key.as_str(),
                    binding.secret_name.as_str()
                )
            }
        })
        .collect();
    (clear, secret)
}

fn render_volumes(plan: &KamalDeploymentPlanV1) -> Vec<String> {
    plan.mounts()
        .iter()
        .map(|mount| {
            let suffix = match mount.access {
                KamalMountAccessV1::ReadOnly => ":ro",
                KamalMountAccessV1::ReadWrite => "",
            };
            format!(
                "{}:{}{}",
                mount.host_path.as_str(),
                mount.container_path.as_str(),
                suffix
            )
        })
        .collect()
}

fn render_logging(plan: &KamalDeploymentPlanV1) -> GeneratedLoggingV1 {
    let driver = match plan.logging().driver {
        KamalLoggingDriverV1::Local => "local",
    };
    let logging_options = BTreeMap::from([
        ("max-file", plan.logging().max_files.to_string()),
        ("max-size", plan.logging().max_size_bytes.to_string()),
    ]);
    GeneratedLoggingV1 {
        driver,
        options: logging_options,
    }
}

fn validate_secret_credential(
    plan: &KamalDeploymentPlanV1,
    bytes: &[u8],
) -> Result<(), KamalAdapterError> {
    let expected = plan
        .secret_bindings()
        .iter()
        .map(|binding| binding.secret_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    validate_secret_credential_names(&expected, bytes)
}

fn validate_secret_credential_names(
    expected: &std::collections::BTreeSet<&str>,
    bytes: &[u8],
) -> Result<(), KamalAdapterError> {
    parse_secret_credential_names(expected, bytes).map(|_| ())
}

fn parse_secret_credential_names(
    expected: &std::collections::BTreeSet<&str>,
    bytes: &[u8],
) -> Result<BTreeMap<String, String>, KamalAdapterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| KamalAdapterError::RuntimeConfigMismatch)?;
    let mut actual = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?;
        if name.is_empty()
            || value.is_empty()
            || value.len() > MAX_SECRET_VALUE_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-' | b':')
            })
            || actual.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
    }
    if actual
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != *expected
    {
        return Err(KamalAdapterError::RuntimeConfigMismatch);
    }
    Ok(actual)
}

fn materialize_or_verify(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
) -> Result<(), KamalAdapterError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    fs::File::open(
        path.parent()
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?,
    )?
    .sync_all()?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || fs::read(path)? != bytes
    {
        return Err(KamalAdapterError::RuntimeConfigMismatch);
    }
    Ok(())
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn run_bounded_command(
    executable: &Path,
    arguments: &[&str],
) -> Result<BoundedCommandOutput, KamalAdapterError> {
    let mut child = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or(KamalAdapterError::CommandOutputTooLarge)?;
    let reader = thread::spawn(move || read_bounded(stdout, MAX_COMMAND_STDOUT_BYTES));
    let status = child.wait()?;
    let stdout = reader
        .join()
        .map_err(|_| KamalAdapterError::CommandOutputTooLarge)??;
    Ok(BoundedCommandOutput { status, stdout })
}

fn read_bounded(
    mut reader: impl std::io::Read,
    maximum_bytes: usize,
) -> Result<Vec<u8>, KamalAdapterError> {
    let mut bytes = Vec::new();
    let mut limited = reader.by_ref().take(
        u64::try_from(maximum_bytes).map_err(|_| KamalAdapterError::CommandOutputTooLarge)? + 1,
    );
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(KamalAdapterError::CommandOutputTooLarge);
    }
    Ok(bytes)
}

fn run_status_command(executable: &Path, arguments: &[&str]) -> Result<(), KamalAdapterError> {
    let status = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(KamalAdapterError::CommandFailed(format!(
            "exit status {status}"
        )))
    }
}

fn run_status_command_owned(
    executable: &Path,
    arguments: &[String],
) -> Result<(), KamalAdapterError> {
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run_status_command(executable, &arguments)
}

fn path_text(path: &Path) -> Result<&str, KamalAdapterError> {
    path.to_str()
        .ok_or(KamalAdapterError::RuntimeConfigMismatch)
}

fn skopeo_inspect_arguments(reference: &str) -> Vec<&str> {
    let mut arguments = vec!["inspect"];
    if reference.starts_with("docker://localhost:5555/") {
        arguments.push("--tls-verify=false");
    }
    arguments.extend(["--format={{.Digest}}", reference]);
    arguments
}

fn skopeo_registry_copy_arguments<'a>(source: &'a str, target: &'a str) -> [&'a str; 5] {
    [
        "copy",
        "--preserve-digests",
        "--dest-tls-verify=false",
        source,
        target,
    ]
}

fn skopeo_docker_import_arguments<'a>(source: &'a str, target: &'a str) -> [&'a str; 3] {
    ["copy", source, target]
}

fn valid_registry_image(value: &str) -> bool {
    let Some((repository, digest)) = value.split_once('@') else {
        return false;
    };
    !repository.is_empty()
        && repository.len() <= 255
        && !repository.contains('@')
        && !repository.contains("//")
        && repository.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'/' | b'_' | b'-')
        })
        && repository.split('/').all(|component| {
            !component.is_empty()
                && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && component
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        && OciDigest::from_str(digest).is_ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn secret_credential_is_exact_and_cannot_trigger_dotenv_substitution() {
        let expected = BTreeSet::from(["DATABASE_KEY", "WEBHOOK_TOKEN"]);
        assert!(
            validate_secret_credential_names(
                &expected,
                b"DATABASE_KEY=abc+/=_-123\nWEBHOOK_TOKEN=token.example:1\n",
            )
            .is_ok()
        );
        for rejected in [
            b"DATABASE_KEY=$(cat /etc/shadow)\nWEBHOOK_TOKEN=value\n".as_slice(),
            b"DATABASE_KEY=value\nWEBHOOK_TOKEN=$OTHER\n".as_slice(),
            b"DATABASE_KEY=value\nUNAUTHORIZED=value\n".as_slice(),
            b"DATABASE_KEY=value\nDATABASE_KEY=other\nWEBHOOK_TOKEN=value\n".as_slice(),
        ] {
            assert!(validate_secret_credential_names(&expected, rejected).is_err());
        }
    }

    #[test]
    fn registry_runtime_accepts_only_digest_pinned_canonical_images() {
        assert!(valid_registry_image(&format!(
            "docker.io/library/registry@sha256:{}",
            "a".repeat(64)
        )));
        for rejected in [
            "registry:2",
            "registry@sha256:abc",
            "LOCAL/registry@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry//image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!valid_registry_image(rejected), "accepted {rejected}");
        }
    }

    #[test]
    fn skopeo_disables_tls_verification_only_for_the_fixed_loopback_registry() {
        assert_eq!(
            skopeo_inspect_arguments("docker://localhost:5555/rimg:abc"),
            [
                "inspect",
                "--tls-verify=false",
                "--format={{.Digest}}",
                "docker://localhost:5555/rimg:abc",
            ]
        );
        assert_eq!(
            skopeo_inspect_arguments("oci-archive:/private/candidate.oci.tar"),
            [
                "inspect",
                "--format={{.Digest}}",
                "oci-archive:/private/candidate.oci.tar",
            ]
        );
        assert_eq!(
            skopeo_registry_copy_arguments(
                "oci-archive:/private/candidate.oci.tar",
                "docker://localhost:5555/rimg:abc",
            ),
            [
                "copy",
                "--preserve-digests",
                "--dest-tls-verify=false",
                "oci-archive:/private/candidate.oci.tar",
                "docker://localhost:5555/rimg:abc",
            ]
        );
        assert_eq!(
            skopeo_docker_import_arguments(
                "oci-archive:/private/candidate.oci.tar",
                "docker-daemon:localhost:5555/rimg:abc",
            ),
            [
                "copy",
                "oci-archive:/private/candidate.oci.tar",
                "docker-daemon:localhost:5555/rimg:abc",
            ]
        );
    }

    #[test]
    fn stable_router_state_requires_the_single_owned_service_and_target() {
        assert_eq!(
            decode_stable_router_target(
                br#"[{"name":"rimg-internal","active_targets":["backend:3000"]}]"#,
                "rimg-internal",
            )
            .unwrap_or_else(|error| panic!("decode router state: {error}")),
            Some("backend:3000".to_owned())
        );
        assert_eq!(
            decode_stable_router_target(b"not-json", "rimg-internal")
                .unwrap_or_else(|error| panic!("malformed state: {error}")),
            None
        );
        assert!(matches!(
            decode_stable_router_target(
                br#"[{"name":"foreign","active_targets":["backend:3000"]}]"#,
                "rimg-internal",
            ),
            Err(KamalAdapterError::StableRouterOwnershipMismatch)
        ));
        assert!(matches!(
            decode_stable_router_target(
                br#"[{"name":"rimg-internal","active_targets":["one:3000","two:3000"]}]"#,
                "rimg-internal",
            ),
            Err(KamalAdapterError::StableRouterStateMismatch)
        ));
    }

    #[test]
    fn stable_router_network_requires_the_owned_project_alias() {
        assert!(
            stable_router_has_network_alias(
                br#"{"kamal":{"Aliases":["rdashboard-rimg-router","rimg"]}}"#,
                "kamal",
                "rimg",
            )
            .unwrap_or_else(|error| panic!("router aliases: {error}"))
        );
        assert!(
            !stable_router_has_network_alias(
                br#"{"kamal":{"Aliases":["rdashboard-rimg-router"]}}"#,
                "kamal",
                "rimg",
            )
            .unwrap_or_else(|error| panic!("router aliases: {error}"))
        );
        assert!(matches!(
            stable_router_has_network_alias(
                br#"{"other":{"Aliases":["telegram-gateway"]}}"#,
                "kamal",
                "telegram-gateway",
            ),
            Err(KamalAdapterError::StableRouterOwnershipMismatch)
        ));
        assert!(
            !container_has_network_alias(br#"{"kamal":{"Aliases":null}}"#, "kamal", "rimg")
                .unwrap_or_else(|error| panic!("null aliases: {error}"))
        );
        assert!(valid_docker_container_id(&"a".repeat(64)));
        assert!(!valid_docker_container_id(&"A".repeat(64)));
        assert!(!valid_docker_container_id(&"a".repeat(63)));
    }

    #[test]
    fn stable_route_identity_is_project_scoped_and_keeps_the_application_port() {
        let project = ProjectId::from_str("telegram-gateway")
            .unwrap_or_else(|error| panic!("project id: {error}"));
        let route = StableRouteIdentityV1::from_parts(&project, "telegram-gateway", 8081)
            .unwrap_or_else(|error| panic!("stable route: {error}"));
        assert_eq!(route.router_container, "rdashboard-telegram-gateway-router");
        assert_eq!(
            route.router_volume,
            "rdashboard-telegram-gateway-router-state"
        );
        assert_eq!(route.proxy_service, "telegram-gateway-internal");
        assert_eq!(route.network_alias, "telegram-gateway");
        assert_eq!(route.app_port, 8081);
    }

    #[test]
    fn runtime_config_path_preserves_rimg_and_scopes_other_projects() {
        let rimg = ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("rimg: {error}"));
        let gateway = ProjectId::from_str("telegram-gateway")
            .unwrap_or_else(|error| panic!("gateway: {error}"));
        assert_eq!(
            installed_runtime_config_path(&rimg),
            PathBuf::from(KAMAL_ADAPTER_CONFIG_PATH)
        );
        assert_eq!(
            installed_runtime_config_path(&gateway),
            PathBuf::from("/etc/rdashboard/projects/telegram-gateway/kamal-adapter-runtime.jcs")
        );
    }

    #[test]
    fn installed_http_health_probe_rejects_ambiguous_or_unbounded_inputs() {
        let valid = InstalledHttpHealthProbeV1 {
            path: "/health".to_owned(),
            expected_status: 200,
            timeout_ms: 1_000,
            interval_ms: 500,
            attempts: 20,
        };
        assert!(valid.is_valid());
        for invalid in [
            InstalledHttpHealthProbeV1 {
                path: "health".to_owned(),
                ..valid.clone()
            },
            InstalledHttpHealthProbeV1 {
                path: "/health?deep=true".to_owned(),
                ..valid.clone()
            },
            InstalledHttpHealthProbeV1 {
                expected_status: 500,
                ..valid.clone()
            },
            InstalledHttpHealthProbeV1 {
                attempts: 0,
                ..valid.clone()
            },
        ] {
            assert!(!invalid.is_valid());
        }
    }

    #[test]
    fn installed_http_health_requires_the_exact_response_status() {
        assert!(http_health_status_matches(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            200
        ));
        assert!(!http_health_status_matches(
            b"HTTP/1.1 204 No Content\r\n\r\n",
            200
        ));
        assert!(!http_health_status_matches(b"ICY 200 OK\r\n\r\n", 200));
        assert!(!http_health_status_matches(b"HTTP/1.1 nope\r\n\r\n", 200));
    }
}
