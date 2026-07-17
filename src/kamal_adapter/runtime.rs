use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
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
const STABLE_ROUTER_CONTAINER: &str = "rdashboard-rimg-router";
const STABLE_ROUTER_VOLUME: &str = "rdashboard-rimg-router-state";
const STABLE_ROUTER_SERVICE: &str = "rimg-internal";
const STABLE_ROUTER_ROLE: &str = "stable-router-v1";
const STABLE_ROUTER_VOLUME_ROLE: &str = "stable-router-state-v1";
const STABLE_BACKEND_ROLE: &str = "stable-backend-v1";
const STABLE_ROUTER_STATE_PATH: &str = "/home/kamal-proxy/.config/kamal-proxy/kamal-proxy.state";
const STABLE_ROUTER_HTTP_PORT: u16 = 8080;
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

impl InstalledKamalAdapterRuntimeV3 {
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
        let config: Self = serde_json::from_slice(&bytes)?;
        if serde_jcs::to_vec(&config)? != bytes
            || config.purpose != "rdashboard.installed-kamal-adapter-runtime.v3"
            || config.schema_version != 3
            || config.project_id != spec.project_id
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
}

#[derive(Debug)]
pub struct InstalledKamalRuntimeV1 {
    config: InstalledKamalAdapterRuntimeV3,
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
        Self::new_bound(
            Path::new(KAMAL_ADAPTER_CONFIG_PATH),
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
        let config = InstalledKamalAdapterRuntimeV3::load(
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

    fn stable_backend_port(plan: &KamalDeploymentPlanV1) -> Result<u16, KamalAdapterError> {
        let mut ports = plan
            .ports()
            .iter()
            .filter(|port| port.protocol == KamalPortProtocolV1::Tcp);
        let port = ports
            .next()
            .ok_or(KamalAdapterError::RuntimeConfigMismatch)?;
        if ports.next().is_some() {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        if port.container_port != STABLE_ROUTER_HTTP_PORT {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        Ok(port.container_port)
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
            self.wait_for_stable_backend_health(&name)?;
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
        self.wait_for_stable_backend_health(&name)?;
        Ok(name)
    }

    fn wait_for_stable_backend_health(&self, name: &str) -> Result<(), KamalAdapterError> {
        for _ in 0..120 {
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
            thread::sleep(Duration::from_secs(1));
        }
        Err(KamalAdapterError::StableBackendUnhealthy)
    }

    fn ensure_stable_router(&self, network: &str) -> Result<(), KamalAdapterError> {
        if self
            .inspect_local_image_id(&self.config.stable_router_image)?
            .as_ref()
            != Some(&self.config.stable_router_local_image_id)
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
        self.ensure_stable_router_volume()?;
        let inspected = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Image}}|{{index .Config.Labels \"io.rdashboard.role\"}}|{{.HostConfig.NetworkMode}}",
                STABLE_ROUTER_CONTAINER,
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
                &["container", "start", STABLE_ROUTER_CONTAINER],
            )?;
            if self.stable_router_has_network_alias(network)? {
                return self.wait_for_stable_router();
            }
            run_status_command(
                &self.docker_path,
                &["container", "rm", "--force", STABLE_ROUTER_CONTAINER],
            )?;
        }
        let state_mount = format!(
            "type=volume,source={STABLE_ROUTER_VOLUME},target=/home/kamal-proxy/.config/kamal-proxy"
        );
        let http_port = format!("--http-port={STABLE_ROUTER_HTTP_PORT}");
        run_status_command(
            &self.docker_path,
            &[
                "run",
                "--detach",
                "--name",
                STABLE_ROUTER_CONTAINER,
                "--label",
                &format!("io.rdashboard.role={STABLE_ROUTER_ROLE}"),
                "--network",
                network,
                "--network-alias",
                "rimg",
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
        if !self.stable_router_has_network_alias(network)? {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        self.wait_for_stable_router()
    }

    fn stable_router_has_network_alias(&self, network: &str) -> Result<bool, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{json .NetworkSettings.Networks}}",
                STABLE_ROUTER_CONTAINER,
            ],
        )?;
        if !output.status.success() {
            return Err(KamalAdapterError::StableRouterOwnershipMismatch);
        }
        stable_router_has_network_alias(&output.stdout, network)
    }

    fn wait_for_stable_router(&self) -> Result<(), KamalAdapterError> {
        for attempt in 0..STABLE_ROUTER_START_ATTEMPTS {
            let output = run_bounded_command(
                &self.docker_path,
                &[
                    "container",
                    "exec",
                    STABLE_ROUTER_CONTAINER,
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
    ) -> Result<(), KamalAdapterError> {
        let router = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "inspect",
                "--format={{.Id}}",
                STABLE_ROUTER_CONTAINER,
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
            let has_alias = container_has_network_alias(&inspected.stdout, network, "rimg")?;
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

    fn ensure_stable_router_volume(&self) -> Result<(), KamalAdapterError> {
        let inspected = run_bounded_command(
            &self.docker_path,
            &[
                "volume",
                "inspect",
                "--format={{index .Labels \"io.rdashboard.role\"}}",
                STABLE_ROUTER_VOLUME,
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
                STABLE_ROUTER_VOLUME,
            ],
        )
    }

    fn stable_router_target(&self) -> Result<Option<String>, KamalAdapterError> {
        let output = run_bounded_command(
            &self.docker_path,
            &[
                "container",
                "exec",
                STABLE_ROUTER_CONTAINER,
                "cat",
                STABLE_ROUTER_STATE_PATH,
            ],
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        decode_stable_router_target(&output.stdout)
    }

    fn switch_stable_router(
        &self,
        target: &str,
        port: u16,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<(), KamalAdapterError> {
        let target = format!("{target}:{port}");
        if self.stable_router_target()?.as_deref() == Some(target.as_str()) {
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
        run_status_command(
            &self.docker_path,
            &[
                "container",
                "exec",
                STABLE_ROUTER_CONTAINER,
                "kamal-proxy",
                "deploy",
                STABLE_ROUTER_SERVICE,
                &target_argument,
                "--health-check-path=/health/ready",
                "--health-check-interval=1s",
                "--health-check-timeout=5s",
                &deploy_timeout,
                "--drain-timeout=30s",
                "--target-timeout=30s",
            ],
        )?;
        if self.stable_router_target()?.as_deref() == Some(target.as_str()) {
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
                self.ensure_stable_router(current.deployment_plan().network().as_str())?;
                let target_endpoint = format!(
                    "{}:{}",
                    Self::stable_backend_name(bundle.deployment_plan()),
                    Self::stable_backend_port(bundle.deployment_plan())?
                );
                if self.stable_router_target()?.as_deref() == Some(target_endpoint.as_str()) {
                    let _ = self.ensure_stable_backend(bundle)?;
                    self.remove_adopted_bootstrap_container(&current)?;
                    self.require_exclusive_stable_router_alias(
                        current.deployment_plan().network().as_str(),
                    )?;
                    if current.digest() != bundle.digest() {
                        self.stop_owned_stable_backend(&current)?;
                    }
                    return Ok(());
                }
                let current_name = self.ensure_stable_backend(&current)?;
                self.switch_stable_router(
                    &current_name,
                    Self::stable_backend_port(current.deployment_plan())?,
                    spec,
                )?;
                self.remove_adopted_bootstrap_container(&current)?;
                self.require_exclusive_stable_router_alias(
                    current.deployment_plan().network().as_str(),
                )?;

                let target_name = self.ensure_stable_backend(bundle)?;
                self.switch_stable_router(
                    &target_name,
                    Self::stable_backend_port(bundle.deployment_plan())?,
                    spec,
                )?;
                if current.digest() != bundle.digest() {
                    self.stop_owned_stable_backend(&current)?;
                }
            }
            KamalEffectKindV1::Rollback => {
                self.ensure_stable_router(bundle.deployment_plan().network().as_str())?;
                self.require_exclusive_stable_router_alias(
                    bundle.deployment_plan().network().as_str(),
                )?;
                let target_name = self.ensure_stable_backend(bundle)?;
                self.switch_stable_router(
                    &target_name,
                    Self::stable_backend_port(bundle.deployment_plan())?,
                    spec,
                )?;
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

fn decode_stable_router_target(bytes: &[u8]) -> Result<Option<String>, KamalAdapterError> {
    let Ok(services) = serde_json::from_slice::<Vec<StableRouterStateServiceV1>>(bytes) else {
        return Ok(None);
    };
    if services.is_empty() {
        return Ok(None);
    }
    if services.len() != 1 || services[0].name != STABLE_ROUTER_SERVICE {
        return Err(KamalAdapterError::StableRouterOwnershipMismatch);
    }
    match services[0].active_targets.as_slice() {
        [target] => Ok(Some(target.clone())),
        _ => Err(KamalAdapterError::StableRouterStateMismatch),
    }
}

fn stable_router_has_network_alias(bytes: &[u8], network: &str) -> Result<bool, KamalAdapterError> {
    container_has_network_alias(bytes, network, "rimg")
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
                options: render_server_options(plan),
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

fn render_server_options(plan: &KamalDeploymentPlanV1) -> BTreeMap<String, serde_json::Value> {
    let mut options = BTreeMap::from([
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
        (
            "network-alias".to_owned(),
            serde_json::Value::String(plan.network_alias().as_str().to_owned()),
        ),
        (
            "user".to_owned(),
            serde_json::Value::String(format!("{}:{}", plan.run_as().uid, plan.run_as().gid)),
        ),
    ]);
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
            )
            .unwrap_or_else(|error| panic!("decode router state: {error}")),
            Some("backend:3000".to_owned())
        );
        assert_eq!(
            decode_stable_router_target(b"not-json")
                .unwrap_or_else(|error| panic!("malformed state: {error}")),
            None
        );
        assert!(matches!(
            decode_stable_router_target(
                br#"[{"name":"foreign","active_targets":["backend:3000"]}]"#,
            ),
            Err(KamalAdapterError::StableRouterOwnershipMismatch)
        ));
        assert!(matches!(
            decode_stable_router_target(
                br#"[{"name":"rimg-internal","active_targets":["one:3000","two:3000"]}]"#,
            ),
            Err(KamalAdapterError::StableRouterStateMismatch)
        ));
    }

    #[test]
    fn stable_router_network_requires_the_owned_rimg_alias() {
        assert!(
            stable_router_has_network_alias(
                br#"{"kamal":{"Aliases":["rdashboard-rimg-router","rimg"]}}"#,
                "kamal",
            )
            .unwrap_or_else(|error| panic!("router aliases: {error}"))
        );
        assert!(
            !stable_router_has_network_alias(
                br#"{"kamal":{"Aliases":["rdashboard-rimg-router"]}}"#,
                "kamal",
            )
            .unwrap_or_else(|error| panic!("router aliases: {error}"))
        );
        assert!(matches!(
            stable_router_has_network_alias(br#"{"other":{"Aliases":["rimg"]}}"#, "kamal"),
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
}
