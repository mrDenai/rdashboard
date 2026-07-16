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
const EXPECTED_KAMAL_VERSION: &str = "2.12.0";
const EPHEMERAL_REGISTRY_CONTAINER: &str = "rdashboard-registry";
const EPHEMERAL_REGISTRY_LABEL: &str = "io.rdashboard.role=ephemeral-registry-v1";
const MIN_REGISTRY_STORAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REGISTRY_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const REGISTRY_START_ATTEMPTS: u8 = 10;
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
pub struct InstalledKamalAdapterRuntimeV2 {
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
    pub secrets_sha256: EvidenceDigest,
    pub ssh_private_key_sha256: EvidenceDigest,
    pub kamal_version: String,
}

impl InstalledKamalAdapterRuntimeV2 {
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
            || config.purpose != "rdashboard.installed-kamal-adapter-runtime.v2"
            || config.schema_version != 2
            || config.project_id != spec.project_id
            || config.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
            || config.kamal_version != EXPECTED_KAMAL_VERSION
            || !valid_registry_image(&config.registry_image)
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
    config: InstalledKamalAdapterRuntimeV2,
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
        let config = InstalledKamalAdapterRuntimeV2::load(
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
        Ok(KamalDeploymentObservationV1 {
            schema_version: 1,
            effect,
            release_bundle_digest: bundle.digest().clone(),
            deployment_plan_digest: plan.digest().clone(),
            runtime_policy_digest: plan.runtime_policy_digest().clone(),
            generated_config_digest,
            image_registry_digest: plan.image_registry_digest().as_str().to_owned(),
            deployed_version,
        })
    }
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
            || actual.insert(name, value).is_some()
        {
            return Err(KamalAdapterError::RuntimeConfigMismatch);
        }
    }
    if actual
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != *expected
    {
        return Err(KamalAdapterError::RuntimeConfigMismatch);
    }
    Ok(())
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
}
