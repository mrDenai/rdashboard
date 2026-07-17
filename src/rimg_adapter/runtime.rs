use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr as _,
    thread,
    time::{Duration, Instant},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use super::{
    RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION, RimgAdapterError, RimgAdminRuntimeV1,
    RimgHealthCheckKindV1, RimgHealthObservationV1, RimgObservedDocumentV1,
    RimgOperationalStatusV1, RimgRuntimeMigrationReportV1, RimgRuntimeSchemaInspectionV1,
};
use crate::{
    adapter_identity::AdapterOperationIdentityV1,
    build::{FIXED_KAMAL_NETWORK_NAME, KamalPortProtocolV1, ReleaseBundleReader, ReleaseBundleV1},
    domain::{EvidenceDigest, ProjectId},
    phase6::AuthorizedPhaseSpecV1,
};

pub const RIMG_ADAPTER_CONFIG_PATH: &str = "/etc/rdashboard/projects/rimg/adapter-runtime.jcs";
pub const RIMG_CLI_PATH: &str = "/usr/libexec/rdashboard/rimg-cli";
pub const DOCKER_CLI_PATH: &str = "/usr/bin/docker";
pub const RIMG_DATABASE_PATH: &str = "/var/lib/rimg/data/rimg.db";
pub const RIMG_OPERATION_LOCK_PATH: &str = "/var/lib/rdashboard-executor/locks/rimg-operation.lock";
pub const RELEASE_BUNDLE_ROOT: &str = "/var/lib/rdashboard-executor/release-bundles";

const MAX_RUNTIME_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_RIMG_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_COMMAND_STDOUT_BYTES: usize = 256 * 1024;
const MAX_COMMAND_STDERR_BYTES: usize = 8 * 1024;
const COMMAND_DEADLINE: Duration = Duration::from_secs(30);
const ADMIN_REQUEST_FILE_NAME: &str = "rimg-admin-request.jcs";
const RESUME_REQUEST_FILE_NAME: &str = "rimg-resume-request.jcs";
const ACQUIRE_FENCE_REQUEST_FILE_NAME: &str = "rimg-acquire-fence-request.jcs";
const RELEASE_FENCE_REQUEST_FILE_NAME: &str = "rimg-release-fence-request.jcs";
const MIGRATION_REQUEST_FILE_NAME: &str = "rimg-migration-request.jcs";
const CONSUMER_SMOKE_INTERVAL: Duration = Duration::from_mins(2);
const CONSUMER_SMOKE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRimgAdapterRuntimeV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub rimg_cli_sha256: EvidenceDigest,
    pub docker_cli_sha256: EvidenceDigest,
}

impl InstalledRimgAdapterRuntimeV1 {
    pub fn load_installed(spec: &AuthorizedPhaseSpecV1) -> Result<Self, RimgAdapterError> {
        Self::load(
            Path::new(RIMG_ADAPTER_CONFIG_PATH),
            Path::new(RIMG_CLI_PATH),
            Path::new(DOCKER_CLI_PATH),
            0,
            spec,
        )
    }

    fn load(
        config_path: &Path,
        executable_path: &Path,
        docker_path: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Self, RimgAdapterError> {
        Self::load_for_policy(
            config_path,
            executable_path,
            docker_path,
            required_uid,
            &spec.project_id,
            &spec.installed_rimg_policy_digest,
        )
    }

    pub(crate) fn load_for_policy(
        config_path: &Path,
        executable_path: &Path,
        docker_path: &Path,
        required_uid: u32,
        project_id: &ProjectId,
        installed_rimg_policy_digest: &EvidenceDigest,
    ) -> Result<Self, RimgAdapterError> {
        let bytes = read_stable_private_file(config_path, required_uid, MAX_RUNTIME_CONFIG_BYTES)?;
        let config: Self = serde_json::from_slice(&bytes)?;
        if serde_jcs::to_vec(&config)? != bytes
            || config.purpose != "rdashboard.installed-rimg-adapter-runtime.v1"
            || config.schema_version != 2
            || config.project_id != *project_id
            || config.installed_rimg_policy_digest != *installed_rimg_policy_digest
        {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        validate_executable(executable_path, required_uid, &config.rimg_cli_sha256)?;
        validate_executable(docker_path, required_uid, &config.docker_cli_sha256)?;
        Ok(config)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RimgAdminActionV1 {
    BeginDrain,
    AcquireFence,
    ReleaseFence,
    Resume,
}

#[derive(Serialize)]
struct RimgAdminRequestV1 {
    schema_version: u16,
    action: RimgAdminActionV1,
    epoch: u64,
    token: uuid::Uuid,
}

#[derive(Clone, Serialize)]
struct RimgMigrationRequestV1 {
    schema_version: u16,
    epoch: u64,
    token: uuid::Uuid,
    operation_lock_path: &'static str,
    operation_id: uuid::Uuid,
    from_application_schema: u32,
    to_application_schema: u32,
}

#[derive(Debug)]
pub struct InstalledRimgAdminRuntimeV1 {
    config: Option<InstalledRimgAdapterRuntimeV1>,
    executable_path: PathBuf,
    docker_path: PathBuf,
    release_bundle_root: PathBuf,
    database_path: PathBuf,
    job_directory: PathBuf,
    required_uid: u32,
}

#[derive(Clone, Debug)]
pub struct InstalledRimgFenceObserverV1 {
    executable_path: PathBuf,
    database_path: PathBuf,
}

impl InstalledRimgFenceObserverV1 {
    pub fn new(
        project_id: &ProjectId,
        installed_rimg_policy_digest: &EvidenceDigest,
    ) -> Result<Self, RimgAdapterError> {
        InstalledRimgAdapterRuntimeV1::load_for_policy(
            Path::new(RIMG_ADAPTER_CONFIG_PATH),
            Path::new(RIMG_CLI_PATH),
            Path::new(DOCKER_CLI_PATH),
            0,
            project_id,
            installed_rimg_policy_digest,
        )?;
        Ok(Self {
            executable_path: PathBuf::from(RIMG_CLI_PATH),
            database_path: PathBuf::from(RIMG_DATABASE_PATH),
        })
    }

    pub fn observe(
        &self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        let database = self
            .database_path
            .to_str()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?;
        invoke_observed_json(
            &self.executable_path,
            &["admin", "status", "--database", database],
        )
    }
}

impl InstalledRimgAdminRuntimeV1 {
    pub fn new(
        job_directory: &Path,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Self, RimgAdapterError> {
        let config = InstalledRimgAdapterRuntimeV1::load_installed(spec)?;
        validate_private_directory(job_directory, 0)?;
        Ok(Self {
            config: Some(config),
            executable_path: PathBuf::from(RIMG_CLI_PATH),
            docker_path: PathBuf::from(DOCKER_CLI_PATH),
            release_bundle_root: PathBuf::from(RELEASE_BUNDLE_ROOT),
            database_path: PathBuf::from(RIMG_DATABASE_PATH),
            job_directory: job_directory.to_path_buf(),
            required_uid: 0,
        })
    }

    pub(crate) fn new_fence(
        job_directory: &Path,
        project_id: &ProjectId,
        installed_rimg_policy_digest: &EvidenceDigest,
    ) -> Result<Self, RimgAdapterError> {
        let config = InstalledRimgAdapterRuntimeV1::load_for_policy(
            Path::new(RIMG_ADAPTER_CONFIG_PATH),
            Path::new(RIMG_CLI_PATH),
            Path::new(DOCKER_CLI_PATH),
            0,
            project_id,
            installed_rimg_policy_digest,
        )?;
        validate_private_directory(job_directory, 0)?;
        Ok(Self {
            config: Some(config),
            executable_path: PathBuf::from(RIMG_CLI_PATH),
            docker_path: PathBuf::from(DOCKER_CLI_PATH),
            release_bundle_root: PathBuf::from(RELEASE_BUNDLE_ROOT),
            database_path: PathBuf::from(RIMG_DATABASE_PATH),
            job_directory: job_directory.to_path_buf(),
            required_uid: 0,
        })
    }

    #[cfg(test)]
    fn new_bound(
        executable_path: &Path,
        database_path: &Path,
        job_directory: &Path,
        required_uid: u32,
    ) -> Result<Self, RimgAdapterError> {
        validate_private_directory(job_directory, required_uid)?;
        Ok(Self {
            config: None,
            executable_path: executable_path.to_path_buf(),
            docker_path: PathBuf::from(DOCKER_CLI_PATH),
            release_bundle_root: PathBuf::from(RELEASE_BUNDLE_ROOT),
            database_path: database_path.to_path_buf(),
            job_directory: job_directory.to_path_buf(),
            required_uid,
        })
    }

    pub(crate) fn invoke_json<T: DeserializeOwned + Serialize>(
        &self,
        arguments: &[&str],
    ) -> Result<RimgObservedDocumentV1<T>, RimgAdapterError> {
        invoke_observed_json(&self.executable_path, arguments)
    }

    pub(crate) fn database_argument(&self) -> Result<&str, RimgAdapterError> {
        self.database_path
            .to_str()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)
    }

    pub(crate) fn materialize_request<T: Serialize>(
        &self,
        file_name: &str,
        document: &T,
    ) -> Result<PathBuf, RimgAdapterError> {
        let path = self.job_directory.join(file_name);
        let bytes = serde_jcs::to_vec(document)?;
        materialize_or_verify_private_file(&path, self.required_uid, &bytes)?;
        Ok(path)
    }

    pub(crate) fn apply_admin_action(
        &mut self,
        action: RimgAdminActionV1,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        self.apply_admin_action_values(action, identity.epoch, identity.token)
    }

    pub(crate) fn apply_admin_action_values(
        &mut self,
        action: RimgAdminActionV1,
        epoch: u64,
        token: uuid::Uuid,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        let request_file_name = match action {
            RimgAdminActionV1::BeginDrain => ADMIN_REQUEST_FILE_NAME,
            RimgAdminActionV1::AcquireFence => ACQUIRE_FENCE_REQUEST_FILE_NAME,
            RimgAdminActionV1::ReleaseFence => RELEASE_FENCE_REQUEST_FILE_NAME,
            RimgAdminActionV1::Resume => RESUME_REQUEST_FILE_NAME,
        };
        let request = self.materialize_request(
            request_file_name,
            &RimgAdminRequestV1 {
                schema_version: RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION,
                action,
                epoch,
                token,
            },
        )?;
        let request = request
            .to_str()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?;
        let database = self.database_argument()?;
        self.invoke_json(&[
            "admin",
            "apply",
            "--database",
            database,
            "--request",
            request,
        ])
    }

    pub(crate) fn fence_status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        let database = self.database_argument()?;
        self.invoke_json(&["admin", "status", "--database", database])
    }

    fn authorized_release_bundle(
        &self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<ReleaseBundleV1, RimgAdapterError> {
        let bundle_digest = spec
            .release_bundle_digest
            .as_ref()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?;
        let plan_digest = spec
            .deployment_plan_digest
            .as_ref()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?;
        let reader =
            ReleaseBundleReader::open_for_owner(&self.release_bundle_root, self.required_uid)?;
        let bundle = reader.load(&spec.project_id, bundle_digest)?;
        if bundle.deployment_plan_digest() != plan_digest {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        Ok(bundle)
    }

    fn health_port(bundle: &ReleaseBundleV1) -> Result<(u16, u16), RimgAdapterError> {
        let ports = bundle.deployment_plan().ports();
        let [port] = ports else {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        };
        if port.protocol != KamalPortProtocolV1::Tcp {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        Ok((port.host_port, port.container_port))
    }

    fn run_health_command(executable: &Path, arguments: &[&str]) -> Result<(), RimgAdapterError> {
        let output = run_bounded_command(executable, arguments)?;
        if !output.status.success() {
            return Err(RimgAdapterError::CommandFailed(format!(
                "exit status {}",
                output.status
            )));
        }
        Ok(())
    }

    fn run_health_command_with_retry(
        executable: &Path,
        arguments: &[&str],
    ) -> Result<(), RimgAdapterError> {
        let mut last_error = None;
        for attempt in 0..3 {
            match Self::run_health_command(executable, arguments) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
            if attempt < 2 {
                thread::sleep(CONSUMER_SMOKE_RETRY_INTERVAL);
            }
        }
        Err(last_error.unwrap_or(RimgAdapterError::HealthObservationMismatch))
    }

    fn run_health_command_owned_with_retry(
        executable: &Path,
        arguments: &[String],
    ) -> Result<(), RimgAdapterError> {
        let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        Self::run_health_command_with_retry(executable, &arguments)
    }

    fn consumer_health_arguments(
        &self,
        bundle: &ReleaseBundleV1,
    ) -> Result<Vec<String>, RimgAdapterError> {
        let plan = bundle.deployment_plan();
        if plan.network().as_str() != FIXED_KAMAL_NETWORK_NAME {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        let (_host_port, container_port) = Self::health_port(bundle)?;
        let image = format!(
            "localhost:5555/{}:{}",
            plan.image().as_str(),
            plan.source_head().as_str()
        );
        let inspected = run_bounded_command(
            &self.docker_path,
            &["image", "inspect", "--format={{.Id}}", &image],
        )?;
        if !inspected.status.success()
            || String::from_utf8(inspected.stdout)
                .ok()
                .is_none_or(|value| value.trim() != bundle.local_image_id().as_str())
        {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        Ok(vec![
            "run".to_owned(),
            "--rm".to_owned(),
            "--pull=never".to_owned(),
            "--read-only".to_owned(),
            "--cap-drop=ALL".to_owned(),
            "--security-opt=no-new-privileges".to_owned(),
            "--pids-limit=64".to_owned(),
            "--memory=128m".to_owned(),
            "--cpus=1.0".to_owned(),
            "--log-driver=none".to_owned(),
            "--user".to_owned(),
            format!("{}:{}", plan.run_as().uid, plan.run_as().gid),
            "--network".to_owned(),
            FIXED_KAMAL_NETWORK_NAME.to_owned(),
            "--entrypoint".to_owned(),
            "rimg".to_owned(),
            image,
            "healthcheck".to_owned(),
            "--host".to_owned(),
            plan.network_alias().as_str().to_owned(),
            "--port".to_owned(),
            container_port.to_string(),
        ])
    }
}

impl RimgAdminRuntimeV1 for InstalledRimgAdminRuntimeV1 {
    fn begin_drain(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        self.apply_admin_action(RimgAdminActionV1::BeginDrain, identity)
    }

    fn operational_status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
        let database = self.database_argument()?;
        self.invoke_json(&["admin", "status", "--database", database])
    }

    fn schema_inspection(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgRuntimeSchemaInspectionV1>, RimgAdapterError> {
        let database = self.database_argument()?;
        self.invoke_json(&["schema", "inspect", "--database", database])
    }

    fn migrate(
        &mut self,
        identity: &AdapterOperationIdentityV1,
        from_application_schema: u32,
        to_application_schema: u32,
    ) -> Result<RimgObservedDocumentV1<RimgRuntimeMigrationReportV1>, RimgAdapterError> {
        let request = self.materialize_request(
            MIGRATION_REQUEST_FILE_NAME,
            &RimgMigrationRequestV1 {
                schema_version: RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION,
                epoch: identity.epoch,
                token: identity.token,
                operation_lock_path: RIMG_OPERATION_LOCK_PATH,
                operation_id: identity.attempt_id,
                from_application_schema,
                to_application_schema,
            },
        )?;
        let request = request
            .to_str()
            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?;
        let database = self.database_argument()?;
        self.invoke_json(&["migrate", "--database", database, "--request", request])
    }

    fn wait_before_drain_poll(&mut self) -> Result<(), RimgAdapterError> {
        thread::sleep(Duration::from_millis(250));
        Ok(())
    }

    fn readiness(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
        let bundle = self.authorized_release_bundle(spec)?;
        let plan = bundle.deployment_plan();
        let (_host_port, container_port) = Self::health_port(&bundle)?;
        let arguments = self.consumer_health_arguments(&bundle)?;
        Self::run_health_command_owned_with_retry(&self.docker_path, &arguments)?;
        RimgObservedDocumentV1::from_document(RimgHealthObservationV1 {
            schema_version: 1,
            check: RimgHealthCheckKindV1::DirectReadiness,
            target_host: plan.network_alias().as_str().to_owned(),
            target_port: container_port,
            network: Some(FIXED_KAMAL_NETWORK_NAME.to_owned()),
            image_digest: Some(plan.image_registry_digest().as_str().to_owned()),
            successful_samples: 1,
            minimum_interval_ms: 0,
        })
    }

    fn consumer_smoke(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
        if self.config.is_none() {
            return Err(RimgAdapterError::RuntimeConfigMismatch);
        }
        let bundle = self.authorized_release_bundle(spec)?;
        let plan = bundle.deployment_plan();
        let (_host_port, container_port) = Self::health_port(&bundle)?;
        let arguments = self.consumer_health_arguments(&bundle)?;
        Self::run_health_command_owned_with_retry(&self.docker_path, &arguments)?;
        let interval_started = Instant::now();
        thread::sleep(CONSUMER_SMOKE_INTERVAL);
        Self::run_health_command_owned_with_retry(&self.docker_path, &arguments)?;
        let minimum_interval_ms = u64::try_from(interval_started.elapsed().as_millis())
            .map_err(|_| RimgAdapterError::HealthObservationMismatch)?;
        if minimum_interval_ms
            < u64::try_from(CONSUMER_SMOKE_INTERVAL.as_millis())
                .map_err(|_| RimgAdapterError::HealthObservationMismatch)?
        {
            return Err(RimgAdapterError::HealthObservationMismatch);
        }
        RimgObservedDocumentV1::from_document(RimgHealthObservationV1 {
            schema_version: 1,
            check: RimgHealthCheckKindV1::ConsumerNetwork,
            target_host: plan.network_alias().as_str().to_owned(),
            target_port: container_port,
            network: Some(FIXED_KAMAL_NETWORK_NAME.to_owned()),
            image_digest: Some(plan.image_registry_digest().as_str().to_owned()),
            successful_samples: 2,
            minimum_interval_ms,
        })
    }

    fn wait_before_soak_poll(&mut self) -> Result<(), RimgAdapterError> {
        thread::sleep(Duration::from_secs(30));
        Ok(())
    }
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn invoke_observed_json<T: DeserializeOwned + Serialize>(
    executable: &Path,
    arguments: &[&str],
) -> Result<RimgObservedDocumentV1<T>, RimgAdapterError> {
    let output = run_bounded_command(executable, arguments)?;
    if !output.status.success() {
        return Err(RimgAdapterError::CommandFailed(format!(
            "exit status {}",
            output.status
        )));
    }
    let document = serde_json::from_slice::<T>(&output.stdout)?;
    RimgObservedDocumentV1::from_document(document)
}

fn run_bounded_command(
    executable: &Path,
    arguments: &[&str],
) -> Result<BoundedCommandOutput, RimgAdapterError> {
    let mut child = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("rimg stdout pipe is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("rimg stderr pipe is unavailable"))?;
    let stdout_reader = thread::spawn(move || read_pipe_bounded(stdout, MAX_COMMAND_STDOUT_BYTES));
    let stderr_reader = thread::spawn(move || read_pipe_bounded(stderr, MAX_COMMAND_STDERR_BYTES));
    let deadline = Instant::now() + COMMAND_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_pipe_reader(stdout_reader);
                let _ = join_pipe_reader(stderr_reader);
                return Err(RimgAdapterError::CommandDeadlineExceeded);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_pipe_reader(stdout_reader);
                let _ = join_pipe_reader(stderr_reader);
                return Err(error.into());
            }
        }
    };
    let stdout = join_pipe_reader(stdout_reader)?;
    let _stderr = join_pipe_reader(stderr_reader)?;
    Ok(BoundedCommandOutput { status, stdout })
}

fn join_pipe_reader(
    reader: thread::JoinHandle<Result<Vec<u8>, RimgAdapterError>>,
) -> Result<Vec<u8>, RimgAdapterError> {
    reader
        .join()
        .map_err(|_| io::Error::other("rimg output reader panicked"))?
}

fn read_pipe_bounded(
    mut pipe: impl io::Read,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RimgAdapterError> {
    let mut bytes = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut exceeded = false;
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        exceeded |= read > remaining;
    }
    if exceeded {
        Err(RimgAdapterError::CommandOutputTooLarge)
    } else {
        Ok(bytes)
    }
}

fn materialize_or_verify_private_file(
    path: &Path,
    required_uid: u32,
    expected: &[u8],
) -> Result<(), RimgAdapterError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(expected)?;
                    file.sync_all()?;
                    File::open(
                        path.parent()
                            .ok_or(RimgAdapterError::RuntimeConfigMismatch)?,
                    )?
                    .sync_all()?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    let actual = read_stable_private_file(
        path,
        required_uid,
        u64::try_from(expected.len()).unwrap_or(u64::MAX),
    )?;
    if actual != expected {
        return Err(RimgAdapterError::RequestFileConflict);
    }
    Ok(())
}

pub(crate) fn read_stable_private_file(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, RimgAdapterError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    Ok(bytes)
}

pub(crate) fn validate_private_directory(
    path: &Path,
    required_uid: u32,
) -> Result<(), RimgAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != required_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    Ok(())
}

pub(crate) fn validate_executable(
    path: &Path,
    required_uid: u32,
    expected_digest: &EvidenceDigest,
) -> Result<(), RimgAdapterError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o022 != 0
        || path_metadata.mode() & 0o111 == 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_RIMG_EXECUTABLE_BYTES
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    let mut file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let actual = format!("{:x}", hasher.finalize());
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
        || EvidenceDigest::from_str(&actual).ok().as_ref() != Some(expected_digest)
    {
        return Err(RimgAdapterError::UnsafeRuntimeFile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::*;
    use crate::phase6::tests::test_migration_phase_spec;

    #[test]
    fn runtime_config_is_canonical_policy_bound_and_hashes_the_exact_executable() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let executable = directory.path().join("rimg-cli");
        let docker = directory.path().join("docker");
        fs::write(&executable, b"fixed rimg executable")
            .unwrap_or_else(|error| panic!("write executable: {error}"));
        fs::write(&docker, b"fixed docker executable")
            .unwrap_or_else(|error| panic!("write docker executable: {error}"));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("executable permissions: {error}"));
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("docker permissions: {error}"));
        let spec = test_migration_phase_spec();
        let config = InstalledRimgAdapterRuntimeV1 {
            purpose: "rdashboard.installed-rimg-adapter-runtime.v1".to_owned(),
            schema_version: 2,
            project_id: spec.project_id.clone(),
            installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
            rimg_cli_sha256: EvidenceDigest::sha256(b"fixed rimg executable"),
            docker_cli_sha256: EvidenceDigest::sha256(b"fixed docker executable"),
        };
        let config_path = directory.path().join("adapter-runtime.jcs");
        fs::write(
            &config_path,
            serde_jcs::to_vec(&config).unwrap_or_else(|error| panic!("config bytes: {error}")),
        )
        .unwrap_or_else(|error| panic!("write config: {error}"));
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("config permissions: {error}"));

        assert_eq!(
            InstalledRimgAdapterRuntimeV1::load(&config_path, &executable, &docker, uid, &spec,)
                .unwrap_or_else(|error| panic!("load config: {error}")),
            config
        );
        fs::write(&executable, b"substituted executable")
            .unwrap_or_else(|error| panic!("substitute executable: {error}"));
        assert!(matches!(
            InstalledRimgAdapterRuntimeV1::load(&config_path, &executable, &docker, uid, &spec,),
            Err(RimgAdapterError::UnsafeRuntimeFile)
        ));
    }

    #[test]
    fn identity_request_is_owner_only_replay_stable_and_conflict_detecting() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("directory permissions: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let runtime = InstalledRimgAdminRuntimeV1::new_bound(
            Path::new("/tmp/rimg-cli"),
            Path::new("/tmp/rimg.db"),
            directory.path(),
            uid,
        )
        .unwrap_or_else(|error| panic!("runtime: {error}"));
        let first = RimgMigrationRequestV1 {
            schema_version: 1,
            epoch: 7,
            token: uuid::Uuid::new_v4(),
            operation_lock_path: RIMG_OPERATION_LOCK_PATH,
            operation_id: uuid::Uuid::new_v4(),
            from_application_schema: 1,
            to_application_schema: 2,
        };
        let path = runtime
            .materialize_request(MIGRATION_REQUEST_FILE_NAME, &first)
            .unwrap_or_else(|error| panic!("request: {error}"));
        runtime
            .materialize_request(MIGRATION_REQUEST_FILE_NAME, &first)
            .unwrap_or_else(|error| panic!("request replay: {error}"));
        assert_eq!(
            fs::metadata(&path)
                .unwrap_or_else(|error| panic!("request metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let second = RimgMigrationRequestV1 {
            token: uuid::Uuid::new_v4(),
            ..first.clone()
        };
        assert!(matches!(
            runtime.materialize_request(MIGRATION_REQUEST_FILE_NAME, &second),
            Err(RimgAdapterError::RequestFileConflict)
        ));
    }
}
