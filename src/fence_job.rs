use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    fence_adapter::{
        FenceAdapterActionV1, FenceAdapterError, FenceAdapterRequestV1, FenceAdapterResultV1,
    },
    store::FenceLease,
};

pub const FENCE_ADAPTER_JOB_ROOT: &str = "/run/rdashboard/fence-jobs";
pub const FENCE_ADAPTER_EXECUTABLE: &str = "/usr/libexec/rdashboard/rimg-fence-adapter";
pub const FENCE_ADAPTER_REQUEST_PATH: &str = "/job/request.jcs";
pub const FENCE_ADAPTER_RESULT_PATH: &str = "/job/result.jcs";

const REQUEST_FILE_NAME: &str = "request.jcs";
const RESULT_FILE_NAME: &str = "result.jcs";
const PENDING_RESULT_FILE_NAME: &str = "result.jcs.pending";
const SYSTEMD_RUN_EXECUTABLE: &str = "/usr/bin/systemd-run";
const SYSTEMCTL_EXECUTABLE: &str = "/usr/bin/systemctl";
const ENV_EXECUTABLE: &str = "/usr/bin/env";
const RIMG_DATA_ROOT: &str = "/var/lib/rimg/data";
const MAX_FENCE_DOCUMENT_BYTES: u64 = 64 * 1024;
const FENCE_TIMEOUT: Duration = Duration::from_mins(1);
const OUTER_DEADLINE_GRACE: Duration = Duration::from_secs(15);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedFenceJobStateV1 {
    ReadyToExecute,
    ResultRequiresReconciliation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedFenceJobV1 {
    job_directory: PathBuf,
    request_path: PathBuf,
    result_path: PathBuf,
    request: FenceAdapterRequestV1,
    required_uid: u32,
    state: PreparedFenceJobStateV1,
}

impl PreparedFenceJobV1 {
    pub fn prepare(
        request: &FenceAdapterRequestV1,
        lease: &FenceLease,
    ) -> Result<Self, FenceJobError> {
        Self::prepare_in(Path::new(FENCE_ADAPTER_JOB_ROOT), 0, request, lease)
    }

    pub(crate) fn prepare_in(
        job_root: &Path,
        required_uid: u32,
        request: &FenceAdapterRequestV1,
        lease: &FenceLease,
    ) -> Result<Self, FenceJobError> {
        request.validate_for_lease(lease)?;
        let request_bytes = request.canonical_bytes()?;
        ensure_job_root(job_root, required_uid)?;
        let project_directory = job_root.join(request.project_id.as_str());
        ensure_private_directory(&project_directory, required_uid)?;
        let attempt_directory = project_directory.join(request.attempt_id.to_string());
        ensure_private_directory(&attempt_directory, required_uid)?;
        let action = match request.action {
            FenceAdapterActionV1::Acquire => "acquire",
            FenceAdapterActionV1::ReleaseAndResume => "release-resume",
        };
        let job_directory = attempt_directory.join(format!("{action}-{}", request.request_digest));
        ensure_private_directory(&job_directory, required_uid)?;
        let request_path = job_directory.join(REQUEST_FILE_NAME);
        materialize_or_verify_request(&request_path, required_uid, &request_bytes, request)?;
        sync_directory(&job_directory, required_uid)?;
        let result_path = job_directory.join(RESULT_FILE_NAME);
        let state = inspect_existing_result(&result_path, required_uid)?;
        Ok(Self {
            job_directory,
            request_path,
            result_path,
            request: request.clone(),
            required_uid,
            state,
        })
    }

    pub fn job_directory(&self) -> &Path {
        &self.job_directory
    }

    pub fn request_path(&self) -> &Path {
        &self.request_path
    }

    pub fn result_path(&self) -> &Path {
        &self.result_path
    }

    pub const fn state(&self) -> PreparedFenceJobStateV1 {
        self.state
    }

    pub fn reconcile_result(&self) -> Result<FenceAdapterResultV1, FenceJobError> {
        read_result(&self.result_path, self.required_uid, &self.request)
    }

    pub fn transient_unit_plan(&self) -> Result<TransientFenceUnitPlanV1, FenceJobError> {
        if self.state != PreparedFenceJobStateV1::ReadyToExecute {
            return Err(FenceJobError::ResultRequiresReconciliation);
        }
        let job_directory = self
            .job_directory
            .to_str()
            .filter(|path| valid_bind_source(path))
            .ok_or(FenceJobError::UnsafeJobPath)?;
        let unit_name = format!(
            "rdashboard-fence-{}-{}",
            self.request.attempt_id.to_string().replace('-', ""),
            &self.request.request_digest.to_string()[..16]
        );
        let arguments = vec![
            "--no-ask-password".to_owned(),
            "--quiet".to_owned(),
            "--wait".to_owned(),
            "--collect".to_owned(),
            "--expand-environment=no".to_owned(),
            "--service-type=exec".to_owned(),
            format!("--unit={unit_name}"),
            "--working-directory=/job".to_owned(),
            "--property=User=root".to_owned(),
            "--property=Group=root".to_owned(),
            "--property=UMask=0077".to_owned(),
            "--property=SetLoginEnvironment=no".to_owned(),
            "--property=StandardOutput=null".to_owned(),
            "--property=StandardError=null".to_owned(),
            "--property=NoNewPrivileges=yes".to_owned(),
            "--property=PrivateDevices=yes".to_owned(),
            "--property=PrivateTmp=yes".to_owned(),
            "--property=ProtectClock=yes".to_owned(),
            "--property=ProtectControlGroups=yes".to_owned(),
            "--property=ProtectHome=yes".to_owned(),
            "--property=InaccessiblePaths=/etc/rdashboard/credentials".to_owned(),
            "--property=ProtectHostname=yes".to_owned(),
            "--property=ProtectKernelLogs=yes".to_owned(),
            "--property=ProtectKernelModules=yes".to_owned(),
            "--property=ProtectKernelTunables=yes".to_owned(),
            "--property=ProtectSystem=strict".to_owned(),
            "--property=ReadWritePaths=/job".to_owned(),
            format!("--property=ReadWritePaths={RIMG_DATA_ROOT}"),
            "--property=RestrictNamespaces=yes".to_owned(),
            "--property=RestrictRealtime=yes".to_owned(),
            "--property=RestrictSUIDSGID=yes".to_owned(),
            "--property=LockPersonality=yes".to_owned(),
            "--property=MemoryDenyWriteExecute=yes".to_owned(),
            "--property=KillMode=control-group".to_owned(),
            "--property=SendSIGKILL=yes".to_owned(),
            "--property=TimeoutStopSec=10s".to_owned(),
            "--property=TasksMax=64".to_owned(),
            "--property=LimitNOFILE=1024".to_owned(),
            "--property=MemoryMax=256M".to_owned(),
            "--property=RestrictAddressFamilies=AF_UNIX".to_owned(),
            format!("--property=RuntimeMaxSec={}ms", FENCE_TIMEOUT.as_millis()),
            format!("--property=BindPaths={job_directory}:/job"),
            "--".to_owned(),
            ENV_EXECUTABLE.to_owned(),
            "-i".to_owned(),
            FENCE_ADAPTER_EXECUTABLE.to_owned(),
            "--request".to_owned(),
            FENCE_ADAPTER_REQUEST_PATH.to_owned(),
            "--result".to_owned(),
            FENCE_ADAPTER_RESULT_PATH.to_owned(),
        ];
        Ok(TransientFenceUnitPlanV1 {
            unit_name,
            arguments,
            outer_deadline: FENCE_TIMEOUT.saturating_add(OUTER_DEADLINE_GRACE),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientFenceUnitPlanV1 {
    unit_name: String,
    arguments: Vec<String>,
    outer_deadline: Duration,
}

impl TransientFenceUnitPlanV1 {
    pub const fn executable(&self) -> &'static str {
        SYSTEMD_RUN_EXECUTABLE
    }

    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub const fn outer_deadline(&self) -> Duration {
        self.outer_deadline
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdTransientFenceRunnerV1;

impl SystemdTransientFenceRunnerV1 {
    pub fn execute(self, job: &PreparedFenceJobV1) -> Result<FenceAdapterResultV1, FenceJobError> {
        if job.required_uid != 0
            || job.state != PreparedFenceJobStateV1::ReadyToExecute
            || inspect_existing_result(&job.result_path, job.required_uid)?
                != PreparedFenceJobStateV1::ReadyToExecute
        {
            return Err(FenceJobError::UnsafeExecutionState);
        }
        verify_existing_request(
            &job.request_path,
            job.required_uid,
            &job.request.canonical_bytes()?,
            &job.request,
        )?;
        for executable in [
            SYSTEMD_RUN_EXECUTABLE,
            SYSTEMCTL_EXECUTABLE,
            ENV_EXECUTABLE,
            FENCE_ADAPTER_EXECUTABLE,
        ] {
            validate_installed_executable(executable)?;
        }
        let plan = job.transient_unit_plan()?;
        let child = Command::new(plan.executable())
            .args(plan.arguments())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(FenceJobError::SpawnSystemdRun)?;
        let status = wait_for_systemd_run(child, &plan)?;
        if !status.success() {
            return Err(FenceJobError::UnitFailed(status));
        }
        job.reconcile_result()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledFenceInvocationV1;

impl InstalledFenceInvocationV1 {
    pub fn parse(arguments: &[String]) -> Result<Self, FenceJobError> {
        if arguments
            != [
                "--request",
                FENCE_ADAPTER_REQUEST_PATH,
                "--result",
                FENCE_ADAPTER_RESULT_PATH,
            ]
        {
            return Err(FenceJobError::InvalidInvocation);
        }
        Ok(Self)
    }

    pub fn load_request(&self) -> Result<FenceAdapterRequestV1, FenceJobError> {
        let bytes = read_private_file(
            Path::new(FENCE_ADAPTER_REQUEST_PATH),
            0,
            MAX_FENCE_DOCUMENT_BYTES,
        )?;
        Ok(FenceAdapterRequestV1::decode_canonical(&bytes)?)
    }

    pub fn existing_result(
        &self,
        request: &FenceAdapterRequestV1,
    ) -> Result<Option<FenceAdapterResultV1>, FenceJobError> {
        read_optional_result(Path::new(FENCE_ADAPTER_RESULT_PATH), 0, request)
    }

    pub fn reconcile_pending_result(
        &self,
        request: &FenceAdapterRequestV1,
    ) -> Result<Option<FenceAdapterResultV1>, FenceJobError> {
        if let Some(result) = self.existing_result(request)? {
            return Ok(Some(result));
        }
        let pending_path = Path::new("/job").join(PENDING_RESULT_FILE_NAME);
        let Some(result) = read_optional_result(&pending_path, 0, request)? else {
            return Ok(None);
        };
        self.publish_result(request, &result)?;
        Ok(Some(result))
    }

    pub fn publish_result(
        &self,
        request: &FenceAdapterRequestV1,
        result: &FenceAdapterResultV1,
    ) -> Result<(), FenceJobError> {
        result.validate(request)?;
        if let Some(existing) = self.existing_result(request)? {
            return if existing == *result {
                Ok(())
            } else {
                Err(FenceJobError::ResultConflict)
            };
        }
        let bytes = result.canonical_bytes()?;
        let pending_path = Path::new("/job").join(PENDING_RESULT_FILE_NAME);
        materialize_or_verify_result(&pending_path, 0, &bytes, request)?;
        match fs::hard_link(&pending_path, FENCE_ADAPTER_RESULT_PATH) {
            Ok(()) => sync_directory(Path::new("/job"), 0)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = self
                    .existing_result(request)?
                    .ok_or(FenceJobError::ResultConflict)?;
                if existing != *result {
                    return Err(FenceJobError::ResultConflict);
                }
            }
            Err(error) => return Err(error.into()),
        }
        match fs::remove_file(&pending_path) {
            Ok(()) => sync_directory(Path::new("/job"), 0)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let existing = self
            .existing_result(request)?
            .ok_or(FenceJobError::ResultConflict)?;
        if existing == *result {
            Ok(())
        } else {
            Err(FenceJobError::ResultConflict)
        }
    }
}

fn wait_for_systemd_run(
    mut child: Child,
    plan: &TransientFenceUnitPlanV1,
) -> Result<ExitStatus, FenceJobError> {
    let deadline = Instant::now() + plan.outer_deadline();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(source) => {
                let cleanup_failed = cleanup_failed_child(&mut child, plan.unit_name());
                return Err(FenceJobError::WaitSystemdRun {
                    source,
                    cleanup_failed,
                });
            }
        }
        if Instant::now() >= deadline {
            let cleanup_failed = cleanup_failed_child(&mut child, plan.unit_name());
            return Err(FenceJobError::DeadlineExceeded { cleanup_failed });
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn cleanup_failed_child(child: &mut Child, unit_name: &str) -> bool {
    let cleanup_failed = terminate_transient_unit(unit_name).is_err();
    let _ = child.kill();
    let _ = child.wait();
    cleanup_failed
}

fn terminate_transient_unit(unit_name: &str) -> Result<(), FenceJobError> {
    let kill = run_systemctl_bounded(&["kill", "--kill-who=all", "--signal=KILL", unit_name])?;
    let stop = run_systemctl_bounded(&["stop", unit_name])?;
    if kill.success() && stop.success() {
        Ok(())
    } else {
        Err(FenceJobError::UnitTerminationFailed)
    }
}

fn run_systemctl_bounded(arguments: &[&str]) -> Result<ExitStatus, FenceJobError> {
    let mut child = Command::new(SYSTEMCTL_EXECUTABLE)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(FenceJobError::TerminateUnit)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().map_err(FenceJobError::TerminateUnit)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(FenceJobError::UnitTerminationDeadlineExceeded);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn valid_bind_source(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 512
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn validate_installed_executable(path: &'static str) -> Result<(), FenceJobError> {
    let path = Path::new(path);
    let path_metadata = fs::symlink_metadata(path).map_err(FenceJobError::InspectExecutable)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != 0
        || path_metadata.mode() & 0o022 != 0
        || path_metadata.mode() & 0o111 == 0
    {
        return Err(FenceJobError::UnsafeInstalledExecutable);
    }
    let opened = File::open(path).map_err(FenceJobError::InspectExecutable)?;
    let opened_metadata = opened
        .metadata()
        .map_err(FenceJobError::InspectExecutable)?;
    let final_metadata = fs::symlink_metadata(path).map_err(FenceJobError::InspectExecutable)?;
    if final_metadata.file_type().is_symlink()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(FenceJobError::UnsafeInstalledExecutable);
    }
    Ok(())
}

fn ensure_job_root(path: &Path, required_uid: u32) -> Result<(), FenceJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, required_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(FenceJobError::UnsafeJobRoot)?;
            validate_parent_directory(parent, required_uid)?;
            create_private_directory(path)?;
            validate_private_directory(path, required_uid)?;
            sync_directory(parent, required_uid)
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_private_directory(path: &Path, required_uid: u32) -> Result<(), FenceJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, required_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(FenceJobError::UnsafeJobRoot)?;
            validate_private_directory(parent, required_uid)?;
            create_private_directory(path)?;
            validate_private_directory(path, required_uid)?;
            sync_directory(parent, required_uid)
        }
        Err(error) => Err(error.into()),
    }
}

fn create_private_directory(path: &Path) -> Result<(), FenceJobError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_parent_directory(path: &Path, required_uid: u32) -> Result<(), FenceJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o022 != 0 {
        return Err(FenceJobError::UnsafeJobRoot);
    }
    Ok(())
}

fn validate_private_directory(path: &Path, required_uid: u32) -> Result<(), FenceJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o077 != 0 {
        return Err(FenceJobError::UnsafeJobRoot);
    }
    Ok(())
}

fn stable_directory_metadata(path: &Path) -> Result<fs::Metadata, FenceJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_dir() {
        return Err(FenceJobError::UnsafeJobRoot);
    }
    let directory = File::open(path)?;
    let opened_metadata = directory.metadata()?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(FenceJobError::JobPathChanged);
    }
    Ok(final_metadata)
}

fn materialize_or_verify_request(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
    request: &FenceAdapterRequestV1,
) -> Result<(), FenceJobError> {
    materialize_or_verify_file(path, required_uid, bytes)?;
    let actual = read_private_file(path, required_uid, MAX_FENCE_DOCUMENT_BYTES)?;
    if actual != bytes || FenceAdapterRequestV1::decode_canonical(&actual)? != *request {
        return Err(FenceJobError::RequestConflict);
    }
    Ok(())
}

fn materialize_or_verify_result(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
    request: &FenceAdapterRequestV1,
) -> Result<(), FenceJobError> {
    materialize_or_verify_file(path, required_uid, bytes)?;
    let actual = read_private_file(path, required_uid, MAX_FENCE_DOCUMENT_BYTES)?;
    if actual != bytes {
        return Err(FenceJobError::ResultConflict);
    }
    FenceAdapterResultV1::decode_canonical(&actual, request)?;
    Ok(())
}

fn materialize_or_verify_file(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
) -> Result<(), FenceJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    sync_directory(
                        path.parent().ok_or(FenceJobError::UnsafeJobPath)?,
                        required_uid,
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn verify_existing_request(
    path: &Path,
    required_uid: u32,
    expected: &[u8],
    request: &FenceAdapterRequestV1,
) -> Result<(), FenceJobError> {
    let bytes = read_private_file(path, required_uid, MAX_FENCE_DOCUMENT_BYTES)?;
    if bytes != expected || FenceAdapterRequestV1::decode_canonical(&bytes)? != *request {
        return Err(FenceJobError::RequestConflict);
    }
    Ok(())
}

fn inspect_existing_result(
    path: &Path,
    required_uid: u32,
) -> Result<PreparedFenceJobStateV1, FenceJobError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(PreparedFenceJobStateV1::ReadyToExecute)
        }
        Err(error) => Err(error.into()),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && metadata.uid() == required_uid
                && metadata.mode().trailing_zeros() >= 6
                && metadata.len() > 0
                && metadata.len() <= MAX_FENCE_DOCUMENT_BYTES =>
        {
            Ok(PreparedFenceJobStateV1::ResultRequiresReconciliation)
        }
        Ok(_) => Err(FenceJobError::UnsafeResultDocument),
    }
}

fn read_result(
    path: &Path,
    required_uid: u32,
    request: &FenceAdapterRequestV1,
) -> Result<FenceAdapterResultV1, FenceJobError> {
    let bytes = read_private_file(path, required_uid, MAX_FENCE_DOCUMENT_BYTES)?;
    Ok(FenceAdapterResultV1::decode_canonical(&bytes, request)?)
}

fn read_optional_result(
    path: &Path,
    required_uid: u32,
    request: &FenceAdapterRequestV1,
) -> Result<Option<FenceAdapterResultV1>, FenceJobError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(Some(read_result(path, required_uid, request)?)),
    }
}

fn read_private_file(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, FenceJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(FenceJobError::UnsafeDocument);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(FenceJobError::JobPathChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(FenceJobError::JobPathChanged);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path, required_uid: u32) -> Result<(), FenceJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o022 != 0 {
        return Err(FenceJobError::UnsafeJobRoot);
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FenceJobError {
    #[error(transparent)]
    Fence(#[from] FenceAdapterError),
    #[error("fixed fence job filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("fixed fence job root or directory is not owner-only and stable")]
    UnsafeJobRoot,
    #[error("fixed fence job path changed while it was being validated")]
    JobPathChanged,
    #[error("fixed fence job path is not safe for a systemd bind mount")]
    UnsafeJobPath,
    #[error("fixed fence request conflicts with an existing replay document")]
    RequestConflict,
    #[error("fixed fence result conflicts with an existing replay document")]
    ResultConflict,
    #[error("fixed fence request or result is not a bounded owner-only regular file")]
    UnsafeDocument,
    #[error("fixed fence result is not a bounded owner-only regular file")]
    UnsafeResultDocument,
    #[error("an existing fixed fence result must be reconciled before execution")]
    ResultRequiresReconciliation,
    #[error("fixed fence execution is not in the root production namespace or is not fresh")]
    UnsafeExecutionState,
    #[error("fixed fence adapter invocation is not the installed fixed invocation")]
    InvalidInvocation,
    #[error("an installed fence executable could not be inspected: {0}")]
    InspectExecutable(io::Error),
    #[error("an installed fence executable is not a stable root-owned executable file")]
    UnsafeInstalledExecutable,
    #[error("systemd-run could not start the fixed fence unit: {0}")]
    SpawnSystemdRun(io::Error),
    #[error("systemd-run could not be waited (cleanup_failed={cleanup_failed}): {source}")]
    WaitSystemdRun {
        source: io::Error,
        cleanup_failed: bool,
    },
    #[error("fixed fence transient unit exceeded its deadline (cleanup_failed={cleanup_failed})")]
    DeadlineExceeded { cleanup_failed: bool },
    #[error("fixed fence transient unit failed with {0}")]
    UnitFailed(ExitStatus),
    #[error("systemctl could not terminate the fixed fence unit: {0}")]
    TerminateUnit(io::Error),
    #[error("systemctl did not confirm fixed fence unit termination")]
    UnitTerminationFailed,
    #[error("systemctl did not terminate the fixed fence unit within five seconds")]
    UnitTerminationDeadlineExceeded,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _, str::FromStr as _};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        domain::{EvidenceDigest, ProjectId},
        fence_adapter::{FenceAdapterActionV1, FenceAdapterRequestV1},
        store::{FenceJournalState, FenceLease},
    };

    fn lease() -> FenceLease {
        FenceLease {
            journal_id: 1,
            project_id: ProjectId::from_str("rimg")
                .unwrap_or_else(|error| panic!("project: {error}")),
            attempt_id: uuid::Uuid::new_v4(),
            epoch: 8,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 10,
            state: FenceJournalState::AcquireIntent,
            release_safe_receipt_digest: None,
        }
    }

    fn request(lease: &FenceLease) -> FenceAdapterRequestV1 {
        FenceAdapterRequestV1::from_lease(
            FenceAdapterActionV1::Acquire,
            lease,
            EvidenceDigest::sha256("installed policy"),
        )
        .unwrap_or_else(|error| panic!("request: {error}"))
    }

    #[test]
    fn job_materialization_is_private_deterministic_and_replay_safe() {
        let temporary = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("permissions: {error}"));
        let uid = fs::metadata(temporary.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let root = temporary.path().join("fence-jobs");
        let lease = lease();
        let request = request(&lease);
        let first = PreparedFenceJobV1::prepare_in(&root, uid, &request, &lease)
            .unwrap_or_else(|error| panic!("first prepare: {error}"));
        let replay = PreparedFenceJobV1::prepare_in(&root, uid, &request, &lease)
            .unwrap_or_else(|error| panic!("replay prepare: {error}"));
        assert_eq!(first, replay);
        assert_eq!(first.state(), PreparedFenceJobStateV1::ReadyToExecute);
        assert_eq!(
            fs::metadata(first.job_directory())
                .unwrap_or_else(|error| panic!("job metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(first.request_path())
                .unwrap_or_else(|error| panic!("request metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn transient_unit_does_not_expose_fence_identity_in_argv() {
        let temporary = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("permissions: {error}"));
        let uid = fs::metadata(temporary.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let lease = lease();
        let request = request(&lease);
        let job = PreparedFenceJobV1::prepare_in(
            &temporary.path().join("fence-jobs"),
            uid,
            &request,
            &lease,
        )
        .unwrap_or_else(|error| panic!("prepare: {error}"));
        let plan = job
            .transient_unit_plan()
            .unwrap_or_else(|error| panic!("plan: {error}"));
        let command = plan.arguments().join(" ");
        assert!(!command.contains(&request.token.to_string()));
        assert!(!command.contains(&request.token.to_string().replace('-', "")));
        let epoch = request.epoch.to_string();
        assert!(plan.arguments().iter().all(|argument| {
            argument != &epoch
                && !argument.contains(&format!("epoch-{epoch}"))
                && !argument.contains(&format!("epoch={epoch}"))
        }));
        assert!(command.contains("ProtectSystem=strict"));
        assert!(command.contains("ReadWritePaths=/var/lib/rimg/data"));
        assert!(command.ends_with(
            "/usr/libexec/rdashboard/rimg-fence-adapter --request /job/request.jcs --result /job/result.jcs"
        ));
    }
}
