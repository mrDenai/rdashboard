use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    adapter_identity::{AdapterIdentityError, AdapterOperationIdentityV1},
    adapter_result::{
        AdapterResultContractError, FixedAdapterResultV1, MAX_FIXED_ADAPTER_RESULT_BYTES,
    },
    domain::{
        EvidenceDigest, ExecutionCleanupReceiptV1, ExecutionCleanupStateV1, ExecutionResultV1,
        ExecutionTerminalReceiptV1, ProjectId,
    },
    execution_receipt::{
        ExecutionReceiptRuntimeError, ExecutionTerminationKindV1,
        INSTALLED_ADAPTER_RECEIPT_EXECUTABLE, execution_started, materialize_cleanup_receipt,
        materialize_execution_start, materialize_termination_intent, read_cleanup_receipt,
        read_terminal_receipt,
    },
    phase6::{
        AdapterResultSchemaV1, AuthorizedPhaseSpecV1, FixedAdapterProfileV1, FixedAdapterRequestV1,
        FixedCommandDefinitionV1, Phase6ContractError,
    },
};

pub const FIXED_ADAPTER_JOB_ROOT: &str = "/run/rdashboard/adapter-jobs";
pub const SYSTEMD_RUN_EXECUTABLE: &str = "/usr/bin/systemd-run";

const REQUEST_FILE_NAME: &str = "request.jcs";
const SPEC_FILE_NAME: &str = "spec.jcs";
const OPERATION_IDENTITY_FILE_NAME: &str = "operation-identity.jcs";
const RESULT_FILE_NAME: &str = "result.jcs";
const MAX_EXISTING_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_EXISTING_RESULT_BYTES: u64 = 256 * 1024;
const SYSTEMCTL_EXECUTABLE: &str = "/usr/bin/systemctl";
const ENV_EXECUTABLE: &str = "/usr/bin/env";
const ADAPTER_INPUT_ROOT: &str = "/inputs";
const RIMG_DATA_ROOT: &str = "/var/lib/rimg/data";
const RDASHBOARD_BACKUP_ROOT: &str = "/var/lib/rdashboard-executor/backups";
const RDASHBOARD_LOCK_ROOT: &str = "/var/lib/rdashboard-executor/locks";
pub const DRIVE_SERVICE_ACCOUNT_CREDENTIAL_NAME: &str = "rimg-drive-service-account.json";
pub const DRIVE_SERVICE_ACCOUNT_CREDENTIAL_SOURCE: &str =
    "/etc/rdashboard/credentials/rimg-drive-service-account.json";
pub const KAMAL_SECRETS_CREDENTIAL_NAME: &str = "rimg-kamal-secrets.env";
pub const KAMAL_SECRETS_CREDENTIAL_SOURCE: &str =
    "/etc/rdashboard/credentials/rimg-kamal-secrets.env";
pub const KAMAL_SSH_KEY_CREDENTIAL_NAME: &str = "rimg-kamal-ssh-key";
pub const KAMAL_SSH_KEY_CREDENTIAL_SOURCE: &str = "/etc/rdashboard/credentials/rimg-kamal-ssh-key";
const PROJECT_CREDENTIAL_ROOT: &str = "/etc/rdashboard/credentials/projects";
const OUTER_DEADLINE_GRACE: Duration = Duration::from_secs(15);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedAdapterJobStateV1 {
    ReadyToExecute,
    ResultRequiresReconciliation,
    ExecutionRequiresReconciliation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAdapterJobV1 {
    project_id: ProjectId,
    job_directory: PathBuf,
    spec_path: PathBuf,
    request_path: PathBuf,
    operation_identity_path: PathBuf,
    result_path: PathBuf,
    request_document_digest: EvidenceDigest,
    sequence: u16,
    profile: FixedAdapterProfileV1,
    result_schema: AdapterResultSchemaV1,
    timeout_ms: u64,
    required_uid: u32,
    state: PreparedAdapterJobStateV1,
}

impl PreparedAdapterJobV1 {
    pub fn prepare(spec: &AuthorizedPhaseSpecV1, sequence: u16) -> Result<Self, AdapterJobError> {
        Self::prepare_in(Path::new(FIXED_ADAPTER_JOB_ROOT), 0, spec, sequence)
    }

    pub(crate) fn prepare_in(
        job_root: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
    ) -> Result<Self, AdapterJobError> {
        let request = spec.fixed_adapter_request(sequence)?;
        let request_bytes = request.canonical_bytes()?;
        let spec_bytes = spec.canonical_bytes()?;
        let step = spec
            .steps
            .iter()
            .find(|step| step.sequence == sequence)
            .ok_or(Phase6ContractError::UnknownAdapterStep(sequence))?;

        ensure_job_root(job_root, required_uid)?;
        let attempt_directory = job_root.join(spec.attempt_id.to_string());
        ensure_private_directory(&attempt_directory, required_uid)?;
        let spec_directory = attempt_directory.join(format!("spec-{}", spec.spec_digest));
        ensure_private_directory(&spec_directory, required_uid)?;
        let job_directory = spec_directory.join(format!("step-{sequence:05}"));
        ensure_private_directory(&job_directory, required_uid)?;

        let spec_path = job_directory.join(SPEC_FILE_NAME);
        materialize_or_verify_spec(&spec_path, required_uid, &spec_bytes, spec)?;
        let request_path = job_directory.join(REQUEST_FILE_NAME);
        materialize_or_verify_request(&request_path, required_uid, &request_bytes, spec, sequence)?;
        sync_directory(&job_directory, required_uid)?;

        let result_path = job_directory.join(RESULT_FILE_NAME);
        let operation_identity_path = job_directory.join(OPERATION_IDENTITY_FILE_NAME);
        let result_state = inspect_existing_result(&result_path, required_uid)?;
        let state = if result_state == PreparedAdapterJobStateV1::ReadyToExecute
            && execution_started(&job_directory, required_uid)?
        {
            PreparedAdapterJobStateV1::ExecutionRequiresReconciliation
        } else {
            result_state
        };
        Ok(Self {
            project_id: spec.project_id.clone(),
            job_directory,
            spec_path,
            request_path,
            operation_identity_path,
            result_path,
            request_document_digest: step.request_document_digest.clone(),
            sequence,
            profile: step.profile,
            result_schema: step.result_schema,
            timeout_ms: step.timeout_ms,
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

    pub fn spec_path(&self) -> &Path {
        &self.spec_path
    }

    pub fn result_path(&self) -> &Path {
        &self.result_path
    }

    pub fn operation_identity_path(&self) -> &Path {
        &self.operation_identity_path
    }

    pub fn materialize_operation_identity(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<(), AdapterJobError> {
        let request = spec.fixed_adapter_request(self.sequence)?;
        if request.digest()? != self.request_document_digest
            || spec.project_id != self.project_id
            || request.profile != self.profile
            || request.result_schema != self.result_schema
            || request.timeout_ms != self.timeout_ms
        {
            return Err(AdapterJobError::RequestDocumentConflict);
        }
        identity.validate_for(spec, &request)?;
        let spec_bytes = spec.canonical_bytes()?;
        verify_existing_spec(&self.spec_path, self.required_uid, &spec_bytes, spec)?;
        let request_bytes = request.canonical_bytes()?;
        verify_existing_request(
            &self.request_path,
            self.required_uid,
            &request_bytes,
            spec,
            self.sequence,
        )?;
        materialize_or_verify_operation_identity(
            &self.operation_identity_path,
            self.required_uid,
            &identity.canonical_bytes()?,
            identity,
            spec,
            &request,
        )?;
        sync_directory(&self.job_directory, self.required_uid)
    }

    pub const fn request_document_digest(&self) -> &EvidenceDigest {
        &self.request_document_digest
    }

    pub const fn sequence(&self) -> u16 {
        self.sequence
    }

    pub const fn profile(&self) -> FixedAdapterProfileV1 {
        self.profile
    }

    pub const fn result_schema(&self) -> AdapterResultSchemaV1 {
        self.result_schema
    }

    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub const fn state(&self) -> PreparedAdapterJobStateV1 {
        self.state
    }

    pub fn execution_command(&self) -> Result<FixedCommandDefinitionV1, AdapterJobError> {
        if self.state != PreparedAdapterJobStateV1::ReadyToExecute {
            return Err(AdapterJobError::ResultRequiresReconciliation);
        }
        Ok(self.profile.command())
    }

    pub fn transient_unit_plan(&self) -> Result<TransientAdapterUnitPlanV1, AdapterJobError> {
        TransientAdapterUnitPlanV1::for_job(self)
    }

    pub fn reconcile_result(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        prior_results: &[FixedAdapterResultV1],
    ) -> Result<FixedAdapterResultV1, AdapterJobError> {
        let request = spec.fixed_adapter_request(self.sequence)?;
        if request.digest()? != self.request_document_digest
            || request.profile != self.profile
            || request.result_schema != self.result_schema
            || request.timeout_ms != self.timeout_ms
        {
            return Err(AdapterJobError::ResultRequiresReconciliation);
        }
        let result = read_existing_result(
            &self.result_path,
            self.required_uid,
            spec,
            self.sequence,
            prior_results,
        )?;
        validate_completed_execution_evidence(self, spec)?;
        Ok(result)
    }
}

fn validate_completed_execution_evidence(
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<(), AdapterJobError> {
    if !execution_started(job.job_directory(), job.required_uid)? {
        return Ok(());
    }
    let terminal =
        read_terminal_receipt(job.job_directory(), job.required_uid, spec, job.sequence)?;
    let cleanup = read_cleanup_receipt(job.job_directory(), job.required_uid, &terminal)?;
    if terminal.process.result != ExecutionResultV1::Succeeded
        || cleanup.state != ExecutionCleanupStateV1::Complete
    {
        return Err(AdapterJobError::ExecutionRequiresReconciliation);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientAdapterUnitPlanV1 {
    unit_name: String,
    arguments: Vec<String>,
    outer_deadline: Duration,
}

impl TransientAdapterUnitPlanV1 {
    fn for_job(job: &PreparedAdapterJobV1) -> Result<Self, AdapterJobError> {
        let command = job.execution_command()?;
        if !command.environment_cleared || command.shell || command.working_directory != "/job" {
            return Err(AdapterJobError::UnsafeCommandDefinition);
        }
        let (unit_name, job_directory) = adapter_unit_identity(job)?;
        let input_bindings = prior_input_bindings(job)?;
        let arguments =
            transient_unit_arguments(job, command, &unit_name, &job_directory, &input_bindings);
        Ok(Self {
            unit_name,
            arguments,
            outer_deadline: Duration::from_millis(job.timeout_ms)
                .saturating_add(OUTER_DEADLINE_GRACE),
        })
    }

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

pub fn fixed_adapter_unit_name(
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
) -> Result<String, AdapterJobError> {
    spec.fixed_adapter_request(sequence)?;
    Ok(format!(
        "rdashboard-adapter-{}-{}-step-{sequence:05}",
        spec.attempt_id.to_string().replace('-', ""),
        spec.spec_digest
    ))
}

fn adapter_unit_identity(job: &PreparedAdapterJobV1) -> Result<(String, String), AdapterJobError> {
    let job_directory = job
        .job_directory
        .to_str()
        .filter(|path| valid_bind_source(path))
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    let spec_digest = job
        .job_directory
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("spec-"))
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    let attempt_id = job
        .job_directory
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|value| {
            value.len() == 36
                && value.bytes().all(|byte| {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) || byte == b'-'
                })
        })
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    let step_name = job
        .job_directory
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            name.strip_prefix("step-").is_some_and(|sequence| {
                sequence.len() == 5 && sequence.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    let unit_name = format!(
        "rdashboard-adapter-{}-{spec_digest}-{step_name}",
        attempt_id.replace('-', "")
    );
    Ok((unit_name, job_directory.to_owned()))
}

fn transient_unit_arguments(
    job: &PreparedAdapterJobV1,
    command: FixedCommandDefinitionV1,
    unit_name: &str,
    job_directory: &str,
    input_bindings: &[(String, String)],
) -> Vec<String> {
    let mut arguments = vec![
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
        format!("--property=TemporaryFileSystem={ADAPTER_INPUT_ROOT}:ro"),
        "--property=RestrictNamespaces=yes".to_owned(),
        "--property=RestrictRealtime=yes".to_owned(),
        "--property=RestrictSUIDSGID=yes".to_owned(),
        "--property=LockPersonality=yes".to_owned(),
        "--property=MemoryDenyWriteExecute=yes".to_owned(),
        "--property=KillMode=control-group".to_owned(),
        "--property=SendSIGKILL=yes".to_owned(),
        "--property=TimeoutStopSec=10s".to_owned(),
        format!("--property=ExecStopPost={INSTALLED_ADAPTER_RECEIPT_EXECUTABLE}"),
        "--property=TasksMax=256".to_owned(),
        "--property=LimitNOFILE=4096".to_owned(),
        "--property=MemoryMax=1G".to_owned(),
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_owned(),
        format!("--property=RuntimeMaxSec={}ms", job.timeout_ms),
        format!("--property=BindPaths={job_directory}:/job"),
    ];
    arguments.extend(input_bindings.iter().map(|(source, destination)| {
        format!("--property=BindReadOnlyPaths={source}:{destination}")
    }));
    arguments.extend(
        fixed_write_paths(job.profile)
            .iter()
            .map(|path| format!("--property=ReadWritePaths={path}")),
    );
    if drive_credentials_required(job.profile) {
        arguments.push(format!(
            "--property=LoadCredential={DRIVE_SERVICE_ACCOUNT_CREDENTIAL_NAME}:{DRIVE_SERVICE_ACCOUNT_CREDENTIAL_SOURCE}"
        ));
    }
    if kamal_credentials_required(job.profile) {
        let (secrets_source, ssh_key_source) = kamal_credential_sources(&job.project_id);
        arguments.extend([
            format!("--property=LoadCredential={KAMAL_SECRETS_CREDENTIAL_NAME}:{secrets_source}"),
            format!("--property=LoadCredential={KAMAL_SSH_KEY_CREDENTIAL_NAME}:{ssh_key_source}"),
        ]);
    }
    arguments.extend([
        "--".to_owned(),
        ENV_EXECUTABLE.to_owned(),
        "-i".to_owned(),
        command.executable.to_owned(),
    ]);
    arguments.extend(command.argv.iter().map(|argument| (*argument).to_owned()));
    arguments
}

fn kamal_credential_sources(project_id: &ProjectId) -> (String, String) {
    if project_id.as_str() == "rimg" {
        return (
            KAMAL_SECRETS_CREDENTIAL_SOURCE.to_owned(),
            KAMAL_SSH_KEY_CREDENTIAL_SOURCE.to_owned(),
        );
    }
    let root = format!("{PROJECT_CREDENTIAL_ROOT}/{}", project_id.as_str());
    (
        format!("{root}/kamal-secrets.env"),
        format!("{root}/kamal-ssh-key"),
    )
}

const fn drive_credentials_required(profile: FixedAdapterProfileV1) -> bool {
    matches!(
        profile,
        FixedAdapterProfileV1::BackupUploadGoogleDrive
            | FixedAdapterProfileV1::BackupReadbackVerify
    )
}

const fn kamal_credentials_required(profile: FixedAdapterProfileV1) -> bool {
    matches!(
        profile,
        FixedAdapterProfileV1::KamalBootstrapDeploy
            | FixedAdapterProfileV1::KamalCandidateDeploy
            | FixedAdapterProfileV1::KamalCodeRollback
    )
}

const fn fixed_write_paths(profile: FixedAdapterProfileV1) -> &'static [&'static str] {
    match profile {
        FixedAdapterProfileV1::RimgDrain => &[RIMG_DATA_ROOT],
        FixedAdapterProfileV1::RimgMigrate => &[RIMG_DATA_ROOT, RDASHBOARD_LOCK_ROOT],
        FixedAdapterProfileV1::BackupCapture => {
            &[RIMG_DATA_ROOT, RDASHBOARD_BACKUP_ROOT, RDASHBOARD_LOCK_ROOT]
        }
        FixedAdapterProfileV1::BackupEncryptAge => &[RDASHBOARD_BACKUP_ROOT],
        _ => &[],
    }
}

fn prior_input_bindings(
    job: &PreparedAdapterJobV1,
) -> Result<Vec<(String, String)>, AdapterJobError> {
    let spec_directory = job
        .job_directory
        .parent()
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    (1..job.sequence)
        .map(|sequence| {
            let step_name = format!("step-{sequence:05}");
            let source = spec_directory.join(&step_name);
            validate_private_directory(&source, job.required_uid)?;
            if inspect_existing_result(&source.join(RESULT_FILE_NAME), job.required_uid)?
                != PreparedAdapterJobStateV1::ResultRequiresReconciliation
            {
                return Err(AdapterJobError::MissingPriorResultDocument(sequence));
            }
            let source = source
                .to_str()
                .filter(|path| valid_bind_source(path))
                .ok_or(AdapterJobError::UnsafeJobPath)?
                .to_owned();
            Ok((source, format!("{ADAPTER_INPUT_ROOT}/{step_name}")))
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterExecutionOutputV1 {
    pub unit_name: String,
    pub terminal_receipt: ExecutionTerminalReceiptV1,
    pub cleanup_receipt: ExecutionCleanupReceiptV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterExecutionResultV1 {
    pub output: AdapterExecutionOutputV1,
    pub result: FixedAdapterResultV1,
}

#[derive(Clone, Debug, Default)]
pub struct AdapterExecutionCancellationV1 {
    cancelled: Arc<AtomicBool>,
}

impl AdapterExecutionCancellationV1 {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SystemdTransientAdapterRunnerV1 {
    cancellation: AdapterExecutionCancellationV1,
}

impl SystemdTransientAdapterRunnerV1 {
    pub const fn new(cancellation: AdapterExecutionCancellationV1) -> Self {
        Self { cancellation }
    }

    pub fn execute(
        &self,
        job: &PreparedAdapterJobV1,
        spec: &AuthorizedPhaseSpecV1,
        prior_results: &[FixedAdapterResultV1],
    ) -> Result<AdapterExecutionResultV1, AdapterJobError> {
        validate_execution_inputs(job, spec, prior_results)?;
        let plan = job.transient_unit_plan()?;
        if self.cancellation.is_cancelled() {
            return Err(AdapterJobError::ExecutionCancelled {
                cleanup_failed: false,
            });
        }
        let request = spec.fixed_adapter_request(job.sequence)?;
        materialize_execution_start(
            job.job_directory(),
            job.required_uid,
            &request,
            crate::unix_time_ms().map_err(AdapterJobError::Clock)?,
        )?;
        let child = spawn_systemd_run(&plan)?;
        let status = wait_for_systemd_run(child, &plan, &self.cancellation, job, spec)?;
        let output = finalize_execution_receipts(job, spec, &plan, true, None)?;
        if !status.success() {
            return Err(AdapterJobError::UnitFailed {
                status,
                output: Box::new(output),
            });
        }
        let result = job.reconcile_result(spec, prior_results)?;
        Ok(AdapterExecutionResultV1 { output, result })
    }
}

fn validate_execution_inputs(
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
    prior_results: &[FixedAdapterResultV1],
) -> Result<(), AdapterJobError> {
    if job.required_uid != 0 {
        return Err(AdapterJobError::UnsafeExecutionIdentity);
    }
    if execution_started(&job.job_directory, job.required_uid)? {
        return Err(AdapterJobError::ExecutionRequiresReconciliation);
    }
    if job.state != PreparedAdapterJobStateV1::ReadyToExecute
        || inspect_existing_result(&job.result_path, job.required_uid)?
            != PreparedAdapterJobStateV1::ReadyToExecute
    {
        return Err(AdapterJobError::ResultRequiresReconciliation);
    }
    let request = spec.fixed_adapter_request(job.sequence)?;
    if request.digest()? != job.request_document_digest
        || request.profile != job.profile
        || request.result_schema != job.result_schema
        || request.timeout_ms != job.timeout_ms
    {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    FixedAdapterResultV1::validate_prior_chain(spec, job.sequence, prior_results)?;
    validate_prior_result_files(job, spec, prior_results)?;
    let adapter_executable = job.execution_command()?.executable;
    for executable in [
        SYSTEMD_RUN_EXECUTABLE,
        SYSTEMCTL_EXECUTABLE,
        ENV_EXECUTABLE,
        INSTALLED_ADAPTER_RECEIPT_EXECUTABLE,
        adapter_executable,
    ] {
        validate_installed_executable(executable)?;
    }
    Ok(())
}

fn validate_prior_result_files(
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
    prior_results: &[FixedAdapterResultV1],
) -> Result<(), AdapterJobError> {
    if read_prior_result_chain(job, spec)? == prior_results {
        Ok(())
    } else {
        Err(AdapterJobError::PriorResultFilesystemMismatch)
    }
}

fn read_prior_result_chain(
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Vec<FixedAdapterResultV1>, AdapterJobError> {
    let spec_directory = job
        .job_directory
        .parent()
        .ok_or(AdapterJobError::UnsafeJobPath)?;
    let mut results = Vec::with_capacity(usize::from(job.sequence.saturating_sub(1)));
    for sequence in 1..job.sequence {
        let path = spec_directory
            .join(format!("step-{sequence:05}"))
            .join(RESULT_FILE_NAME);
        let result = read_existing_result(&path, job.required_uid, spec, sequence, &results)?;
        results.push(result);
    }
    Ok(results)
}

fn spawn_systemd_run(plan: &TransientAdapterUnitPlanV1) -> Result<Child, AdapterJobError> {
    Command::new(plan.executable())
        .args(plan.arguments())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(AdapterJobError::SpawnSystemdRun)
}

fn wait_for_systemd_run(
    mut child: Child,
    plan: &TransientAdapterUnitPlanV1,
    cancellation: &AdapterExecutionCancellationV1,
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<ExitStatus, AdapterJobError> {
    let deadline = Instant::now() + plan.outer_deadline();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                let cleanup_failed = cleanup_failed_child(&mut child, plan.unit_name());
                finalize_execution_receipts(
                    job,
                    spec,
                    plan,
                    !cleanup_failed,
                    cleanup_failed.then(|| "unit-cleanup-unconfirmed".to_owned()),
                )?;
                return Err(AdapterJobError::WaitSystemdRun {
                    source: error,
                    cleanup_failed,
                });
            }
        }
        if cancellation.is_cancelled() {
            let intent_result = crate::unix_time_ms()
                .map_err(AdapterJobError::Clock)
                .and_then(|recorded_at_ms| {
                    materialize_termination_intent(
                        job.job_directory(),
                        job.required_uid,
                        ExecutionTerminationKindV1::Cancelled,
                        recorded_at_ms,
                    )
                    .map_err(AdapterJobError::from)
                });
            let cleanup_failed = cleanup_failed_child(&mut child, plan.unit_name());
            let receipt_result = finalize_execution_receipts(
                job,
                spec,
                plan,
                !cleanup_failed,
                cleanup_failed.then(|| "unit-cleanup-unconfirmed".to_owned()),
            );
            intent_result?;
            receipt_result?;
            return Err(AdapterJobError::ExecutionCancelled { cleanup_failed });
        }
        if Instant::now() >= deadline {
            let intent_result = crate::unix_time_ms()
                .map_err(AdapterJobError::Clock)
                .and_then(|recorded_at_ms| {
                    materialize_termination_intent(
                        job.job_directory(),
                        job.required_uid,
                        ExecutionTerminationKindV1::DeadlineExceeded,
                        recorded_at_ms,
                    )
                    .map_err(AdapterJobError::from)
                });
            let cleanup_failed = cleanup_failed_child(&mut child, plan.unit_name());
            let receipt_result = finalize_execution_receipts(
                job,
                spec,
                plan,
                !cleanup_failed,
                cleanup_failed.then(|| "unit-cleanup-unconfirmed".to_owned()),
            );
            intent_result?;
            receipt_result?;
            return Err(AdapterJobError::DeadlineExceeded { cleanup_failed });
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn finalize_execution_receipts(
    job: &PreparedAdapterJobV1,
    spec: &AuthorizedPhaseSpecV1,
    plan: &TransientAdapterUnitPlanV1,
    unit_collected: bool,
    error_code: Option<String>,
) -> Result<AdapterExecutionOutputV1, AdapterJobError> {
    let terminal_receipt =
        read_terminal_receipt(job.job_directory(), job.required_uid, spec, job.sequence)?;
    let cleanup_receipt = materialize_cleanup_receipt(
        job.job_directory(),
        job.required_uid,
        &terminal_receipt,
        unit_collected,
        error_code,
        crate::unix_time_ms().map_err(AdapterJobError::Clock)?,
    )?;
    Ok(AdapterExecutionOutputV1 {
        unit_name: plan.unit_name().to_owned(),
        terminal_receipt,
        cleanup_receipt,
    })
}

fn cleanup_failed_child(child: &mut Child, unit_name: &str) -> bool {
    let cleanup_failed = terminate_transient_unit(unit_name).is_err();
    terminate_child(child);
    cleanup_failed
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn terminate_transient_unit(unit_name: &str) -> Result<(), AdapterJobError> {
    let kill_status =
        run_systemctl_bounded(&["kill", "--kill-who=all", "--signal=KILL", unit_name])?;
    let stop_status = run_systemctl_bounded(&["stop", unit_name])?;
    if kill_status.success() && stop_status.success() {
        Ok(())
    } else {
        Err(AdapterJobError::UnitTerminationFailed)
    }
}

fn run_systemctl_bounded(arguments: &[&str]) -> Result<ExitStatus, AdapterJobError> {
    let mut child = Command::new(SYSTEMCTL_EXECUTABLE)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(AdapterJobError::TerminateUnit)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().map_err(AdapterJobError::TerminateUnit)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AdapterJobError::UnitTerminationDeadlineExceeded);
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

fn validate_installed_executable(path: &'static str) -> Result<(), AdapterJobError> {
    let path = Path::new(path);
    let path_metadata = fs::symlink_metadata(path).map_err(AdapterJobError::InspectExecutable)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != 0
        || path_metadata.mode() & 0o022 != 0
        || path_metadata.mode() & 0o111 == 0
    {
        return Err(AdapterJobError::UnsafeInstalledExecutable);
    }
    let executable = File::open(path).map_err(AdapterJobError::InspectExecutable)?;
    let opened_metadata = executable
        .metadata()
        .map_err(AdapterJobError::InspectExecutable)?;
    let final_metadata = fs::symlink_metadata(path).map_err(AdapterJobError::InspectExecutable)?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.file_type().is_file()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(AdapterJobError::UnsafeInstalledExecutable);
    }
    Ok(())
}

fn ensure_job_root(path: &Path, required_uid: u32) -> Result<(), AdapterJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, required_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(AdapterJobError::UnsafeJobRoot)?;
            validate_parent_directory(parent, required_uid)?;
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(AdapterJobError::Io(error)),
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_private_directory(path, required_uid)?;
            sync_directory(parent, required_uid)
        }
        Err(error) => Err(AdapterJobError::Io(error)),
    }
}

fn ensure_private_directory(path: &Path, required_uid: u32) -> Result<(), AdapterJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, required_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(AdapterJobError::UnsafeJobRoot)?;
            validate_private_directory(parent, required_uid)?;
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(AdapterJobError::Io(error)),
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_private_directory(path, required_uid)?;
            sync_directory(parent, required_uid)
        }
        Err(error) => Err(AdapterJobError::Io(error)),
    }
}

fn validate_parent_directory(path: &Path, required_uid: u32) -> Result<(), AdapterJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o022 != 0 {
        return Err(AdapterJobError::UnsafeJobRoot);
    }
    Ok(())
}

fn validate_private_directory(path: &Path, required_uid: u32) -> Result<(), AdapterJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o077 != 0 {
        return Err(AdapterJobError::UnsafeJobRoot);
    }
    Ok(())
}

fn stable_directory_metadata(path: &Path) -> Result<fs::Metadata, AdapterJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_dir() {
        return Err(AdapterJobError::UnsafeJobRoot);
    }
    let directory = File::open(path)?;
    let opened_metadata = directory.metadata()?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.is_dir()
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    Ok(final_metadata)
}

fn materialize_or_verify_request(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
) -> Result<(), AdapterJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_existing_request(path, required_uid, expected_bytes, spec, sequence),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(expected_bytes)?;
                    file.sync_all()?;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    verify_existing_request(path, required_uid, expected_bytes, spec, sequence)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_existing_request(path, required_uid, expected_bytes, spec, sequence)
                }
                Err(error) => Err(AdapterJobError::Io(error)),
            }
        }
        Err(error) => Err(AdapterJobError::Io(error)),
    }
}

fn materialize_or_verify_spec(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    expected_spec: &AuthorizedPhaseSpecV1,
) -> Result<(), AdapterJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_existing_spec(path, required_uid, expected_bytes, expected_spec),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(expected_bytes)?;
                    file.sync_all()?;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    verify_existing_spec(path, required_uid, expected_bytes, expected_spec)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_existing_spec(path, required_uid, expected_bytes, expected_spec)
                }
                Err(error) => Err(AdapterJobError::Io(error)),
            }
        }
        Err(error) => Err(AdapterJobError::Io(error)),
    }
}

fn materialize_or_verify_operation_identity(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    expected_identity: &AdapterOperationIdentityV1,
    spec: &AuthorizedPhaseSpecV1,
    request: &FixedAdapterRequestV1,
) -> Result<(), AdapterJobError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_existing_operation_identity(
            path,
            required_uid,
            expected_bytes,
            expected_identity,
            spec,
            request,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(expected_bytes)?;
                    file.sync_all()?;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    verify_existing_operation_identity(
                        path,
                        required_uid,
                        expected_bytes,
                        expected_identity,
                        spec,
                        request,
                    )
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_existing_operation_identity(
                        path,
                        required_uid,
                        expected_bytes,
                        expected_identity,
                        spec,
                        request,
                    )
                }
                Err(error) => Err(AdapterJobError::Io(error)),
            }
        }
        Err(error) => Err(AdapterJobError::Io(error)),
    }
}

fn verify_existing_operation_identity(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    expected_identity: &AdapterOperationIdentityV1,
    spec: &AuthorizedPhaseSpecV1,
    request: &FixedAdapterRequestV1,
) -> Result<(), AdapterJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_EXISTING_REQUEST_BYTES
    {
        return Err(AdapterJobError::UnsafeRequestDocument);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_EXISTING_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    if bytes != expected_bytes {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    let decoded = AdapterOperationIdentityV1::decode_authorized(&bytes, spec, request)?;
    if decoded != *expected_identity {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    Ok(())
}

fn verify_existing_spec(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    expected_spec: &AuthorizedPhaseSpecV1,
) -> Result<(), AdapterJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_EXISTING_REQUEST_BYTES
    {
        return Err(AdapterJobError::UnsafeRequestDocument);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    file.sync_all()?;
    sync_directory(
        path.parent().ok_or(AdapterJobError::UnsafeJobPath)?,
        required_uid,
    )?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_EXISTING_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    if bytes != expected_bytes {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    let decoded = AuthorizedPhaseSpecV1::decode_canonical(&bytes)?;
    if decoded != *expected_spec {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    Ok(())
}

fn verify_existing_request(
    path: &Path,
    required_uid: u32,
    expected_bytes: &[u8],
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
) -> Result<(), AdapterJobError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_EXISTING_REQUEST_BYTES
    {
        return Err(AdapterJobError::UnsafeRequestDocument);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    file.sync_all()?;
    sync_directory(
        path.parent().ok_or(AdapterJobError::UnsafeJobPath)?,
        required_uid,
    )?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_EXISTING_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes != expected_bytes {
        return Err(AdapterJobError::RequestDocumentConflict);
    }
    FixedAdapterRequestV1::decode_authorized(&bytes, spec, sequence)?;
    Ok(())
}

fn inspect_existing_result(
    path: &Path,
    required_uid: u32,
) -> Result<PreparedAdapterJobStateV1, AdapterJobError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(PreparedAdapterJobStateV1::ReadyToExecute)
        }
        Err(error) => Err(AdapterJobError::Io(error)),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && metadata.uid() == required_uid
                && metadata.mode().trailing_zeros() >= 6
                && metadata.len() > 0
                && metadata.len() <= MAX_EXISTING_RESULT_BYTES =>
        {
            Ok(PreparedAdapterJobStateV1::ResultRequiresReconciliation)
        }
        Ok(_) => Err(AdapterJobError::UnsafeResultDocument),
    }
}

fn read_existing_result(
    path: &Path,
    required_uid: u32,
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
    prior_results: &[FixedAdapterResultV1],
) -> Result<FixedAdapterResultV1, AdapterJobError> {
    if inspect_existing_result(path, required_uid)?
        != PreparedAdapterJobStateV1::ResultRequiresReconciliation
    {
        return Err(AdapterJobError::MissingResultDocument);
    }
    let path_metadata = fs::symlink_metadata(path)?;
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    file.sync_all()?;
    sync_directory(
        path.parent().ok_or(AdapterJobError::UnsafeJobPath)?,
        required_uid,
    )?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(u64::try_from(MAX_FIXED_ADAPTER_RESULT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(AdapterJobError::JobPathChanged);
    }
    Ok(FixedAdapterResultV1::decode_authorized(
        &bytes,
        spec,
        sequence,
        prior_results,
    )?)
}

fn sync_directory(path: &Path, required_uid: u32) -> Result<(), AdapterJobError> {
    validate_parent_or_private_directory(path, required_uid)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn validate_parent_or_private_directory(
    path: &Path,
    required_uid: u32,
) -> Result<(), AdapterJobError> {
    let metadata = stable_directory_metadata(path)?;
    if metadata.uid() != required_uid || metadata.mode() & 0o022 != 0 {
        return Err(AdapterJobError::UnsafeJobRoot);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterJobError {
    #[error("fixed adapter authorization is invalid: {0}")]
    Phase6(#[from] Phase6ContractError),
    #[error(transparent)]
    Identity(#[from] AdapterIdentityError),
    #[error("fixed adapter job filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("fixed adapter job root or directory is not owner-only and stable")]
    UnsafeJobRoot,
    #[error("fixed adapter job path changed during validation")]
    JobPathChanged,
    #[error("fixed adapter request document is not a safe owner-only regular file")]
    UnsafeRequestDocument,
    #[error("fixed adapter request document conflicts with the authorized replay")]
    RequestDocumentConflict,
    #[error("fixed adapter result document is not a safe bounded owner-only regular file")]
    UnsafeResultDocument,
    #[error("an existing fixed adapter result must be reconciled before execution")]
    ResultRequiresReconciliation,
    #[error("fixed adapter execution evidence already exists and requires reconciliation")]
    ExecutionRequiresReconciliation,
    #[error("fixed adapter command definition violates the no-shell, clear-environment contract")]
    UnsafeCommandDefinition,
    #[error("fixed adapter job path cannot be represented as a safe systemd bind source")]
    UnsafeJobPath,
    #[error("fixed adapter execution is restricted to the root-owned production job namespace")]
    UnsafeExecutionIdentity,
    #[error("an installed fixed executable could not be inspected: {0}")]
    InspectExecutable(io::Error),
    #[error("an installed fixed executable is not a stable root-owned executable file")]
    UnsafeInstalledExecutable,
    #[error("systemd-run could not be started: {0}")]
    SpawnSystemdRun(io::Error),
    #[error("the host clock could not provide execution receipt time: {0}")]
    Clock(std::time::SystemTimeError),
    #[error(transparent)]
    ExecutionReceipt(#[from] ExecutionReceiptRuntimeError),
    #[error("systemd-run could not be waited (cleanup_failed={cleanup_failed}): {source}")]
    WaitSystemdRun {
        source: io::Error,
        cleanup_failed: bool,
    },
    #[error("fixed adapter transient unit exceeded its deadline (cleanup_failed={cleanup_failed})")]
    DeadlineExceeded { cleanup_failed: bool },
    #[error("fixed adapter execution was cancelled (cleanup_failed={cleanup_failed})")]
    ExecutionCancelled { cleanup_failed: bool },
    #[error("fixed adapter transient unit failed with {status}")]
    UnitFailed {
        status: ExitStatus,
        output: Box<AdapterExecutionOutputV1>,
    },
    #[error("fixed adapter transient unit did not write a bounded owner-only result document")]
    MissingResultDocument,
    #[error("fixed adapter step {0} has no safe completed prior result document")]
    MissingPriorResultDocument(u16),
    #[error("fixed adapter prior-result files do not match the validated in-memory chain")]
    PriorResultFilesystemMismatch,
    #[error(transparent)]
    Result(#[from] AdapterResultContractError),
    #[error("systemctl could not terminate the timed-out transient unit: {0}")]
    TerminateUnit(io::Error),
    #[error("systemctl did not confirm transient-unit termination")]
    UnitTerminationFailed,
    #[error("systemctl did not finish transient-unit termination within five seconds")]
    UnitTerminationDeadlineExceeded,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_identity::AdapterOperationIdentityV1,
        adapter_result::{FixedAdapterEvidenceV1, PhaseObservationEvidenceV1},
        domain::PhaseArtifacts,
        phase6::tests::{
            test_base_backup_phase_spec, test_bootstrap_phase_spec, test_health_phase_spec,
            test_migration_phase_spec,
        },
        store::{FenceJournalState, FenceLease},
    };

    #[test]
    fn adapter_execution_cancellation_is_shared_across_clones() {
        let cancellation = AdapterExecutionCancellationV1::default();
        let clone = cancellation.clone();
        assert!(!cancellation.is_cancelled());
        clone.cancel();
        assert!(cancellation.is_cancelled());
    }

    fn path_uid(path: &Path) -> u32 {
        fs::metadata(path)
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid()
    }

    fn readiness_result(
        spec: &AuthorizedPhaseSpecV1,
        completed_at_ms: i64,
        label: &str,
    ) -> FixedAdapterResultV1 {
        let artifacts = spec
            .bind_artifacts(PhaseArtifacts {
                health_evidence_digest: Some(EvidenceDigest::sha256(format!("{label} artifacts"))),
                ..PhaseArtifacts::default()
            })
            .unwrap_or_else(|error| panic!("readiness artifacts: {error}"));
        FixedAdapterResultV1::new(
            spec,
            1,
            FixedAdapterEvidenceV1::ReadinessEvidence(
                PhaseObservationEvidenceV1::new(
                    completed_at_ms,
                    EvidenceDigest::sha256(format!("{label} observation")),
                    artifacts,
                )
                .unwrap_or_else(|error| panic!("readiness evidence: {error}")),
            ),
            &[],
        )
        .unwrap_or_else(|error| panic!("readiness result: {error}"))
    }

    fn assert_materialized_spec(prepared: &PreparedAdapterJobV1, spec: &AuthorizedPhaseSpecV1) {
        assert_eq!(
            fs::metadata(prepared.spec_path())
                .unwrap_or_else(|error| panic!("spec metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let bytes =
            fs::read(prepared.spec_path()).unwrap_or_else(|error| panic!("read spec: {error}"));
        assert_eq!(
            AuthorizedPhaseSpecV1::decode_canonical(&bytes)
                .unwrap_or_else(|error| panic!("decode spec: {error}")),
            *spec
        );
    }

    fn assert_receipt_capture_plan(unit: &TransientAdapterUnitPlanV1) {
        assert!(unit.arguments().contains(&format!(
            "--property=ExecStopPost={INSTALLED_ADAPTER_RECEIPT_EXECUTABLE}"
        )));
        assert_eq!(
            unit.arguments()
                .iter()
                .filter(|argument| argument.starts_with("--property=ExecStopPost="))
                .count(),
            1
        );
    }

    #[test]
    fn materializes_exact_owner_only_request_and_replays_it() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_bootstrap_phase_spec();
        let uid = path_uid(temp.path());

        let prepared = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("prepare adapter job: {error}"));
        assert_eq!(prepared.state(), PreparedAdapterJobStateV1::ReadyToExecute);
        assert_eq!(
            prepared.profile(),
            FixedAdapterProfileV1::KamalBootstrapDeploy
        );
        assert_eq!(
            prepared
                .execution_command()
                .unwrap_or_else(|error| panic!("execution command: {error}"))
                .working_directory,
            "/job"
        );
        assert_eq!(prepared.timeout_ms(), 300_000);
        let unit = prepared
            .transient_unit_plan()
            .unwrap_or_else(|error| panic!("transient unit plan: {error}"));
        assert_eq!(unit.executable(), SYSTEMD_RUN_EXECUTABLE);
        assert_eq!(unit.outer_deadline(), Duration::from_secs(315));
        assert!(unit.arguments().contains(&format!(
            "--property=LoadCredential={KAMAL_SECRETS_CREDENTIAL_NAME}:{PROJECT_CREDENTIAL_ROOT}/adapter-test/kamal-secrets.env"
        )));
        assert!(unit.arguments().contains(&format!(
            "--property=LoadCredential={KAMAL_SSH_KEY_CREDENTIAL_NAME}:{PROJECT_CREDENTIAL_ROOT}/adapter-test/kamal-ssh-key"
        )));
        assert!(!unit.arguments().iter().any(|argument| {
            argument.contains(KAMAL_SECRETS_CREDENTIAL_SOURCE)
                || argument.contains(KAMAL_SSH_KEY_CREDENTIAL_SOURCE)
        }));
        assert!(
            unit.arguments()
                .contains(&"--property=RuntimeMaxSec=300000ms".to_owned())
        );
        assert!(unit.arguments().iter().any(|argument| {
            argument
                == &format!(
                    "--property=BindPaths={}:/job",
                    prepared.job_directory().display()
                )
        }));
        let separator = unit
            .arguments()
            .iter()
            .position(|argument| argument == "--")
            .unwrap_or_else(|| panic!("systemd-run argument separator"));
        assert_eq!(
            &unit.arguments()[separator + 1..separator + 4],
            [
                ENV_EXECUTABLE,
                "-i",
                "/usr/libexec/rdashboard/kamal-adapter"
            ]
        );
        assert!(
            unit.arguments()[separator + 4..]
                .iter()
                .all(|argument| !argument.contains("sh -c"))
        );
        assert!(
            unit.arguments()
                .contains(&"--property=TemporaryFileSystem=/inputs:ro".to_owned())
        );
        assert!(
            unit.arguments()
                .contains(&"--property=StandardOutput=null".to_owned())
        );
        assert!(
            unit.arguments()
                .contains(&"--property=StandardError=null".to_owned())
        );
        assert_receipt_capture_plan(&unit);
        assert!(!unit.arguments().contains(&"--pipe".to_owned()));
        assert!(
            unit.arguments()
                .windows(2)
                .any(|arguments| { arguments == ["--inputs".to_owned(), "/inputs".to_owned()] })
        );
        assert_eq!(
            fs::metadata(prepared.request_path())
                .unwrap_or_else(|error| panic!("request metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_materialized_spec(&prepared, &spec);
        let request_bytes = fs::read(prepared.request_path())
            .unwrap_or_else(|error| panic!("read request: {error}"));
        FixedAdapterRequestV1::decode_authorized(&request_bytes, &spec, 1)
            .unwrap_or_else(|error| panic!("decode request: {error}"));

        let replayed = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("replay adapter job: {error}"));
        assert_eq!(replayed, prepared);
    }

    #[test]
    fn kamal_credentials_preserve_rimg_and_scope_other_projects() {
        let rimg = "rimg"
            .parse::<ProjectId>()
            .unwrap_or_else(|error| panic!("rimg project id: {error}"));
        assert_eq!(
            kamal_credential_sources(&rimg),
            (
                KAMAL_SECRETS_CREDENTIAL_SOURCE.to_owned(),
                KAMAL_SSH_KEY_CREDENTIAL_SOURCE.to_owned(),
            )
        );
        let gateway = "telegram-gateway"
            .parse::<ProjectId>()
            .unwrap_or_else(|error| panic!("gateway project id: {error}"));
        assert_eq!(
            kamal_credential_sources(&gateway),
            (
                format!("{PROJECT_CREDENTIAL_ROOT}/telegram-gateway/kamal-secrets.env"),
                format!("{PROJECT_CREDENTIAL_ROOT}/telegram-gateway/kamal-ssh-key"),
            )
        );
    }

    #[test]
    fn rejects_request_conflict_and_requires_result_reconciliation() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_bootstrap_phase_spec();
        let uid = path_uid(temp.path());
        let prepared = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("prepare adapter job: {error}"));

        fs::write(prepared.request_path(), b"{}").unwrap_or_else(|error| panic!("tamper: {error}"));
        assert!(matches!(
            PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1),
            Err(AdapterJobError::RequestDocumentConflict)
        ));

        let spec_conflict = test_bootstrap_phase_spec();
        let spec_job = PreparedAdapterJobV1::prepare_in(&root, uid, &spec_conflict, 1)
            .unwrap_or_else(|error| panic!("spec conflict job: {error}"));
        fs::write(spec_job.spec_path(), b"{}")
            .unwrap_or_else(|error| panic!("tamper spec: {error}"));
        assert!(matches!(
            PreparedAdapterJobV1::prepare_in(&root, uid, &spec_conflict, 1),
            Err(AdapterJobError::RequestDocumentConflict)
        ));

        let result_spec = test_bootstrap_phase_spec();
        let result_job = PreparedAdapterJobV1::prepare_in(&root, uid, &result_spec, 1)
            .unwrap_or_else(|error| panic!("result job: {error}"));
        let artifacts = result_spec
            .bind_artifacts(result_spec.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bind artifacts: {error}"));
        let result = FixedAdapterResultV1::new(
            &result_spec,
            1,
            FixedAdapterEvidenceV1::DeploymentEvidence(
                PhaseObservationEvidenceV1::new(
                    900,
                    EvidenceDigest::sha256("deployment observation"),
                    artifacts,
                )
                .unwrap_or_else(|error| panic!("evidence: {error}")),
            ),
            &[],
        )
        .unwrap_or_else(|error| panic!("result: {error}"));
        fs::write(
            result_job.result_path(),
            result
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("result bytes: {error}")),
        )
        .unwrap_or_else(|error| panic!("write result: {error}"));
        fs::set_permissions(result_job.result_path(), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("result permissions: {error}"));
        let reconcile = PreparedAdapterJobV1::prepare_in(&root, uid, &result_spec, 1)
            .unwrap_or_else(|error| panic!("reconcile adapter job: {error}"));
        assert_eq!(
            reconcile.state(),
            PreparedAdapterJobStateV1::ResultRequiresReconciliation
        );
        assert_eq!(
            reconcile
                .reconcile_result(&result_spec, &[])
                .unwrap_or_else(|error| panic!("reconcile result: {error}")),
            result
        );
        assert_eq!(
            result_job
                .reconcile_result(&result_spec, &[])
                .unwrap_or_else(|error| panic!("reconcile freshly written result: {error}")),
            result
        );
        assert!(matches!(
            reconcile.execution_command(),
            Err(AdapterJobError::ResultRequiresReconciliation)
        ));
    }

    #[test]
    fn durable_start_without_result_is_never_reexecuted_ambiguously() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_bootstrap_phase_spec();
        let uid = path_uid(temp.path());
        let prepared = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("prepare adapter job: {error}"));
        let request = spec
            .fixed_adapter_request(1)
            .unwrap_or_else(|error| panic!("request: {error}"));
        materialize_execution_start(prepared.job_directory(), uid, &request, 100)
            .unwrap_or_else(|error| panic!("start: {error}"));

        let replayed = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("replay adapter job: {error}"));
        assert_eq!(
            replayed.state(),
            PreparedAdapterJobStateV1::ExecutionRequiresReconciliation
        );
        assert!(matches!(
            replayed.execution_command(),
            Err(AdapterJobError::ResultRequiresReconciliation)
        ));
    }

    #[test]
    fn later_steps_mount_only_completed_prior_jobs_read_only() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_bootstrap_phase_spec();
        let uid = path_uid(temp.path());
        let prepared = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("prepare adapter job: {error}"));
        let spec_directory = prepared
            .job_directory()
            .parent()
            .unwrap_or_else(|| panic!("spec directory"));
        fs::write(prepared.result_path(), b"completed")
            .unwrap_or_else(|error| panic!("prior result: {error}"));
        fs::set_permissions(prepared.result_path(), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("prior result permissions: {error}"));
        let second_directory = spec_directory.join("step-00002");
        fs::create_dir(&second_directory)
            .unwrap_or_else(|error| panic!("second directory: {error}"));
        fs::set_permissions(&second_directory, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("second directory permissions: {error}"));
        let mut second = prepared.clone();
        second.sequence = 2;
        second.job_directory = second_directory.clone();
        second.request_path = second_directory.join(REQUEST_FILE_NAME);
        second.result_path = second_directory.join(RESULT_FILE_NAME);
        second.state = PreparedAdapterJobStateV1::ReadyToExecute;

        let plan = second
            .transient_unit_plan()
            .unwrap_or_else(|error| panic!("second plan: {error}"));
        assert!(plan.arguments().contains(&format!(
            "--property=BindReadOnlyPaths={}:/inputs/step-00001",
            prepared.job_directory().display()
        )));
        assert!(!plan.arguments().iter().any(|argument| {
            argument.starts_with("--property=BindReadOnlyPaths=") && argument.contains("step-00002")
        }));
    }

    #[test]
    fn prior_result_files_must_equal_the_validated_chain() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_health_phase_spec();
        let uid = path_uid(temp.path());
        let first = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("first job: {error}"));
        let stored = readiness_result(&spec, 100, "stored");
        fs::write(
            first.result_path(),
            stored
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("stored result: {error}")),
        )
        .unwrap_or_else(|error| panic!("write stored result: {error}"));
        fs::set_permissions(first.result_path(), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("stored result permissions: {error}"));
        let second = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 2)
            .unwrap_or_else(|error| panic!("second job: {error}"));

        validate_prior_result_files(&second, &spec, std::slice::from_ref(&stored))
            .unwrap_or_else(|error| panic!("matching prior file: {error}"));
        let substituted = readiness_result(&spec, 101, "substituted");
        assert!(matches!(
            validate_prior_result_files(&second, &spec, &[substituted]),
            Err(AdapterJobError::PriorResultFilesystemMismatch)
        ));
    }

    #[test]
    fn materializes_exact_owner_only_operation_identity_without_putting_secret_in_argv() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_migration_phase_spec();
        let uid = path_uid(temp.path());
        let inspection = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 1)
            .unwrap_or_else(|error| panic!("prepare schema inspection: {error}"));
        fs::write(inspection.result_path(), b"completed")
            .unwrap_or_else(|error| panic!("schema inspection result: {error}"));
        fs::set_permissions(inspection.result_path(), fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("schema inspection result permissions: {error}"));
        let prepared = PreparedAdapterJobV1::prepare_in(&root, uid, &spec, 2)
            .unwrap_or_else(|error| panic!("prepare adapter job: {error}"));
        let lease = FenceLease {
            journal_id: 11,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: spec.fencing_epoch.unwrap_or(0),
            token: uuid::Uuid::new_v4(),
            created_at_ms: 1_000,
            state: FenceJournalState::Held,
            release_safe_receipt_digest: None,
        };
        let identity = AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease)
            .unwrap_or_else(|error| panic!("identity: {error}"));

        prepared
            .materialize_operation_identity(&spec, &identity)
            .unwrap_or_else(|error| panic!("materialize identity: {error}"));
        prepared
            .materialize_operation_identity(&spec, &identity)
            .unwrap_or_else(|error| panic!("replay identity: {error}"));
        assert_eq!(
            fs::metadata(prepared.operation_identity_path())
                .unwrap_or_else(|error| panic!("identity metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let bytes = fs::read(prepared.operation_identity_path())
            .unwrap_or_else(|error| panic!("read identity: {error}"));
        let request = spec
            .fixed_adapter_request(2)
            .unwrap_or_else(|error| panic!("request: {error}"));
        assert_eq!(
            AdapterOperationIdentityV1::decode_authorized(&bytes, &spec, &request)
                .unwrap_or_else(|error| panic!("decode identity: {error}")),
            identity
        );
        let unit = prepared
            .transient_unit_plan()
            .unwrap_or_else(|error| panic!("transient unit: {error}"));
        assert!(unit.arguments().windows(2).any(|arguments| {
            arguments
                == [
                    "--identity".to_owned(),
                    "/job/operation-identity.jcs".to_owned(),
                ]
        }));
        assert!(
            unit.arguments()
                .contains(&"--property=ReadWritePaths=/var/lib/rimg/data".to_owned())
        );
        assert!(
            !unit
                .arguments()
                .iter()
                .any(|argument| argument.contains(&lease.token.to_string()))
        );

        let mut substituted_lease = lease.clone();
        substituted_lease.token = uuid::Uuid::new_v4();
        let substituted =
            AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &substituted_lease)
                .unwrap_or_else(|error| panic!("substituted identity: {error}"));
        assert!(matches!(
            prepared.materialize_operation_identity(&spec, &substituted),
            Err(AdapterJobError::RequestDocumentConflict)
        ));
    }

    #[test]
    fn backup_profiles_have_only_their_required_mutable_host_roots() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temp.path().join("adapter-jobs");
        let spec = test_base_backup_phase_spec();
        let prepared = PreparedAdapterJobV1::prepare_in(&root, path_uid(temp.path()), &spec, 1)
            .unwrap_or_else(|error| panic!("prepare backup capture: {error}"));
        let arguments = prepared
            .transient_unit_plan()
            .unwrap_or_else(|error| panic!("backup transient unit: {error}"))
            .arguments()
            .to_vec();
        for path in [
            "/var/lib/rimg/data",
            "/var/lib/rdashboard-executor/backups",
            "/var/lib/rdashboard-executor/locks",
        ] {
            assert!(
                arguments.contains(&format!("--property=ReadWritePaths={path}")),
                "missing writable path {path}"
            );
        }
        assert!(!arguments.iter().any(|argument| {
            argument.starts_with("--property=ReadWritePaths=")
                && !matches!(
                    argument.as_str(),
                    "--property=ReadWritePaths=/job"
                        | "--property=ReadWritePaths=/var/lib/rimg/data"
                        | "--property=ReadWritePaths=/var/lib/rdashboard-executor/backups"
                        | "--property=ReadWritePaths=/var/lib/rdashboard-executor/locks"
                )
        }));

        let encrypt = PreparedAdapterJobV1::prepare_in(&root, path_uid(temp.path()), &spec, 2)
            .unwrap_or_else(|error| panic!("prepare backup encryption: {error}"));
        assert_eq!(
            fixed_write_paths(encrypt.profile()),
            &["/var/lib/rdashboard-executor/backups"]
        );
        assert_eq!(
            fixed_adapter_unit_name(&spec, 2)
                .unwrap_or_else(|error| panic!("fixed unit name: {error}")),
            adapter_unit_identity(&encrypt)
                .unwrap_or_else(|error| panic!("unit identity: {error}"))
                .0
        );
        assert!(drive_credentials_required(
            FixedAdapterProfileV1::BackupUploadGoogleDrive
        ));
        assert!(drive_credentials_required(
            FixedAdapterProfileV1::BackupReadbackVerify
        ));
        assert!(!drive_credentials_required(
            FixedAdapterProfileV1::BackupEncryptAge
        ));
        assert!(kamal_credentials_required(
            FixedAdapterProfileV1::KamalBootstrapDeploy
        ));
        assert!(kamal_credentials_required(
            FixedAdapterProfileV1::KamalCodeRollback
        ));
        let load_credential = format!(
            "--property=LoadCredential={DRIVE_SERVICE_ACCOUNT_CREDENTIAL_NAME}:{DRIVE_SERVICE_ACCOUNT_CREDENTIAL_SOURCE}"
        );
        let upload_arguments = transient_unit_arguments(
            &PreparedAdapterJobV1 {
                profile: FixedAdapterProfileV1::BackupUploadGoogleDrive,
                ..encrypt.clone()
            },
            FixedAdapterProfileV1::BackupUploadGoogleDrive.command(),
            "rdashboard-adapter-test",
            encrypt
                .job_directory()
                .to_str()
                .unwrap_or_else(|| panic!("test job path is not UTF-8")),
            &[],
        );
        assert!(upload_arguments.contains(&load_credential));
        assert!(
            upload_arguments
                .contains(&"--property=InaccessiblePaths=/etc/rdashboard/credentials".to_owned())
        );
    }
}
