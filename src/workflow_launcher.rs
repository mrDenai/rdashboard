use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::ExitStatusExt as _,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    thread,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        EvidenceDigest, ProjectId, WorkflowAdapterIdV1, WorkflowArtifactKindV1, WorkflowLeaseV1,
        WorkflowNetworkClassV1, WorkflowWorkerPoolV1, valid_workflow_identity,
    },
    operation_state::{
        WORKFLOW_OPERATION_STATE_ROOT, WorkflowOperationStateError,
        WorkflowOperationStateManagerV1, WorkflowOperationStateOutcomeV1,
        WorkflowOperationStateReleaseV1,
    },
    preparation::{
        PREPARATION_STORE_ROOT, PreparationObjectKindV1, PreparationStoreError,
        PreparationStoreReaderV1,
    },
    rootless_oci::RootlessOciRuntimePolicyV1,
    workflow_execution_grant::{
        VerifiedWorkflowExecutionGrantV1, WorkflowExecutionGrantError,
        WorkflowExecutionGrantVerificationKeyV1, WorkflowExecutionGrantVerifierV1,
    },
};

pub const WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_LAUNCHER_POLICY_PATH: &str = "/etc/rdashboard/workflow-launcher.jcs";
pub const WORKFLOW_LAUNCHER_JOB_ROOT: &str = "/var/lib/rdashboard-workflow-launcher/jobs";
pub const WORKFLOW_JOB_EXECUTABLE: &str = "/usr/libexec/rdashboard/rdashboard-workflow-job";
pub const SYSTEMD_RUN_EXECUTABLE: &str = "/usr/bin/systemd-run";

const ENV_EXECUTABLE: &str = "/usr/bin/env";
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const ED25519_KEY_BYTES: usize = 32;
const MAX_KEYS: usize = 8;
const MAX_CONCURRENT_JOBS: u16 = 32;
const MAX_JOURNAL_RECORDS: u32 = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLauncherVerificationKeyConfigV1 {
    pub key_id: String,
    pub key_epoch: u64,
    pub public_key_base64url: String,
    pub active_from_ms: i64,
    pub signing_retired_at_ms: Option<i64>,
    pub verify_until_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLauncherPolicyV1 {
    pub schema_version: u16,
    pub worker_uid: u32,
    pub build_uid: u32,
    pub build_gid: u32,
    pub worker_id: String,
    pub host_id: String,
    pub grant_issuer: String,
    pub launcher_audience: String,
    pub minimum_grant_key_epoch: u64,
    pub grant_verification_keys: Vec<WorkflowLauncherVerificationKeyConfigV1>,
    pub allowed_adapters: Vec<WorkflowAdapterIdV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootless_oci: Option<RootlessOciRuntimePolicyV1>,
    pub max_concurrent_jobs: u16,
    pub max_journal_records: u32,
}

impl WorkflowLauncherPolicyV1 {
    pub fn load_root_owned() -> Result<Self, WorkflowLauncherError> {
        Self::load_from_path(Path::new(WORKFLOW_LAUNCHER_POLICY_PATH), 0)
    }

    pub(crate) fn load_from_path(
        path: &Path,
        required_uid: u32,
    ) -> Result<Self, WorkflowLauncherError> {
        let path_metadata = fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || path_metadata.uid() != required_uid
            || path_metadata.mode() & 0o7777 != 0o600
            || path_metadata.nlink() != 1
            || path_metadata.len() == 0
            || path_metadata.len() > MAX_POLICY_BYTES
        {
            return Err(WorkflowLauncherError::UnsafePolicy);
        }
        let file = File::open(path)?;
        let opened = file.metadata()?;
        if !same_file(&path_metadata, &opened) {
            return Err(WorkflowLauncherError::PolicyChanged);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
        file.take(MAX_POLICY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        let final_metadata = fs::symlink_metadata(path)?;
        if !same_file(&opened, &final_metadata)
            || bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
        {
            return Err(WorkflowLauncherError::PolicyChanged);
        }
        Self::decode_canonical(&bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowLauncherError> {
        let policy: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&policy)? != bytes {
            return Err(WorkflowLauncherError::NoncanonicalPolicy);
        }
        policy.validate()?;
        Ok(policy)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowLauncherError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn validate(&self) -> Result<(), WorkflowLauncherError> {
        if self.schema_version != WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION {
            return Err(WorkflowLauncherError::UnsupportedPolicyVersion(
                self.schema_version,
            ));
        }
        if self.worker_uid == 0
            || self.worker_uid == u32::MAX
            || self.build_uid == 0
            || self.build_uid == u32::MAX
            || self.build_gid == 0
            || self.build_gid == u32::MAX
            || self.worker_uid == self.build_uid
            || !valid_workflow_identity(&self.worker_id)
            || !valid_workflow_identity(&self.host_id)
            || !(1..=MAX_KEYS).contains(&self.grant_verification_keys.len())
            || self.allowed_adapters.is_empty()
            || self.allowed_adapters.len() > 3
            || !self
                .allowed_adapters
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self.allowed_adapters.iter().any(|adapter| {
                !matches!(
                    adapter,
                    WorkflowAdapterIdV1::WorkerBareBinCiV1
                        | WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
                        | WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
                )
            })
            || self
                .allowed_adapters
                .contains(&WorkflowAdapterIdV1::WorkerOciReleaseBuildV1)
                != self.rootless_oci.is_some()
            || self
                .rootless_oci
                .as_ref()
                .is_some_and(|policy| policy.validate(self.worker_uid, self.build_uid).is_err())
            || !(1..=MAX_CONCURRENT_JOBS).contains(&self.max_concurrent_jobs)
            || self.max_journal_records == 0
            || self.max_journal_records > MAX_JOURNAL_RECORDS
            || u32::from(self.max_concurrent_jobs) > self.max_journal_records
        {
            return Err(WorkflowLauncherError::InvalidPolicy);
        }
        let _ = self.grant_verifier()?;
        Ok(())
    }

    fn grant_verifier(&self) -> Result<WorkflowExecutionGrantVerifierV1, WorkflowLauncherError> {
        let keys = self
            .grant_verification_keys
            .iter()
            .map(|key| {
                Ok(WorkflowExecutionGrantVerificationKeyV1::new(
                    key.key_id.clone(),
                    key.key_epoch,
                    decode_public_key(&key.public_key_base64url)?,
                    key.active_from_ms,
                    key.signing_retired_at_ms,
                    key.verify_until_ms,
                    key.revoked_at_ms,
                )?)
            })
            .collect::<Result<Vec<_>, WorkflowLauncherError>>()?;
        Ok(WorkflowExecutionGrantVerifierV1::new(
            self.grant_issuer.clone(),
            self.launcher_audience.clone(),
            self.minimum_grant_key_epoch,
            keys,
        )?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWorkflowLaunchV1 {
    pub lease: WorkflowLeaseV1,
    pub grant: VerifiedWorkflowExecutionGrantV1,
    pub unit_name: String,
    pub job_directory: PathBuf,
    pub prepared_run_path: PathBuf,
    pub dependency_snapshot_path: PathBuf,
    pub operation_state_path: Option<PathBuf>,
    pub executable: &'static str,
    pub arguments: Vec<String>,
}

impl AuthorizedWorkflowLaunchV1 {
    pub fn authorize(
        policy: &WorkflowLauncherPolicyV1,
        preparation_reader: &PreparationStoreReaderV1,
        lease: &WorkflowLeaseV1,
        execution_grant: &str,
        now_ms: i64,
    ) -> Result<Self, WorkflowLauncherError> {
        validate_launcher_lease(policy, lease)?;
        let prepared_run_key = required_prepared_run_key(lease)?;
        let grant = policy
            .grant_verifier()?
            .verify(execution_grant, lease, now_ms)?;
        let prepared = preparation_reader
            .open_entry(PreparationObjectKindV1::PreparedRun, prepared_run_key)?;
        let composition = prepared.prepared_run_composition()?;
        if composition.workflow_policy_digest != lease.workflow_policy_digest {
            return Err(WorkflowLauncherError::PreparedRunMismatch);
        }
        let dependency = preparation_reader.open_entry(
            PreparationObjectKindV1::DependencySnapshot,
            &composition.dependency_snapshot_key,
        )?;
        let compact_lease_id = lease.lease_id.simple();
        let unit_name = unit_name(lease);
        let job_directory = Path::new(WORKFLOW_LAUNCHER_JOB_ROOT)
            .join(format!("{compact_lease_id}-g{}", lease.lease_generation));
        let prepared_run_path = prepared.payload_path();
        let dependency_snapshot_path = dependency.payload_path();
        let operation_state_path = lease.operation_state.as_ref().map(|state| {
            Path::new(WORKFLOW_OPERATION_STATE_ROOT)
                .join(state.state_key.as_str())
                .join("data")
        });
        let arguments = transient_unit_arguments(
            policy,
            lease,
            &unit_name,
            &prepared_run_path,
            &dependency_snapshot_path,
            operation_state_path.as_deref(),
        )?;
        Ok(Self {
            lease: lease.clone(),
            grant,
            unit_name,
            job_directory,
            prepared_run_path,
            dependency_snapshot_path,
            operation_state_path,
            executable: SYSTEMD_RUN_EXECUTABLE,
            arguments,
        })
    }
}

pub const WORKFLOW_LAUNCH_RECORD_SCHEMA_VERSION: u16 = 1;

const WORKFLOW_LAUNCH_RECORD_PURPOSE: &str = "rdashboard.workflow-launch-record.v1";
const WORKFLOW_LAUNCH_TERMINAL_PURPOSE: &str = "rdashboard.workflow-launch-terminal.v1";
const WORKFLOW_LAUNCH_CLEANUP_PURPOSE: &str = "rdashboard.workflow-launch-cleanup.v1";
const WORKFLOW_LAUNCH_RECORD_FILE: &str = "record.jcs";
const MAX_RECORD_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLaunchStateV1 {
    Accepted,
    Running,
    Succeeded,
    Failed,
    NeedsReconcile,
    CleanupPending,
    Cleaned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLaunchTerminalKindV1 {
    ProcessExit,
    SpawnRejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLaunchReconcileReasonV1 {
    LauncherRestarted,
    ProcessWaitUncertain,
    SupervisorUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLaunchTerminalV1 {
    pub kind: WorkflowLaunchTerminalKindV1,
    pub succeeded: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub failure_digest: Option<EvidenceDigest>,
    pub completed_at_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowLaunchTerminalPayload<'a> {
    purpose: &'static str,
    execution_identity_digest: &'a EvidenceDigest,
    launch_grant_digest: &'a EvidenceDigest,
    unit_name: &'a str,
    kind: WorkflowLaunchTerminalKindV1,
    succeeded: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    failure_digest: &'a Option<EvidenceDigest>,
    completed_at_ms: i64,
}

impl WorkflowLaunchTerminalV1 {
    fn process_exit(
        lease: &WorkflowLeaseV1,
        launch_grant_digest: &EvidenceDigest,
        unit_name: &str,
        exit: WorkflowProcessExitV1,
        completed_at_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        let succeeded = exit.exit_code == Some(0) && exit.signal.is_none();
        let mut terminal = Self {
            kind: WorkflowLaunchTerminalKindV1::ProcessExit,
            succeeded,
            exit_code: exit.exit_code,
            signal: exit.signal,
            failure_digest: None,
            completed_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        terminal.evidence_digest =
            terminal.calculate_digest(lease, launch_grant_digest, unit_name)?;
        terminal.validate(lease, launch_grant_digest, unit_name)?;
        Ok(terminal)
    }

    fn spawn_rejected(
        lease: &WorkflowLeaseV1,
        launch_grant_digest: &EvidenceDigest,
        unit_name: &str,
        failure_digest: EvidenceDigest,
        completed_at_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        let mut terminal = Self {
            kind: WorkflowLaunchTerminalKindV1::SpawnRejected,
            succeeded: false,
            exit_code: None,
            signal: None,
            failure_digest: Some(failure_digest),
            completed_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        terminal.evidence_digest =
            terminal.calculate_digest(lease, launch_grant_digest, unit_name)?;
        terminal.validate(lease, launch_grant_digest, unit_name)?;
        Ok(terminal)
    }

    fn validate(
        &self,
        lease: &WorkflowLeaseV1,
        launch_grant_digest: &EvidenceDigest,
        unit_name: &str,
    ) -> Result<(), WorkflowLaunchJournalError> {
        let shape_is_valid = match self.kind {
            WorkflowLaunchTerminalKindV1::ProcessExit => {
                self.failure_digest.is_none()
                    && self.exit_code.is_some() != self.signal.is_some()
                    && self.succeeded == (self.exit_code == Some(0) && self.signal.is_none())
            }
            WorkflowLaunchTerminalKindV1::SpawnRejected => {
                !self.succeeded
                    && self.exit_code.is_none()
                    && self.signal.is_none()
                    && self.failure_digest.is_some()
            }
        };
        if !shape_is_valid
            || self.completed_at_ms < 0
            || self.evidence_digest
                != self.calculate_digest(lease, launch_grant_digest, unit_name)?
        {
            return Err(WorkflowLaunchJournalError::InvalidRecord);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
        lease: &WorkflowLeaseV1,
        launch_grant_digest: &EvidenceDigest,
        unit_name: &str,
    ) -> Result<EvidenceDigest, WorkflowLaunchJournalError> {
        let execution_identity_digest = execution_identity_digest(lease)?;
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowLaunchTerminalPayload {
                purpose: WORKFLOW_LAUNCH_TERMINAL_PURPOSE,
                execution_identity_digest: &execution_identity_digest,
                launch_grant_digest,
                unit_name,
                kind: self.kind,
                succeeded: self.succeeded,
                exit_code: self.exit_code,
                signal: self.signal,
                failure_digest: &self.failure_digest,
                completed_at_ms: self.completed_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLaunchCleanupV1 {
    pub unit_was_loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_state: Option<WorkflowOperationStateReleaseV1>,
    pub completed_at_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowLaunchCleanupPayload<'a> {
    purpose: &'static str,
    execution_identity_digest: &'a EvidenceDigest,
    unit_name: &'a str,
    unit_was_loaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_state: &'a Option<WorkflowOperationStateReleaseV1>,
    completed_at_ms: i64,
}

impl WorkflowLaunchCleanupV1 {
    fn new(
        lease: &WorkflowLeaseV1,
        unit_name: &str,
        unit_was_loaded: bool,
        operation_state: Option<WorkflowOperationStateReleaseV1>,
        completed_at_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        let mut cleanup = Self {
            unit_was_loaded,
            operation_state,
            completed_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        cleanup.evidence_digest = cleanup.calculate_digest(lease, unit_name)?;
        cleanup.validate(lease, unit_name)?;
        Ok(cleanup)
    }

    fn validate(
        &self,
        lease: &WorkflowLeaseV1,
        unit_name: &str,
    ) -> Result<(), WorkflowLaunchJournalError> {
        if self.completed_at_ms < lease.leased_at_ms
            || self.operation_state.is_some() != lease.operation_state.is_some()
            || self.operation_state.as_ref().is_some_and(|release| {
                release.completed_at_ms > self.completed_at_ms
                    || release.validate_for(lease).is_err()
            })
            || self.evidence_digest != self.calculate_digest(lease, unit_name)?
        {
            return Err(WorkflowLaunchJournalError::InvalidRecord);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
        lease: &WorkflowLeaseV1,
        unit_name: &str,
    ) -> Result<EvidenceDigest, WorkflowLaunchJournalError> {
        let execution_identity_digest = execution_identity_digest(lease)?;
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowLaunchCleanupPayload {
                purpose: WORKFLOW_LAUNCH_CLEANUP_PURPOSE,
                execution_identity_digest: &execution_identity_digest,
                unit_name,
                unit_was_loaded: self.unit_was_loaded,
                operation_state: &self.operation_state,
                completed_at_ms: self.completed_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowLaunchRecordV1 {
    purpose: String,
    schema_version: u16,
    lease: WorkflowLeaseV1,
    launch_grant_digest: Option<EvidenceDigest>,
    latest_grant_digest: Option<EvidenceDigest>,
    prepared_run_key: EvidenceDigest,
    unit_name: String,
    state: WorkflowLaunchStateV1,
    accepted_at_ms: i64,
    started_at_ms: Option<i64>,
    terminal: Option<WorkflowLaunchTerminalV1>,
    reconcile_reason: Option<WorkflowLaunchReconcileReasonV1>,
    reconcile_at_ms: Option<i64>,
    cleanup_started_at_ms: Option<i64>,
    cleanup: Option<WorkflowLaunchCleanupV1>,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowLaunchRecordPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lease: &'a WorkflowLeaseV1,
    launch_grant_digest: &'a Option<EvidenceDigest>,
    latest_grant_digest: &'a Option<EvidenceDigest>,
    prepared_run_key: &'a EvidenceDigest,
    unit_name: &'a str,
    state: WorkflowLaunchStateV1,
    accepted_at_ms: i64,
    started_at_ms: Option<i64>,
    terminal: &'a Option<WorkflowLaunchTerminalV1>,
    reconcile_reason: Option<WorkflowLaunchReconcileReasonV1>,
    reconcile_at_ms: Option<i64>,
    cleanup_started_at_ms: Option<i64>,
    cleanup: &'a Option<WorkflowLaunchCleanupV1>,
}

impl WorkflowLaunchRecordV1 {
    fn accepted(
        launch: &AuthorizedWorkflowLaunchV1,
        accepted_at_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        let prepared_run_key = required_prepared_run_key(&launch.lease)?.clone();
        let mut record = Self {
            purpose: WORKFLOW_LAUNCH_RECORD_PURPOSE.to_owned(),
            schema_version: WORKFLOW_LAUNCH_RECORD_SCHEMA_VERSION,
            lease: launch.lease.clone(),
            launch_grant_digest: Some(launch.grant.token_digest.clone()),
            latest_grant_digest: Some(launch.grant.token_digest.clone()),
            prepared_run_key,
            unit_name: launch.unit_name.clone(),
            state: WorkflowLaunchStateV1::Accepted,
            accepted_at_ms,
            started_at_ms: None,
            terminal: None,
            reconcile_reason: None,
            reconcile_at_ms: None,
            cleanup_started_at_ms: None,
            cleanup: None,
            document_digest: EvidenceDigest::sha256([]),
        };
        record.refresh_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn cleanup_tombstone(
        lease: &WorkflowLeaseV1,
        cleanup_started_at_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        let prepared_run_key = required_prepared_run_key(lease)?.clone();
        let mut record = Self {
            purpose: WORKFLOW_LAUNCH_RECORD_PURPOSE.to_owned(),
            schema_version: WORKFLOW_LAUNCH_RECORD_SCHEMA_VERSION,
            lease: lease.clone(),
            launch_grant_digest: None,
            latest_grant_digest: None,
            prepared_run_key,
            unit_name: unit_name(lease),
            state: WorkflowLaunchStateV1::CleanupPending,
            accepted_at_ms: cleanup_started_at_ms,
            started_at_ms: None,
            terminal: None,
            reconcile_reason: None,
            reconcile_at_ms: None,
            cleanup_started_at_ms: Some(cleanup_started_at_ms),
            cleanup: None,
            document_digest: EvidenceDigest::sha256([]),
        };
        record.refresh_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), WorkflowLaunchJournalError> {
        self.lease.validate()?;
        let prepared_run_key = required_prepared_run_key(&self.lease)?;
        let shape_is_valid = match self.state {
            WorkflowLaunchStateV1::Accepted => {
                self.started_at_ms.is_none()
                    && self.terminal.is_none()
                    && self.reconcile_reason.is_none()
                    && self.reconcile_at_ms.is_none()
                    && self.cleanup_started_at_ms.is_none()
                    && self.cleanup.is_none()
                    && self.launch_grant_digest.is_some()
                    && self.latest_grant_digest.is_some()
            }
            WorkflowLaunchStateV1::Running => {
                self.started_at_ms.is_some()
                    && self.terminal.is_none()
                    && self.reconcile_reason.is_none()
                    && self.reconcile_at_ms.is_none()
                    && self.cleanup_started_at_ms.is_none()
                    && self.cleanup.is_none()
                    && self.launch_grant_digest.is_some()
                    && self.latest_grant_digest.is_some()
            }
            WorkflowLaunchStateV1::Succeeded | WorkflowLaunchStateV1::Failed => {
                self.terminal.is_some()
                    && self.reconcile_reason.is_none()
                    && self.reconcile_at_ms.is_none()
                    && self.cleanup_started_at_ms.is_none()
                    && self.cleanup.is_none()
                    && self.launch_grant_digest.is_some()
                    && self.latest_grant_digest.is_some()
            }
            WorkflowLaunchStateV1::NeedsReconcile => {
                self.reconcile_reason.is_some()
                    && self.reconcile_at_ms.is_some()
                    && self.cleanup_started_at_ms.is_none()
                    && self.cleanup.is_none()
            }
            WorkflowLaunchStateV1::CleanupPending => {
                self.cleanup_started_at_ms.is_some() && self.cleanup.is_none()
            }
            WorkflowLaunchStateV1::Cleaned => {
                self.cleanup_started_at_ms.is_some() && self.cleanup.is_some()
            }
        };
        if self.purpose != WORKFLOW_LAUNCH_RECORD_PURPOSE
            || self.schema_version != WORKFLOW_LAUNCH_RECORD_SCHEMA_VERSION
            || self.accepted_at_ms < self.lease.leased_at_ms
            || self
                .started_at_ms
                .is_some_and(|value| value < self.accepted_at_ms)
            || self
                .reconcile_at_ms
                .is_some_and(|value| value < self.accepted_at_ms)
            || self
                .cleanup_started_at_ms
                .is_some_and(|value| value < self.accepted_at_ms)
            || self.prepared_run_key != *prepared_run_key
            || self.unit_name != unit_name(&self.lease)
            || !shape_is_valid
        {
            return Err(WorkflowLaunchJournalError::InvalidRecord);
        }
        if let Some(terminal) = &self.terminal {
            terminal.validate(
                &self.lease,
                self.launch_grant_digest
                    .as_ref()
                    .ok_or(WorkflowLaunchJournalError::InvalidRecord)?,
                &self.unit_name,
            )?;
            if terminal.completed_at_ms < self.accepted_at_ms
                || (self.state == WorkflowLaunchStateV1::Succeeded) != terminal.succeeded
                    && matches!(
                        self.state,
                        WorkflowLaunchStateV1::Succeeded | WorkflowLaunchStateV1::Failed
                    )
            {
                return Err(WorkflowLaunchJournalError::InvalidRecord);
            }
        }
        if let Some(cleanup) = &self.cleanup {
            cleanup.validate(&self.lease, &self.unit_name)?;
            if cleanup.completed_at_ms
                < self
                    .cleanup_started_at_ms
                    .ok_or(WorkflowLaunchJournalError::InvalidRecord)?
                || self
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| cleanup.completed_at_ms < terminal.completed_at_ms)
            {
                return Err(WorkflowLaunchJournalError::InvalidRecord);
            }
        }
        if self.document_digest != self.calculate_digest()? {
            return Err(WorkflowLaunchJournalError::InvalidRecord);
        }
        Ok(())
    }

    fn refresh_digest(&mut self) -> Result<(), WorkflowLaunchJournalError> {
        self.document_digest = self.calculate_digest()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, WorkflowLaunchJournalError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &WorkflowLaunchRecordPayload {
                purpose: WORKFLOW_LAUNCH_RECORD_PURPOSE,
                schema_version: self.schema_version,
                lease: &self.lease,
                launch_grant_digest: &self.launch_grant_digest,
                latest_grant_digest: &self.latest_grant_digest,
                prepared_run_key: &self.prepared_run_key,
                unit_name: &self.unit_name,
                state: self.state,
                accepted_at_ms: self.accepted_at_ms,
                started_at_ms: self.started_at_ms,
                terminal: &self.terminal,
                reconcile_reason: self.reconcile_reason,
                reconcile_at_ms: self.reconcile_at_ms,
                cleanup_started_at_ms: self.cleanup_started_at_ms,
                cleanup: &self.cleanup,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowLaunchJournalError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowLaunchJournalError> {
        let record: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&record)? != bytes {
            return Err(WorkflowLaunchJournalError::NoncanonicalRecord);
        }
        record.validate()?;
        Ok(record)
    }

    fn status(&self) -> WorkflowLaunchStatusV1 {
        WorkflowLaunchStatusV1 {
            lease_digest: self.lease.lease_digest.clone(),
            lease_id: self.lease.lease_id,
            lease_generation: self.lease.lease_generation,
            attempt_id: self.lease.attempt_id,
            project_id: self.lease.project_id.clone(),
            unit_name: self.unit_name.clone(),
            state: self.state,
            terminal: self.terminal.clone(),
            cleanup: self.cleanup.clone(),
            record_digest: self.document_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLaunchStatusV1 {
    pub lease_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub unit_name: String,
    pub state: WorkflowLaunchStateV1,
    pub terminal: Option<WorkflowLaunchTerminalV1>,
    pub cleanup: Option<WorkflowLaunchCleanupV1>,
    pub record_digest: EvidenceDigest,
}

#[derive(Clone, Debug)]
pub struct WorkflowLaunchJournalV1 {
    inner: Arc<WorkflowLaunchJournalInner>,
}

#[derive(Debug)]
struct WorkflowLaunchJournalInner {
    root: PathBuf,
    expected_owner_uid: u32,
    max_records: u32,
    root_lock: File,
    operation_lock: Mutex<()>,
}

impl Drop for WorkflowLaunchJournalInner {
    fn drop(&mut self) {
        // Release the advisory lock before closing the descriptor. A concurrently
        // forked child can briefly inherit the same open-file description until
        // exec applies CLOEXEC; relying on close alone would make an immediate
        // in-process reopen spuriously report AlreadyOpen.
        let _ = fs2::FileExt::unlock(&self.root_lock);
    }
}

impl WorkflowLaunchJournalV1 {
    pub fn open_root_owned(
        root: impl Into<PathBuf>,
        max_records: u32,
        now_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        Self::open(root, 0, max_records, now_ms)
    }

    pub(crate) fn open(
        root: impl Into<PathBuf>,
        expected_owner_uid: u32,
        max_records: u32,
        now_ms: i64,
    ) -> Result<Self, WorkflowLaunchJournalError> {
        if max_records == 0 || max_records > MAX_JOURNAL_RECORDS || now_ms < 0 {
            return Err(WorkflowLaunchJournalError::InvalidConfig);
        }
        let root = root.into();
        validate_private_directory(&root, expected_owner_uid)?;
        let root_lock = File::open(&root)?;
        root_lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                WorkflowLaunchJournalError::AlreadyOpen
            } else {
                WorkflowLaunchJournalError::Io(error)
            }
        })?;
        validate_opened_directory(&root, &root_lock, expected_owner_uid)?;
        let journal = Self {
            inner: Arc::new(WorkflowLaunchJournalInner {
                root,
                expected_owner_uid,
                max_records,
                root_lock,
                operation_lock: Mutex::new(()),
            }),
        };
        journal.reconcile_startup(now_ms)?;
        Ok(journal)
    }

    fn accept(
        &self,
        launch: &AuthorizedWorkflowLaunchV1,
        accepted_at_ms: i64,
        max_concurrent_jobs: u16,
    ) -> Result<(WorkflowLaunchStatusV1, bool), WorkflowLaunchJournalError> {
        let _guard = self.lock()?;
        self.revalidate_root()?;
        let path = self.job_path(&launch.lease);
        if path.try_exists()? {
            let mut record = self.load_record(&path)?;
            if !record.lease.same_execution_as(&launch.lease)? {
                return Err(WorkflowLaunchJournalError::IdentityConflict);
            }
            let mut changed = false;
            if launch.lease.expires_at_ms > record.lease.expires_at_ms {
                record.lease = launch.lease.clone();
                changed = true;
            }
            if record.latest_grant_digest.as_ref() != Some(&launch.grant.token_digest) {
                record.latest_grant_digest = Some(launch.grant.token_digest.clone());
                changed = true;
            }
            if changed {
                record.refresh_digest()?;
                self.write_record(&path, &record)?;
            }
            return Ok((record.status(), false));
        }
        let (records, active) = self.count_records()?;
        if records >= self.inner.max_records {
            return Err(WorkflowLaunchJournalError::JournalFull);
        }
        if active >= u32::from(max_concurrent_jobs) {
            return Err(WorkflowLaunchJournalError::ConcurrencyLimit);
        }
        let record = WorkflowLaunchRecordV1::accepted(launch, accepted_at_ms)?;
        self.create_record_directory(&path, &record)?;
        Ok((record.status(), true))
    }

    fn mark_running(
        &self,
        lease: &WorkflowLeaseV1,
        started_at_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError> {
        self.update_record(lease, |record| {
            if record.state != WorkflowLaunchStateV1::Accepted
                || started_at_ms < record.accepted_at_ms
            {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            record.state = WorkflowLaunchStateV1::Running;
            record.started_at_ms = Some(started_at_ms);
            Ok(())
        })
    }

    fn mark_spawn_rejected(
        &self,
        lease: &WorkflowLeaseV1,
        failure_digest: EvidenceDigest,
        completed_at_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError> {
        self.update_record(lease, |record| {
            if record.state != WorkflowLaunchStateV1::Accepted
                || completed_at_ms < record.accepted_at_ms
            {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            record.state = WorkflowLaunchStateV1::Failed;
            record.terminal = Some(WorkflowLaunchTerminalV1::spawn_rejected(
                &record.lease,
                record
                    .launch_grant_digest
                    .as_ref()
                    .ok_or(WorkflowLaunchJournalError::InvalidRecord)?,
                &record.unit_name,
                failure_digest,
                completed_at_ms,
            )?);
            Ok(())
        })
    }

    fn mark_process_exit(
        &self,
        lease: &WorkflowLeaseV1,
        exit: WorkflowProcessExitV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError> {
        self.update_record(lease, |record| {
            if matches!(
                record.state,
                WorkflowLaunchStateV1::CleanupPending | WorkflowLaunchStateV1::Cleaned
            ) {
                return Ok(());
            }
            if record.state != WorkflowLaunchStateV1::Running
                || completed_at_ms < record.started_at_ms.unwrap_or(record.accepted_at_ms)
            {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            let terminal = WorkflowLaunchTerminalV1::process_exit(
                &record.lease,
                record
                    .launch_grant_digest
                    .as_ref()
                    .ok_or(WorkflowLaunchJournalError::InvalidRecord)?,
                &record.unit_name,
                exit,
                completed_at_ms,
            )?;
            record.state = if terminal.succeeded {
                WorkflowLaunchStateV1::Succeeded
            } else {
                WorkflowLaunchStateV1::Failed
            };
            record.terminal = Some(terminal);
            Ok(())
        })
    }

    fn mark_needs_reconcile(
        &self,
        lease: &WorkflowLeaseV1,
        reason: WorkflowLaunchReconcileReasonV1,
        now_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError> {
        self.update_record(lease, |record| {
            if matches!(
                record.state,
                WorkflowLaunchStateV1::CleanupPending | WorkflowLaunchStateV1::Cleaned
            ) {
                return Ok(());
            }
            if now_ms < record.accepted_at_ms {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            record.state = WorkflowLaunchStateV1::NeedsReconcile;
            record.reconcile_reason = Some(reason);
            record.reconcile_at_ms = Some(now_ms);
            Ok(())
        })
    }

    fn begin_cleanup(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<(WorkflowLaunchStatusV1, bool), WorkflowLaunchJournalError> {
        let _guard = self.lock()?;
        self.revalidate_root()?;
        let path = self.job_path(lease);
        let mut record = if path.try_exists()? {
            let record = self.load_record(&path)?;
            if !record.lease.same_execution_as(lease)? {
                return Err(WorkflowLaunchJournalError::IdentityConflict);
            }
            record
        } else {
            let (records, _) = self.count_records()?;
            if records >= self.inner.max_records {
                return Err(WorkflowLaunchJournalError::JournalFull);
            }
            let record = WorkflowLaunchRecordV1::cleanup_tombstone(lease, now_ms)?;
            self.create_record_directory(&path, &record)?;
            return Ok((record.status(), true));
        };
        if record.state == WorkflowLaunchStateV1::Cleaned {
            return Ok((record.status(), false));
        }
        if record.state != WorkflowLaunchStateV1::CleanupPending {
            if now_ms < record.accepted_at_ms {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            if record
                .terminal
                .as_ref()
                .is_some_and(|terminal| now_ms < terminal.completed_at_ms)
            {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            if lease.expires_at_ms > record.lease.expires_at_ms {
                record.lease = lease.clone();
                record.refresh_digest()?;
            }
            record.state = WorkflowLaunchStateV1::CleanupPending;
            record.cleanup_started_at_ms = Some(now_ms);
            record.reconcile_reason = None;
            record.reconcile_at_ms = None;
            record.refresh_digest()?;
            self.write_record(&path, &record)?;
        }
        Ok((record.status(), true))
    }

    fn finish_cleanup(
        &self,
        lease: &WorkflowLeaseV1,
        unit_was_loaded: bool,
        operation_state: Option<WorkflowOperationStateReleaseV1>,
        completed_at_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError> {
        self.update_record(lease, |record| {
            if record.state == WorkflowLaunchStateV1::Cleaned {
                return Ok(());
            }
            if record.state != WorkflowLaunchStateV1::CleanupPending
                || completed_at_ms
                    < record
                        .cleanup_started_at_ms
                        .ok_or(WorkflowLaunchJournalError::StateConflict)?
                || record
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| completed_at_ms < terminal.completed_at_ms)
            {
                return Err(WorkflowLaunchJournalError::StateConflict);
            }
            record.cleanup = Some(WorkflowLaunchCleanupV1::new(
                &record.lease,
                &record.unit_name,
                unit_was_loaded,
                operation_state,
                completed_at_ms,
            )?);
            record.state = WorkflowLaunchStateV1::Cleaned;
            Ok(())
        })
    }

    pub fn observe(
        &self,
        lease_id: Uuid,
        lease_generation: u32,
    ) -> Result<Option<WorkflowLaunchStatusV1>, WorkflowLaunchJournalError> {
        if lease_id.is_nil() || lease_generation == 0 {
            return Err(WorkflowLaunchJournalError::InvalidLocator);
        }
        let _guard = self.lock()?;
        self.revalidate_root()?;
        let path = self
            .inner
            .root
            .join(job_directory_name(lease_id, lease_generation));
        if !path.try_exists()? {
            return Ok(None);
        }
        Ok(Some(self.load_record(&path)?.status()))
    }

    fn update_record<F>(
        &self,
        lease: &WorkflowLeaseV1,
        update: F,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchJournalError>
    where
        F: FnOnce(&mut WorkflowLaunchRecordV1) -> Result<(), WorkflowLaunchJournalError>,
    {
        let _guard = self.lock()?;
        self.revalidate_root()?;
        let path = self.job_path(lease);
        let mut record = self.load_record(&path)?;
        if !record.lease.same_execution_as(lease)? {
            return Err(WorkflowLaunchJournalError::IdentityConflict);
        }
        if lease.expires_at_ms > record.lease.expires_at_ms {
            record.lease = lease.clone();
            record.refresh_digest()?;
        }
        update(&mut record)?;
        record.refresh_digest()?;
        record.validate()?;
        self.write_record(&path, &record)?;
        Ok(record.status())
    }

    fn reconcile_startup(&self, now_ms: i64) -> Result<(), WorkflowLaunchJournalError> {
        let _guard = self.lock()?;
        self.revalidate_root()?;
        let entries = fs::read_dir(&self.inner.root)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > usize::try_from(self.inner.max_records).unwrap_or(usize::MAX) + 32 {
            return Err(WorkflowLaunchJournalError::JournalFull);
        }
        for entry in entries {
            let name = entry.file_name();
            let path = entry.path();
            if name.as_encoded_bytes().starts_with(b".staging-") {
                remove_root_owned_staging(&path, self.inner.expected_owner_uid)?;
                continue;
            }
            let mut record = self.load_record(&path)?;
            if OsStr::new(&job_directory_name(
                record.lease.lease_id,
                record.lease.lease_generation,
            )) != name
            {
                return Err(WorkflowLaunchJournalError::InvalidRecordPath);
            }
            remove_record_temporaries(&path, self.inner.expected_owner_uid)?;
            if matches!(
                record.state,
                WorkflowLaunchStateV1::Accepted | WorkflowLaunchStateV1::Running
            ) {
                record.state = WorkflowLaunchStateV1::NeedsReconcile;
                record.reconcile_reason = Some(WorkflowLaunchReconcileReasonV1::LauncherRestarted);
                record.reconcile_at_ms = Some(now_ms.max(record.accepted_at_ms));
                record.refresh_digest()?;
                self.write_record(&path, &record)?;
            }
        }
        Ok(())
    }

    fn count_records(&self) -> Result<(u32, u32), WorkflowLaunchJournalError> {
        let mut records = 0_u32;
        let mut active = 0_u32;
        for entry in fs::read_dir(&self.inner.root)? {
            let entry = entry?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".staging-")
            {
                continue;
            }
            records = records
                .checked_add(1)
                .ok_or(WorkflowLaunchJournalError::JournalFull)?;
            let record = self.load_record(&entry.path())?;
            if matches!(
                record.state,
                WorkflowLaunchStateV1::Accepted
                    | WorkflowLaunchStateV1::Running
                    | WorkflowLaunchStateV1::NeedsReconcile
                    | WorkflowLaunchStateV1::CleanupPending
            ) {
                active = active
                    .checked_add(1)
                    .ok_or(WorkflowLaunchJournalError::ConcurrencyLimit)?;
            }
        }
        Ok((records, active))
    }

    fn create_record_directory(
        &self,
        final_path: &Path,
        record: &WorkflowLaunchRecordV1,
    ) -> Result<(), WorkflowLaunchJournalError> {
        let stage_name = format!(".staging-{}", Uuid::new_v4().simple());
        let stage = self.inner.root.join(stage_name);
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&stage)?;
        let result = (|| {
            validate_private_directory(&stage, self.inner.expected_owner_uid)?;
            write_new_record(
                &stage.join(WORKFLOW_LAUNCH_RECORD_FILE),
                record,
                self.inner.expected_owner_uid,
            )?;
            File::open(&stage)?.sync_all()?;
            fs::rename(&stage, final_path)?;
            File::open(&self.inner.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() && stage.try_exists().unwrap_or(false) {
            let _ = remove_root_owned_staging(&stage, self.inner.expected_owner_uid);
        }
        result
    }

    fn load_record(
        &self,
        directory: &Path,
    ) -> Result<WorkflowLaunchRecordV1, WorkflowLaunchJournalError> {
        validate_private_directory(directory, self.inner.expected_owner_uid)?;
        let bytes = read_stable_private_file(
            &directory.join(WORKFLOW_LAUNCH_RECORD_FILE),
            self.inner.expected_owner_uid,
            MAX_RECORD_BYTES,
        )?;
        let record = WorkflowLaunchRecordV1::decode_canonical(&bytes)?;
        if directory.file_name()
            != Some(OsStr::new(&job_directory_name(
                record.lease.lease_id,
                record.lease.lease_generation,
            )))
        {
            return Err(WorkflowLaunchJournalError::InvalidRecordPath);
        }
        Ok(record)
    }

    fn write_record(
        &self,
        directory: &Path,
        record: &WorkflowLaunchRecordV1,
    ) -> Result<(), WorkflowLaunchJournalError> {
        validate_private_directory(directory, self.inner.expected_owner_uid)?;
        let bytes = record.canonical_bytes()?;
        if bytes.len() > usize::try_from(MAX_RECORD_BYTES).unwrap_or(usize::MAX) {
            return Err(WorkflowLaunchJournalError::RecordTooLarge);
        }
        let temporary = directory.join(format!(".record-{}.tmp", Uuid::new_v4().simple()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join(WORKFLOW_LAUNCH_RECORD_FILE))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn job_path(&self, lease: &WorkflowLeaseV1) -> PathBuf {
        self.inner
            .root
            .join(job_directory_name(lease.lease_id, lease.lease_generation))
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, WorkflowLaunchJournalError> {
        self.inner
            .operation_lock
            .lock()
            .map_err(|_| WorkflowLaunchJournalError::LockPoisoned)
    }

    fn revalidate_root(&self) -> Result<(), WorkflowLaunchJournalError> {
        validate_opened_directory(
            &self.inner.root,
            &self.inner.root_lock,
            self.inner.expected_owner_uid,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowProcessExitV1 {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

pub trait WorkflowLaunchProcessV1: Send {
    fn wait(self: Box<Self>) -> Result<WorkflowProcessExitV1, WorkflowLaunchRuntimeError>;

    fn abort(self: Box<Self>) -> Result<(), WorkflowLaunchRuntimeError>;
}

pub trait WorkflowLaunchRuntimeV1: Send + Sync {
    fn spawn(
        &self,
        launch: &AuthorizedWorkflowLaunchV1,
    ) -> Result<Box<dyn WorkflowLaunchProcessV1>, WorkflowLaunchRuntimeError>;

    fn terminate(&self, unit_name: &str) -> Result<bool, WorkflowLaunchRuntimeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdWorkflowLaunchRuntimeV1;

struct SystemdWorkflowLaunchProcessV1 {
    child: Child,
}

impl WorkflowLaunchProcessV1 for SystemdWorkflowLaunchProcessV1 {
    fn wait(mut self: Box<Self>) -> Result<WorkflowProcessExitV1, WorkflowLaunchRuntimeError> {
        let status = self
            .child
            .wait()
            .map_err(WorkflowLaunchRuntimeError::Wait)?;
        Ok(process_exit(status))
    }

    fn abort(mut self: Box<Self>) -> Result<(), WorkflowLaunchRuntimeError> {
        if self
            .child
            .try_wait()
            .map_err(WorkflowLaunchRuntimeError::AbortQuery)?
            .is_none()
        {
            self.child
                .kill()
                .map_err(WorkflowLaunchRuntimeError::Abort)?;
        }
        self.child
            .wait()
            .map_err(WorkflowLaunchRuntimeError::AbortWait)?;
        Ok(())
    }
}

impl WorkflowLaunchRuntimeV1 for SystemdWorkflowLaunchRuntimeV1 {
    fn spawn(
        &self,
        launch: &AuthorizedWorkflowLaunchV1,
    ) -> Result<Box<dyn WorkflowLaunchProcessV1>, WorkflowLaunchRuntimeError> {
        let child = Command::new(launch.executable)
            .args(&launch.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(WorkflowLaunchRuntimeError::Spawn)?;
        Ok(Box::new(SystemdWorkflowLaunchProcessV1 { child }))
    }

    fn terminate(&self, unit_name: &str) -> Result<bool, WorkflowLaunchRuntimeError> {
        let stop = Command::new("/usr/bin/systemctl")
            .args(["stop", "--", unit_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(WorkflowLaunchRuntimeError::Stop)?;
        if !stop.success() {
            let load_state = systemd_property(unit_name, "LoadState")?;
            if load_state == "not-found" {
                return Ok(false);
            }
            return Err(WorkflowLaunchRuntimeError::StopRejected);
        }
        let active_state = systemd_property(unit_name, "ActiveState")?;
        if !matches!(active_state.as_str(), "inactive" | "failed") {
            return Err(WorkflowLaunchRuntimeError::UnitStillActive);
        }
        let reset = Command::new("/usr/bin/systemctl")
            .args(["reset-failed", "--", unit_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(WorkflowLaunchRuntimeError::ResetFailed)?;
        if !reset.success() {
            let load_state = systemd_property(unit_name, "LoadState")?;
            if load_state != "not-found" {
                return Err(WorkflowLaunchRuntimeError::ResetRejected);
            }
        }
        Ok(true)
    }
}

pub struct WorkflowLaunchSupervisorV1 {
    policy: WorkflowLauncherPolicyV1,
    preparation_reader: PreparationStoreReaderV1,
    journal: WorkflowLaunchJournalV1,
    operation_states: Arc<dyn WorkflowOperationStateManagerV1>,
    runtime: Arc<dyn WorkflowLaunchRuntimeV1>,
}

impl WorkflowLaunchSupervisorV1 {
    pub fn new(
        policy: WorkflowLauncherPolicyV1,
        preparation_reader: PreparationStoreReaderV1,
        journal: WorkflowLaunchJournalV1,
        operation_states: Arc<dyn WorkflowOperationStateManagerV1>,
        runtime: Arc<dyn WorkflowLaunchRuntimeV1>,
    ) -> Result<Self, WorkflowLaunchSupervisorError> {
        policy.validate()?;
        if policy.max_journal_records != journal.inner.max_records {
            return Err(WorkflowLaunchSupervisorError::PolicyJournalMismatch);
        }
        Ok(Self {
            policy,
            preparation_reader,
            journal,
            operation_states,
            runtime,
        })
    }

    pub fn launch(
        &self,
        lease: &WorkflowLeaseV1,
        execution_grant: &str,
        now_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchSupervisorError> {
        self.launch_with_waiter(lease, execution_grant, now_ms, |name, task| {
            thread::Builder::new().name(name).spawn(task).map(drop)
        })
    }

    fn launch_with_waiter<F>(
        &self,
        lease: &WorkflowLeaseV1,
        execution_grant: &str,
        now_ms: i64,
        spawn_waiter: F,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchSupervisorError>
    where
        F: FnOnce(String, Box<dyn FnOnce() + Send>) -> io::Result<()>,
    {
        let launch = AuthorizedWorkflowLaunchV1::authorize(
            &self.policy,
            &self.preparation_reader,
            lease,
            execution_grant,
            now_ms,
        )?;
        let (status, is_new) =
            self.journal
                .accept(&launch, now_ms, self.policy.max_concurrent_jobs)?;
        if !is_new {
            return Ok(status);
        }
        let operation_state = self.operation_states.acquire(lease, now_ms)?;
        if launch.operation_state_path.as_ref() != Some(&operation_state.data_path)
            || lease.operation_state.as_ref().map(|state| &state.state_key)
                != Some(&operation_state.state_key)
        {
            return Err(WorkflowLaunchSupervisorError::OperationStatePathMismatch);
        }
        let (process_sender, process_receiver) =
            std::sync::mpsc::sync_channel::<Box<dyn WorkflowLaunchProcessV1>>(1);
        let journal = self.journal.clone();
        let wait_lease = lease.clone();
        let fallback_time = wait_lease.expires_at_ms.max(now_ms);
        let waiter_name = format!("workflow-{}", wait_lease.lease_id.simple());
        if let Err(error) = spawn_waiter(
            waiter_name,
            Box::new(move || {
                let Ok(process) = process_receiver.recv() else {
                    return;
                };
                if let Ok(exit) = process.wait() {
                    let completed_at_ms = crate::unix_time_ms().unwrap_or(fallback_time);
                    let _ = journal.mark_process_exit(&wait_lease, exit, completed_at_ms);
                } else {
                    let reconcile_at_ms = crate::unix_time_ms().unwrap_or(fallback_time);
                    let _ = journal.mark_needs_reconcile(
                        &wait_lease,
                        WorkflowLaunchReconcileReasonV1::ProcessWaitUncertain,
                        reconcile_at_ms,
                    );
                }
            }),
        ) {
            return Ok(self.journal.mark_spawn_rejected(
                lease,
                WorkflowLaunchRuntimeError::WaiterSpawn(error).evidence_digest(),
                now_ms,
            )?);
        }
        let process = match self.runtime.spawn(&launch) {
            Ok(process) => process,
            Err(error) => {
                return Ok(self.journal.mark_spawn_rejected(
                    lease,
                    error.evidence_digest(),
                    now_ms,
                )?);
            }
        };
        let running = match self.journal.mark_running(lease, now_ms) {
            Ok(running) => running,
            Err(error) => {
                let handoff = process_sender.send(process);
                let _ = self.journal.mark_needs_reconcile(
                    lease,
                    WorkflowLaunchReconcileReasonV1::SupervisorUnavailable,
                    now_ms,
                );
                match handoff {
                    Ok(()) => {
                        self.runtime.terminate(&launch.unit_name)?;
                    }
                    Err(send_error) => {
                        self.contain_unowned_process(&launch.unit_name, send_error.0)?;
                    }
                }
                return Err(error.into());
            }
        };
        if let Err(send_error) = process_sender.send(process) {
            let reconciled = self.journal.mark_needs_reconcile(
                lease,
                WorkflowLaunchReconcileReasonV1::SupervisorUnavailable,
                now_ms,
            );
            self.contain_unowned_process(&launch.unit_name, send_error.0)?;
            return Ok(reconciled?);
        }
        Ok(running)
    }

    fn contain_unowned_process(
        &self,
        unit_name: &str,
        process: Box<dyn WorkflowLaunchProcessV1>,
    ) -> Result<(), WorkflowLaunchRuntimeError> {
        let stop = self.runtime.terminate(unit_name);
        let abort = process.abort();
        stop?;
        abort?;
        Ok(())
    }

    pub fn observe(
        &self,
        lease_id: Uuid,
        lease_generation: u32,
    ) -> Result<Option<WorkflowLaunchStatusV1>, WorkflowLaunchSupervisorError> {
        Ok(self.journal.observe(lease_id, lease_generation)?)
    }

    pub fn cleanup(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLaunchSupervisorError> {
        validate_launcher_cleanup_lease(&self.policy, lease)?;
        let (status, needs_runtime) = self.journal.begin_cleanup(lease, now_ms)?;
        if !needs_runtime {
            return Ok(status);
        }
        let unit_was_loaded = self.runtime.terminate(&unit_name(lease))?;
        let outcome = match status.terminal.as_ref() {
            Some(terminal) if terminal.succeeded => WorkflowOperationStateOutcomeV1::Succeeded,
            Some(_) => WorkflowOperationStateOutcomeV1::Failed,
            None => WorkflowOperationStateOutcomeV1::Unknown,
        };
        let operation_state = if lease.operation_state.is_some() {
            Some(self.operation_states.release(lease, outcome, now_ms)?)
        } else {
            // Leases accepted by an older installed launcher have no operation-state contract.
            // They still need to be stoppable and journalled as clean during a rolling upgrade.
            None
        };
        Ok(self
            .journal
            .finish_cleanup(lease, unit_was_loaded, operation_state, now_ms)?)
    }
}

fn validate_launcher_lease(
    policy: &WorkflowLauncherPolicyV1,
    lease: &WorkflowLeaseV1,
) -> Result<(), WorkflowLauncherError> {
    policy.validate()?;
    lease.validate()?;
    if lease.worker_id != policy.worker_id
        || lease.host_id != policy.host_id
        || !matches!(
            lease.worker_pool,
            WorkflowWorkerPoolV1::VpsRequired | WorkflowWorkerPoolV1::BuildCompute
        )
        || lease.network_class != WorkflowNetworkClassV1::Offline
        || lease.operation_state.is_none()
        || !policy.allowed_adapters.contains(&lease.adapter_id)
        || !matches!(
            lease.adapter_id,
            WorkflowAdapterIdV1::WorkerBareBinCiV1
                | WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
                | WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
        )
    {
        return Err(WorkflowLauncherError::UnsupportedLease);
    }
    let _ = required_prepared_run_key(lease)?;
    Ok(())
}

fn validate_launcher_cleanup_lease(
    policy: &WorkflowLauncherPolicyV1,
    lease: &WorkflowLeaseV1,
) -> Result<(), WorkflowLauncherError> {
    policy.validate()?;
    lease.validate()?;
    if lease.worker_id != policy.worker_id
        || lease.host_id != policy.host_id
        || !matches!(
            lease.worker_pool,
            WorkflowWorkerPoolV1::VpsRequired | WorkflowWorkerPoolV1::BuildCompute
        )
        || lease.network_class != WorkflowNetworkClassV1::Offline
        || !matches!(
            lease.adapter_id,
            WorkflowAdapterIdV1::WorkerBareBinCiV1
                | WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
                | WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
        )
    {
        return Err(WorkflowLauncherError::UnsupportedLease);
    }
    let _ = required_prepared_run_key(lease)?;
    Ok(())
}

fn required_prepared_run_key(
    lease: &WorkflowLeaseV1,
) -> Result<&EvidenceDigest, WorkflowLauncherError> {
    let inputs = lease.required_input_artifacts()?;
    let [input] = inputs else {
        return Err(WorkflowLauncherError::UnsupportedLease);
    };
    if input.artifact_kind != WorkflowArtifactKindV1::PreparedRun {
        return Err(WorkflowLauncherError::UnsupportedLease);
    }
    Ok(&input.output_digest)
}

#[derive(Serialize)]
struct WorkflowExecutionIdentityPayload<'a> {
    purpose: &'static str,
    normalized_lease: &'a WorkflowLeaseV1,
}

fn execution_identity_digest(
    lease: &WorkflowLeaseV1,
) -> Result<EvidenceDigest, WorkflowLaunchJournalError> {
    lease.validate()?;
    let mut normalized = lease.clone();
    normalized.expires_at_ms = 0;
    normalized.lease_digest = EvidenceDigest::sha256([]);
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &WorkflowExecutionIdentityPayload {
            purpose: "rdashboard.workflow-execution-identity.v1",
            normalized_lease: &normalized,
        },
    )?))
}

fn unit_name(lease: &WorkflowLeaseV1) -> String {
    format!(
        "rdashboard-workflow-{}-g{}",
        lease.lease_id.simple(),
        lease.lease_generation
    )
}

fn job_directory_name(lease_id: Uuid, lease_generation: u32) -> String {
    format!("{}-g{lease_generation}", lease_id.simple())
}

fn process_exit(status: ExitStatus) -> WorkflowProcessExitV1 {
    WorkflowProcessExitV1 {
        exit_code: status.code(),
        signal: status.signal(),
    }
}

fn systemd_property(unit_name: &str, property: &str) -> Result<String, WorkflowLaunchRuntimeError> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", "--property", property, "--value", "--", unit_name])
        .stdin(Stdio::null())
        .output()
        .map_err(WorkflowLaunchRuntimeError::Query)?;
    if !output.status.success() || output.stdout.len() > 128 {
        return Err(WorkflowLaunchRuntimeError::QueryRejected);
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| WorkflowLaunchRuntimeError::QueryRejected)?
        .trim();
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(WorkflowLaunchRuntimeError::QueryRejected);
    }
    Ok(value.to_owned())
}

fn validate_private_directory(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<(), WorkflowLaunchJournalError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(WorkflowLaunchJournalError::UnsafePath);
    }
    Ok(())
}

fn validate_opened_directory(
    path: &Path,
    opened: &File,
    expected_owner_uid: u32,
) -> Result<(), WorkflowLaunchJournalError> {
    validate_private_directory(path, expected_owner_uid)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let opened_metadata = opened.metadata()?;
    if !same_file(&path_metadata, &opened_metadata) {
        return Err(WorkflowLaunchJournalError::PathChanged);
    }
    Ok(())
}

fn read_stable_private_file(
    path: &Path,
    expected_owner_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, WorkflowLaunchJournalError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != expected_owner_uid
        || path_metadata.permissions().mode() & 0o7777 != 0o600
        || path_metadata.nlink() != 1
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(WorkflowLaunchJournalError::UnsafePath);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file(&path_metadata, &opened) {
        return Err(WorkflowLaunchJournalError::PathChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if !same_file(&opened, &final_metadata)
        || bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
    {
        return Err(WorkflowLaunchJournalError::PathChanged);
    }
    Ok(bytes)
}

fn write_new_record(
    path: &Path,
    record: &WorkflowLaunchRecordV1,
    expected_owner_uid: u32,
) -> Result<(), WorkflowLaunchJournalError> {
    let bytes = record.canonical_bytes()?;
    if bytes.len() > usize::try_from(MAX_RECORD_BYTES).unwrap_or(usize::MAX) {
        return Err(WorkflowLaunchJournalError::RecordTooLarge);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(WorkflowLaunchJournalError::UnsafePath);
    }
    Ok(())
}

fn remove_record_temporaries(
    directory: &Path,
    expected_owner_uid: u32,
) -> Result<(), WorkflowLaunchJournalError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == OsStr::new(WORKFLOW_LAUNCH_RECORD_FILE) {
            continue;
        }
        if !name.as_encoded_bytes().starts_with(b".record-")
            || !name.as_encoded_bytes().ends_with(b".tmp")
        {
            return Err(WorkflowLaunchJournalError::UnsafePath);
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_owner_uid
            || metadata.nlink() != 1
        {
            return Err(WorkflowLaunchJournalError::UnsafePath);
        }
        fs::remove_file(entry.path())?;
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn remove_root_owned_staging(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<(), WorkflowLaunchJournalError> {
    validate_private_directory(path, expected_owner_uid)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_owner_uid
            || metadata.nlink() != 1
        {
            return Err(WorkflowLaunchJournalError::UnsafePath);
        }
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(path)?;
    File::open(
        path.parent()
            .ok_or(WorkflowLaunchJournalError::UnsafePath)?,
    )?
    .sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLaunchJournalError {
    #[error("workflow launch journal configuration is invalid")]
    InvalidConfig,
    #[error("workflow launch journal is already open")]
    AlreadyOpen,
    #[error("workflow launch journal path is unsafe")]
    UnsafePath,
    #[error("workflow launch journal path changed while open")]
    PathChanged,
    #[error("workflow launch record path is invalid")]
    InvalidRecordPath,
    #[error("workflow launch record is invalid")]
    InvalidRecord,
    #[error("workflow launch record is not canonical JCS")]
    NoncanonicalRecord,
    #[error("workflow launch record exceeds its size limit")]
    RecordTooLarge,
    #[error("workflow launch journal capacity is exhausted")]
    JournalFull,
    #[error("workflow launch concurrency limit is exhausted")]
    ConcurrencyLimit,
    #[error("workflow launch record identity conflicts with the request")]
    IdentityConflict,
    #[error("workflow launch record state conflicts with the request")]
    StateConflict,
    #[error("workflow launch locator is invalid")]
    InvalidLocator,
    #[error("workflow launch journal lock is poisoned")]
    LockPoisoned,
    #[error("workflow launch lease contract failed: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("workflow launch authorization failed: {0}")]
    Launcher(#[from] WorkflowLauncherError),
    #[error("workflow launch journal JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("workflow launch journal I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLaunchRuntimeError {
    #[error("systemd-run could not be started: {0}")]
    Spawn(io::Error),
    #[error("systemd-run could not be waited: {0}")]
    Wait(io::Error),
    #[error("workflow launch waiter thread could not be started: {0}")]
    WaiterSpawn(io::Error),
    #[error("systemd-run state could not be queried before abort: {0}")]
    AbortQuery(io::Error),
    #[error("systemd-run could not be aborted: {0}")]
    Abort(io::Error),
    #[error("aborted systemd-run could not be reaped: {0}")]
    AbortWait(io::Error),
    #[error("workflow unit stop could not be started: {0}")]
    Stop(io::Error),
    #[error("workflow unit stop was rejected")]
    StopRejected,
    #[error("workflow unit remains active after stop")]
    UnitStillActive,
    #[error("workflow unit state query could not be started: {0}")]
    Query(io::Error),
    #[error("workflow unit state query was rejected")]
    QueryRejected,
    #[error("workflow unit reset-failed could not be started: {0}")]
    ResetFailed(io::Error),
    #[error("workflow unit reset-failed was rejected")]
    ResetRejected,
}

impl WorkflowLaunchRuntimeError {
    fn evidence_digest(&self) -> EvidenceDigest {
        let stable = match self {
            Self::Spawn(error) => format!("spawn:{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::Wait(error) => format!("wait:{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::WaiterSpawn(error) => {
                format!("waiter-spawn:{:?}:{:?}", error.kind(), error.raw_os_error())
            }
            Self::AbortQuery(error) => {
                format!("abort-query:{:?}:{:?}", error.kind(), error.raw_os_error())
            }
            Self::Abort(error) => format!("abort:{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::AbortWait(error) => {
                format!("abort-wait:{:?}:{:?}", error.kind(), error.raw_os_error())
            }
            Self::Stop(error) => format!("stop:{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::Query(error) => format!("query:{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::ResetFailed(error) => {
                format!("reset:{:?}:{:?}", error.kind(), error.raw_os_error())
            }
            Self::StopRejected => "stop-rejected".to_owned(),
            Self::UnitStillActive => "unit-still-active".to_owned(),
            Self::QueryRejected => "query-rejected".to_owned(),
            Self::ResetRejected => "reset-rejected".to_owned(),
        };
        EvidenceDigest::sha256(stable)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLaunchSupervisorError {
    #[error("workflow launcher policy does not match its journal")]
    PolicyJournalMismatch,
    #[error("workflow operation-state path does not match its authorized lease")]
    OperationStatePathMismatch,
    #[error("workflow launch authorization failed: {0}")]
    Launcher(#[from] WorkflowLauncherError),
    #[error("workflow launch journal failed: {0}")]
    Journal(#[from] WorkflowLaunchJournalError),
    #[error("workflow operation-state lifecycle failed: {0}")]
    OperationState(#[from] WorkflowOperationStateError),
    #[error("workflow launch runtime failed: {0}")]
    Runtime(#[from] WorkflowLaunchRuntimeError),
}

fn transient_unit_arguments(
    policy: &WorkflowLauncherPolicyV1,
    lease: &WorkflowLeaseV1,
    unit_name: &str,
    prepared_run_path: &Path,
    dependency_snapshot_path: &Path,
    operation_state_path: Option<&Path>,
) -> Result<Vec<String>, WorkflowLauncherError> {
    let resources = lease
        .resources
        .as_ref()
        .ok_or(WorkflowLauncherError::UnsupportedLease)?;
    let adapter = adapter_argument(lease.adapter_id)?;
    let operation_state_path =
        operation_state_path.ok_or(WorkflowLauncherError::UnsupportedLease)?;
    Ok(vec![
        "--no-ask-password".to_owned(),
        "--quiet".to_owned(),
        "--wait".to_owned(),
        "--collect".to_owned(),
        "--expand-environment=no".to_owned(),
        "--service-type=exec".to_owned(),
        format!("--unit={unit_name}"),
        "--working-directory=/job".to_owned(),
        format!("--property=User={}", policy.build_uid),
        format!("--property=Group={}", policy.build_gid),
        "--property=UMask=0077".to_owned(),
        "--property=SetLoginEnvironment=no".to_owned(),
        "--property=NoNewPrivileges=yes".to_owned(),
        "--property=PrivateDevices=yes".to_owned(),
        "--property=PrivateNetwork=yes".to_owned(),
        "--property=PrivateTmp=yes".to_owned(),
        "--property=ProtectClock=yes".to_owned(),
        "--property=ProtectControlGroups=yes".to_owned(),
        "--property=ProtectHome=yes".to_owned(),
        "--property=ProtectHostname=yes".to_owned(),
        "--property=ProtectKernelLogs=yes".to_owned(),
        "--property=ProtectKernelModules=yes".to_owned(),
        "--property=ProtectKernelTunables=yes".to_owned(),
        "--property=ProtectProc=invisible".to_owned(),
        "--property=ProcSubset=pid".to_owned(),
        "--property=ProtectSystem=strict".to_owned(),
        "--property=RestrictAddressFamilies=AF_UNIX".to_owned(),
        "--property=RestrictNamespaces=yes".to_owned(),
        "--property=RestrictRealtime=yes".to_owned(),
        "--property=RestrictSUIDSGID=yes".to_owned(),
        "--property=LockPersonality=yes".to_owned(),
        "--property=MemoryDenyWriteExecute=yes".to_owned(),
        "--property=MemorySwapMax=0".to_owned(),
        "--property=CapabilityBoundingSet=".to_owned(),
        "--property=AmbientCapabilities=".to_owned(),
        "--property=DevicePolicy=closed".to_owned(),
        "--property=KillMode=control-group".to_owned(),
        "--property=CollectMode=inactive-or-failed".to_owned(),
        "--property=SendSIGKILL=yes".to_owned(),
        "--property=TimeoutStopSec=10s".to_owned(),
        "--property=StandardOutput=journal".to_owned(),
        "--property=StandardError=journal".to_owned(),
        format!(
            "--property=CPUQuota={}",
            cpu_quota(resources.cpu_millicores)
        ),
        format!("--property=MemoryMax={}", resources.memory_max_bytes),
        format!("--property=TasksMax={}", resources.tasks_max),
        format!("--property=LimitFSIZE={}", resources.output_max_bytes),
        format!("--property=RuntimeMaxSec={}ms", lease.timeout_ms),
        format!(
            "--property=InaccessiblePaths=-/etc/rdashboard/credentials /run -/var/lib/rdashboard-workflow-launcher -{WORKFLOW_OPERATION_STATE_ROOT}"
        ),
        format!(
            "--property=BindReadOnlyPaths={}:/prepared",
            prepared_run_path.display()
        ),
        format!(
            "--property=BindReadOnlyPaths={}:/dependencies",
            dependency_snapshot_path.display()
        ),
        format!(
            "--property=BindPaths={}:/operation",
            operation_state_path.display()
        ),
        format!(
            "--property=TemporaryFileSystem=/job:rw,nodev,nosuid,size={},nr_inodes={},mode=0700,uid={},gid={}",
            resources.scratch_max_bytes,
            resources.scratch_max_inodes,
            policy.build_uid,
            policy.build_gid,
        ),
        "--property=ReadWritePaths=/job".to_owned(),
        "--".to_owned(),
        ENV_EXECUTABLE.to_owned(),
        "-i".to_owned(),
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin".to_owned(),
        "HOME=/nonexistent".to_owned(),
        "TMPDIR=/job/tmp".to_owned(),
        "CARGO_HOME=/job/cargo-home".to_owned(),
        "CARGO_NET_OFFLINE=true".to_owned(),
        "CARGO_TARGET_DIR=/operation/target".to_owned(),
        "CCACHE_DIR=/operation/ccache".to_owned(),
        "CCACHE_TEMPDIR=/job/ccache-tmp".to_owned(),
        "RDASHBOARD_PREPARED_ROOT=/prepared".to_owned(),
        "RDASHBOARD_DEPENDENCY_ROOT=/dependencies".to_owned(),
        "RDASHBOARD_OPERATION_ROOT=/operation".to_owned(),
        WORKFLOW_JOB_EXECUTABLE.to_owned(),
        adapter.to_owned(),
    ])
}

fn adapter_argument(adapter: WorkflowAdapterIdV1) -> Result<&'static str, WorkflowLauncherError> {
    match adapter {
        WorkflowAdapterIdV1::WorkerBareBinCiV1 => Ok("bare-bin-ci-v1"),
        WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1 => Ok("native-release-build-v1"),
        WorkflowAdapterIdV1::WorkerOciReleaseBuildV1 => Ok("oci-release-build-v1"),
        _ => Err(WorkflowLauncherError::UnsupportedLease),
    }
}

fn cpu_quota(millicores: u32) -> String {
    let whole = millicores / 10;
    let fractional = millicores % 10;
    if fractional == 0 {
        format!("{whole}%")
    } else {
        format!("{whole}.{fractional}%")
    }
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, WorkflowLauncherError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WorkflowLauncherError::InvalidPublicKey)?;
    let bytes: [u8; ED25519_KEY_BYTES] = decoded
        .try_into()
        .map_err(|_| WorkflowLauncherError::InvalidPublicKey)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(WorkflowLauncherError::InvalidPublicKey);
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| WorkflowLauncherError::InvalidPublicKey)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLauncherError {
    #[error("unsupported workflow launcher policy schema version {0}")]
    UnsupportedPolicyVersion(u16),
    #[error("workflow launcher policy is invalid")]
    InvalidPolicy,
    #[error("workflow launcher policy is not a root-owned private regular file")]
    UnsafePolicy,
    #[error("workflow launcher policy changed while being read")]
    PolicyChanged,
    #[error("workflow launcher policy is not canonical JCS")]
    NoncanonicalPolicy,
    #[error("workflow launcher verification key is not canonical unpadded base64url")]
    InvalidPublicKey,
    #[error("workflow launcher does not support this lease boundary")]
    UnsupportedLease,
    #[error("workflow launcher policy I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("workflow launcher policy JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("workflow launcher grant verification failed: {0}")]
    Grant(#[from] WorkflowExecutionGrantError),
    #[error("workflow launcher lease contract failed: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("workflow launcher prepared input failed validation: {0}")]
    Preparation(#[from] PreparationStoreError),
    #[error("workflow launcher prepared input does not match the installed workflow policy")]
    PreparedRunMismatch,
}

pub fn installed_preparation_reader(
    worker_uid: u32,
) -> Result<PreparationStoreReaderV1, WorkflowLauncherError> {
    Ok(PreparationStoreReaderV1::open(
        PREPARATION_STORE_ROOT,
        worker_uid,
    )?)
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc::{self, Receiver, Sender},
        },
        time::Duration,
    };

    use ed25519_dalek::SigningKey;
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{
        domain::{GitCommitId, ProjectManifestV2, WorkflowLeaseInputV1, WorkflowNodeKindV1},
        operation_state::{
            WorkflowOperationStateAcquisitionV1, WorkflowOperationStateDispositionV1,
            WorkflowOperationStateManagerV1, WorkflowOperationStateOutcomeV1,
            WorkflowOperationStateReleaseV1,
        },
        preparation::{
            PREPARED_RUN_COMPOSITION_FILE, PREPARED_RUN_SOURCE_DIRECTORY, PreparationKeyMaterialV1,
            PreparationStore, PreparedRunCompositionV1, open_test_preparation_store,
        },
        workflow_execution_grant::WorkflowExecutionGrantSignerV1,
    };

    struct LauncherFixture {
        _directory: TempDir,
        _store: PreparationStore,
        reader: PreparationStoreReaderV1,
        policy: WorkflowLauncherPolicyV1,
        lease: WorkflowLeaseV1,
        signer: WorkflowExecutionGrantSignerV1,
        operation_states: Arc<TestOperationStates>,
        journal_root: PathBuf,
        owner_uid: u32,
    }

    fn fixture() -> LauncherFixture {
        fixture_with_composition_policy_mismatch(false)
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_with_composition_policy_mismatch(mismatched: bool) -> LauncherFixture {
        let directory = tempdir().expect("temporary directory");
        let preparation_root = directory.path().join("preparation");
        fs::create_dir(&preparation_root).expect("create preparation root");
        fs::set_permissions(&preparation_root, fs::Permissions::from_mode(0o700))
            .expect("protect preparation root");
        let owner_uid = fs::metadata(&preparation_root)
            .expect("preparation metadata")
            .uid();
        assert_ne!(
            owner_uid, 0,
            "tests require an unprivileged workspace owner"
        );
        let store = open_test_preparation_store(&preparation_root, owner_uid, 32 * 1024 * 1024)
            .expect("open preparation store");
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("manifest");
        let workflow_policy_digest = manifest.workflow_policy_digest().expect("workflow policy");
        let dependency_input = directory.path().join("dependency-input");
        fs::create_dir(&dependency_input).expect("create dependency input");
        fs::write(dependency_input.join("source-tree.jcs"), b"{}")
            .expect("write dependency marker");
        let dependency_material = PreparationKeyMaterialV1::DependencySnapshot {
            toolchain_digest: EvidenceDigest::sha256("source-tree toolchain"),
            lockfile_digest: EvidenceDigest::sha256("source-tree lockfile"),
            platform: "linux-x86_64".to_owned(),
            workflow_policy_digest: workflow_policy_digest.clone(),
        };
        let dependency = store
            .get_or_prepare_directory(&dependency_material, 99, || {
                Ok::<_, io::Error>(dependency_input.clone())
            })
            .expect("publish dependency snapshot");
        let input = directory.path().join("prepared-input");
        fs::create_dir(&input).expect("create prepared input");
        let source_input = input.join(PREPARED_RUN_SOURCE_DIRECTORY);
        fs::create_dir(&source_input).expect("create prepared source input");
        fs::create_dir(source_input.join("bin")).expect("create bin directory");
        fs::write(source_input.join("bin/ci"), b"#!/bin/sh\nexit 0\n").expect("write bin/ci");
        fs::set_permissions(
            source_input.join("bin/ci"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("make bin/ci executable");
        fs::write(source_input.join("Cargo.lock"), b"# exact input\n").expect("write lockfile");
        let material = PreparationKeyMaterialV1::PreparedRun {
            source_snapshot_key: EvidenceDigest::sha256("source"),
            dependency_snapshot_key: dependency.manifest.key.clone(),
            workflow_policy_digest: if mismatched {
                EvidenceDigest::sha256("other installed workflow policy")
            } else {
                workflow_policy_digest.clone()
            },
            generated_input_digest: EvidenceDigest::sha256("generated input"),
        };
        fs::write(
            input.join(PREPARED_RUN_COMPOSITION_FILE),
            PreparedRunCompositionV1::new(&material)
                .expect("prepared composition")
                .canonical_bytes()
                .expect("canonical prepared composition"),
        )
        .expect("write prepared composition");
        let prepared = store
            .get_or_prepare_directory(&material, 100, || Ok::<_, io::Error>(input.clone()))
            .expect("publish prepared run");
        let reader = PreparationStoreReaderV1::open(&preparation_root, owner_uid)
            .expect("open preparation reader");

        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::Verification)
            .expect("verification node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("verification profile");
        let attempt_id = Uuid::from_u128(13);
        let source_sha = GitCommitId::from_str(&"a".repeat(40)).expect("source SHA");
        let preparation_key = EvidenceDigest::sha256("preparation key");
        let operation_state = crate::domain::WorkflowOperationStateV1::new(
            attempt_id,
            &manifest.project_id,
            &source_sha,
            &workflow_policy_digest,
            &preparation_key,
            "shared-vps-worker",
            "production-vps",
            vec![node.node_id.clone()],
            6 * 1024 * 1024 * 1024,
            500_000,
        )
        .expect("operation state");
        let lease = WorkflowLeaseV1::new(
            Uuid::from_u128(11),
            1,
            Uuid::from_u128(12),
            attempt_id,
            manifest.project_id.clone(),
            source_sha,
            7,
            EvidenceDigest::sha256("source attestation"),
            workflow_policy_digest,
            preparation_key,
            node,
            profile,
            None,
            vec![WorkflowLeaseInputV1 {
                node_id: "prepare".parse().expect("prepare node ID"),
                artifact_kind: WorkflowArtifactKindV1::PreparedRun,
                output_digest: prepared.manifest.key.clone(),
            }],
            EvidenceDigest::sha256("expected input"),
            "shared-vps-worker".to_owned(),
            "production-vps".to_owned(),
            100,
            15_100,
        )
        .and_then(|lease| lease.with_operation_state(operation_state))
        .expect("verification lease");
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let signer = WorkflowExecutionGrantSignerV1::new(
            "workflow-gateway",
            "workflow-launcher",
            "workflow-key-1",
            1,
            signing_key.clone(),
        )
        .expect("grant signer");
        let policy = WorkflowLauncherPolicyV1 {
            schema_version: WORKFLOW_LAUNCHER_POLICY_SCHEMA_VERSION,
            worker_uid: owner_uid,
            build_uid: owner_uid.checked_add(1).expect("build UID"),
            build_gid: owner_uid.checked_add(1).expect("build GID"),
            worker_id: "shared-vps-worker".to_owned(),
            host_id: "production-vps".to_owned(),
            grant_issuer: "workflow-gateway".to_owned(),
            launcher_audience: "workflow-launcher".to_owned(),
            minimum_grant_key_epoch: 1,
            grant_verification_keys: vec![WorkflowLauncherVerificationKeyConfigV1 {
                key_id: "workflow-key-1".to_owned(),
                key_epoch: 1,
                public_key_base64url: URL_SAFE_NO_PAD
                    .encode(signing_key.verifying_key().as_bytes()),
                active_from_ms: 0,
                signing_retired_at_ms: None,
                verify_until_ms: None,
                revoked_at_ms: None,
            }],
            allowed_adapters: vec![WorkflowAdapterIdV1::WorkerBareBinCiV1],
            rootless_oci: None,
            max_concurrent_jobs: 1,
            max_journal_records: 64,
        };
        policy.validate().expect("launcher policy");
        let journal_root = directory.path().join("journal");
        fs::create_dir(&journal_root).expect("create journal root");
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))
            .expect("protect journal root");
        LauncherFixture {
            _directory: directory,
            _store: store,
            reader,
            policy,
            lease,
            signer,
            operation_states: Arc::new(TestOperationStates::default()),
            journal_root,
            owner_uid,
        }
    }

    #[derive(Debug, Default)]
    struct TestOperationStates {
        acquire_calls: AtomicUsize,
        release_calls: AtomicUsize,
    }

    impl TestOperationStates {
        fn counts(&self) -> (usize, usize) {
            (
                self.acquire_calls.load(Ordering::SeqCst),
                self.release_calls.load(Ordering::SeqCst),
            )
        }
    }

    impl WorkflowOperationStateManagerV1 for TestOperationStates {
        fn acquire(
            &self,
            lease: &WorkflowLeaseV1,
            _now_ms: i64,
        ) -> Result<WorkflowOperationStateAcquisitionV1, WorkflowOperationStateError> {
            self.acquire_calls.fetch_add(1, Ordering::SeqCst);
            let state = lease
                .operation_state
                .as_ref()
                .ok_or(WorkflowOperationStateError::MissingStateContract)?;
            Ok(WorkflowOperationStateAcquisitionV1 {
                data_path: Path::new(WORKFLOW_OPERATION_STATE_ROOT)
                    .join(state.state_key.as_str())
                    .join("data"),
                state_key: state.state_key.clone(),
                record_digest: EvidenceDigest::sha256("acquired operation state"),
            })
        }

        fn release(
            &self,
            lease: &WorkflowLeaseV1,
            outcome: WorkflowOperationStateOutcomeV1,
            completed_at_ms: i64,
        ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError> {
            self.release_calls.fetch_add(1, Ordering::SeqCst);
            let (disposition, reusable) = match outcome {
                WorkflowOperationStateOutcomeV1::Succeeded => (
                    WorkflowOperationStateDispositionV1::RemovedAfterSuccess,
                    true,
                ),
                WorkflowOperationStateOutcomeV1::Failed => (
                    WorkflowOperationStateDispositionV1::RemovedAfterFailure,
                    false,
                ),
                WorkflowOperationStateOutcomeV1::Unknown => {
                    (WorkflowOperationStateDispositionV1::Reset, false)
                }
            };
            WorkflowOperationStateReleaseV1::from_manager(
                lease,
                disposition,
                reusable,
                0,
                0,
                completed_at_ms,
                Some(EvidenceDigest::sha256("released operation state")),
            )
        }
    }

    #[derive(Debug)]
    struct ControlledRuntime {
        receiver: Mutex<Option<Receiver<WorkflowProcessExitV1>>>,
        spawn_count: AtomicUsize,
        terminate_count: AtomicUsize,
    }

    impl WorkflowLaunchRuntimeV1 for ControlledRuntime {
        fn spawn(
            &self,
            _launch: &AuthorizedWorkflowLaunchV1,
        ) -> Result<Box<dyn WorkflowLaunchProcessV1>, WorkflowLaunchRuntimeError> {
            self.spawn_count.fetch_add(1, Ordering::SeqCst);
            let receiver = self
                .receiver
                .lock()
                .expect("runtime receiver lock")
                .take()
                .ok_or_else(|| {
                    WorkflowLaunchRuntimeError::Spawn(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "duplicate spawn",
                    ))
                })?;
            Ok(Box::new(ControlledProcess { receiver }))
        }

        fn terminate(&self, _unit_name: &str) -> Result<bool, WorkflowLaunchRuntimeError> {
            self.terminate_count.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    struct ControlledProcess {
        receiver: Receiver<WorkflowProcessExitV1>,
    }

    impl WorkflowLaunchProcessV1 for ControlledProcess {
        fn wait(self: Box<Self>) -> Result<WorkflowProcessExitV1, WorkflowLaunchRuntimeError> {
            self.receiver.recv().map_err(|_| {
                WorkflowLaunchRuntimeError::Wait(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "test process disconnected",
                ))
            })
        }

        fn abort(self: Box<Self>) -> Result<(), WorkflowLaunchRuntimeError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct JournalFailureRuntime {
        record_path: PathBuf,
        receiver: Mutex<Option<Receiver<WorkflowProcessExitV1>>>,
        exit_sender: Sender<WorkflowProcessExitV1>,
        spawn_count: AtomicUsize,
        terminate_count: AtomicUsize,
        wait_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
    }

    impl WorkflowLaunchRuntimeV1 for JournalFailureRuntime {
        fn spawn(
            &self,
            _launch: &AuthorizedWorkflowLaunchV1,
        ) -> Result<Box<dyn WorkflowLaunchProcessV1>, WorkflowLaunchRuntimeError> {
            self.spawn_count.fetch_add(1, Ordering::SeqCst);
            fs::remove_file(&self.record_path).map_err(WorkflowLaunchRuntimeError::Spawn)?;
            let receiver = self
                .receiver
                .lock()
                .expect("journal-failure receiver lock")
                .take()
                .ok_or_else(|| {
                    WorkflowLaunchRuntimeError::Spawn(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "duplicate injected process",
                    ))
                })?;
            Ok(Box::new(JournalFailureProcess {
                receiver,
                wait_count: self.wait_count.clone(),
                abort_count: self.abort_count.clone(),
            }))
        }

        fn terminate(&self, _unit_name: &str) -> Result<bool, WorkflowLaunchRuntimeError> {
            self.terminate_count.fetch_add(1, Ordering::SeqCst);
            let _ = self.exit_sender.send(WorkflowProcessExitV1 {
                exit_code: None,
                signal: Some(15),
            });
            Ok(true)
        }
    }

    struct JournalFailureProcess {
        receiver: Receiver<WorkflowProcessExitV1>,
        wait_count: Arc<AtomicUsize>,
        abort_count: Arc<AtomicUsize>,
    }

    impl WorkflowLaunchProcessV1 for JournalFailureProcess {
        fn wait(self: Box<Self>) -> Result<WorkflowProcessExitV1, WorkflowLaunchRuntimeError> {
            let exit = self.receiver.recv().map_err(|_| {
                WorkflowLaunchRuntimeError::Wait(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected process disconnected",
                ))
            })?;
            self.wait_count.fetch_add(1, Ordering::SeqCst);
            Ok(exit)
        }

        fn abort(self: Box<Self>) -> Result<(), WorkflowLaunchRuntimeError> {
            self.abort_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn runtime() -> (Arc<ControlledRuntime>, Sender<WorkflowProcessExitV1>) {
        let (sender, receiver) = mpsc::channel();
        (
            Arc::new(ControlledRuntime {
                receiver: Mutex::new(Some(receiver)),
                spawn_count: AtomicUsize::new(0),
                terminate_count: AtomicUsize::new(0),
            }),
            sender,
        )
    }

    fn assert_rootless_oci_policy_coupling(fixture: &LauncherFixture) {
        let canonical_policy = fixture.policy.canonical_bytes().expect("canonical policy");
        assert_eq!(
            WorkflowLauncherPolicyV1::decode_canonical(&canonical_policy)
                .expect("decode canonical policy"),
            fixture.policy
        );
        let mut duplicate_adapter_policy = fixture.policy.clone();
        duplicate_adapter_policy
            .allowed_adapters
            .push(WorkflowAdapterIdV1::WorkerBareBinCiV1);
        assert!(matches!(
            duplicate_adapter_policy.validate(),
            Err(WorkflowLauncherError::InvalidPolicy)
        ));
        let mut unproven_oci_policy = fixture.policy.clone();
        unproven_oci_policy.allowed_adapters = vec![WorkflowAdapterIdV1::WorkerOciReleaseBuildV1];
        assert!(matches!(
            unproven_oci_policy.validate(),
            Err(WorkflowLauncherError::InvalidPolicy)
        ));
        unproven_oci_policy.rootless_oci = Some(RootlessOciRuntimePolicyV1 {
            schema_version: crate::rootless_oci::ROOTLESS_OCI_POLICY_SCHEMA_VERSION,
            daemon_uid: fixture
                .policy
                .build_uid
                .checked_add(1)
                .expect("BuildKit UID"),
            daemon_user: "rdashboard-buildkit".to_owned(),
            buildkitd_sha256: EvidenceDigest::sha256("buildkitd"),
            buildctl_sha256: EvidenceDigest::sha256("buildctl"),
            rootlesskit_sha256: EvidenceDigest::sha256("rootlesskit"),
            runtime_sha256: EvidenceDigest::sha256("runc"),
            buildkit_config_sha256: EvidenceDigest::sha256("buildkitd.toml"),
            max_parallelism: 1,
        });
        unproven_oci_policy
            .validate()
            .expect("OCI policy with an exact rootless runtime contract");
    }

    #[test]
    fn authorization_binds_the_exact_grant_input_and_fixed_sandbox() {
        let fixture = fixture();
        assert_rootless_oci_policy_coupling(&fixture);
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(21))
            .expect("execution grant");
        let launch = AuthorizedWorkflowLaunchV1::authorize(
            &fixture.policy,
            &fixture.reader,
            &fixture.lease,
            &grant,
            101,
        )
        .expect("authorize fixed launch");
        assert_eq!(launch.executable, SYSTEMD_RUN_EXECUTABLE);
        assert_eq!(launch.unit_name, unit_name(&fixture.lease));
        assert!(
            launch
                .arguments
                .iter()
                .any(|argument| argument == "--property=PrivateNetwork=yes")
        );
        assert!(launch.arguments.iter().any(|argument| {
            argument.starts_with("--property=InaccessiblePaths=")
                && argument.split_ascii_whitespace().any(|path| path == "/run")
        }));
        assert!(launch.arguments.iter().any(|argument| {
            argument.starts_with("--property=BindReadOnlyPaths=")
                && argument.ends_with(":/prepared")
        }));
        assert!(launch.arguments.iter().any(|argument| {
            argument.starts_with("--property=BindReadOnlyPaths=")
                && argument.ends_with(":/dependencies")
        }));
        assert!(launch.arguments.iter().any(|argument| {
            argument.starts_with("--property=BindPaths=") && argument.ends_with(":/operation")
        }));
        assert!(
            launch
                .arguments
                .iter()
                .any(|argument| argument == "--working-directory=/job")
        );
        assert!(launch.arguments.iter().any(|argument| {
            argument.starts_with("--property=TemporaryFileSystem=/job:")
                && argument.contains("rw,nodev,nosuid,size=")
                && !argument.contains("noexec")
                && argument.contains("size=")
                && argument.contains("nr_inodes=")
        }));
        let separator = launch
            .arguments
            .iter()
            .position(|argument| argument == "--")
            .expect("systemd-run separator");
        assert_eq!(
            &launch.arguments[separator + 1..],
            [
                ENV_EXECUTABLE,
                "-i",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "HOME=/nonexistent",
                "TMPDIR=/job/tmp",
                "CARGO_HOME=/job/cargo-home",
                "CARGO_NET_OFFLINE=true",
                "CARGO_TARGET_DIR=/operation/target",
                "CCACHE_DIR=/operation/ccache",
                "CCACHE_TEMPDIR=/job/ccache-tmp",
                "RDASHBOARD_PREPARED_ROOT=/prepared",
                "RDASHBOARD_DEPENDENCY_ROOT=/dependencies",
                "RDASHBOARD_OPERATION_ROOT=/operation",
                WORKFLOW_JOB_EXECUTABLE,
                "bare-bin-ci-v1",
            ]
        );

        let mut mismatched = fixture.lease.clone();
        mismatched.host_id = "other-vps".to_owned();
        assert!(matches!(
            AuthorizedWorkflowLaunchV1::authorize(
                &fixture.policy,
                &fixture.reader,
                &mismatched,
                &grant,
                101,
            ),
            Err(WorkflowLauncherError::Workflow(_) | WorkflowLauncherError::UnsupportedLease)
        ));
    }

    #[test]
    fn authorization_rejects_a_prepared_run_from_another_workflow_policy() {
        let fixture = fixture_with_composition_policy_mismatch(true);
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(22))
            .expect("execution grant");

        assert!(matches!(
            AuthorizedWorkflowLaunchV1::authorize(
                &fixture.policy,
                &fixture.reader,
                &fixture.lease,
                &grant,
                101,
            ),
            Err(WorkflowLauncherError::PreparedRunMismatch)
        ));
    }

    #[test]
    fn waiter_failure_precedes_any_runtime_effect() {
        let fixture = fixture();
        let journal = WorkflowLaunchJournalV1::open(
            &fixture.journal_root,
            fixture.owner_uid,
            fixture.policy.max_journal_records,
            100,
        )
        .expect("open journal");
        let (runtime, _exit_sender) = runtime();
        let supervisor = WorkflowLaunchSupervisorV1::new(
            fixture.policy.clone(),
            fixture.reader.clone(),
            journal,
            fixture.operation_states.clone(),
            runtime.clone(),
        )
        .expect("supervisor");
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(26))
            .expect("grant");

        let status = supervisor
            .launch_with_waiter(&fixture.lease, &grant, 101, |_name, _task| {
                Err(io::Error::other("injected waiter exhaustion"))
            })
            .expect("record waiter failure");

        assert_eq!(status.state, WorkflowLaunchStateV1::Failed);
        assert_eq!(
            status.terminal.expect("terminal evidence").kind,
            WorkflowLaunchTerminalKindV1::SpawnRejected
        );
        assert_eq!(runtime.spawn_count.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.terminate_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn journal_failure_after_spawn_stops_unit_and_reaps_process() {
        let fixture = fixture();
        let journal = WorkflowLaunchJournalV1::open(
            &fixture.journal_root,
            fixture.owner_uid,
            fixture.policy.max_journal_records,
            100,
        )
        .expect("open journal");
        let record_path = fixture
            .journal_root
            .join(job_directory_name(
                fixture.lease.lease_id,
                fixture.lease.lease_generation,
            ))
            .join(WORKFLOW_LAUNCH_RECORD_FILE);
        let (exit_sender, receiver) = mpsc::channel();
        let runtime = Arc::new(JournalFailureRuntime {
            record_path,
            receiver: Mutex::new(Some(receiver)),
            exit_sender,
            spawn_count: AtomicUsize::new(0),
            terminate_count: AtomicUsize::new(0),
            wait_count: Arc::new(AtomicUsize::new(0)),
            abort_count: Arc::new(AtomicUsize::new(0)),
        });
        let supervisor = WorkflowLaunchSupervisorV1::new(
            fixture.policy.clone(),
            fixture.reader.clone(),
            journal,
            fixture.operation_states.clone(),
            runtime.clone(),
        )
        .expect("supervisor");
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(27))
            .expect("grant");

        assert!(matches!(
            supervisor.launch(&fixture.lease, &grant, 101),
            Err(WorkflowLaunchSupervisorError::Journal(
                WorkflowLaunchJournalError::Io(_)
            ))
        ));
        assert_eq!(runtime.spawn_count.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.terminate_count.load(Ordering::SeqCst), 1);
        for _ in 0..100 {
            if runtime.wait_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(runtime.wait_count.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.abort_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn renewed_replay_never_spawns_twice_and_cleanup_is_idempotent() {
        let fixture = fixture();
        let journal = WorkflowLaunchJournalV1::open(
            &fixture.journal_root,
            fixture.owner_uid,
            fixture.policy.max_journal_records,
            100,
        )
        .expect("open journal");
        let (runtime, exit_sender) = runtime();
        let supervisor = WorkflowLaunchSupervisorV1::new(
            fixture.policy.clone(),
            fixture.reader.clone(),
            journal,
            fixture.operation_states.clone(),
            runtime.clone(),
        )
        .expect("supervisor");
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(22))
            .expect("grant");
        let running = supervisor
            .launch(&fixture.lease, &grant, 101)
            .expect("launch");
        assert_eq!(running.state, WorkflowLaunchStateV1::Running);
        assert_eq!(runtime.spawn_count.load(Ordering::SeqCst), 1);

        let renewed = fixture.lease.renewed(20_000).expect("renew lease");
        let renewed_grant = fixture
            .signer
            .issue(&renewed, 102, Uuid::from_u128(23))
            .expect("renewed grant");
        let replay = supervisor
            .launch(&renewed, &renewed_grant, 102)
            .expect("replay launch");
        assert_eq!(replay.state, WorkflowLaunchStateV1::Running);
        assert_eq!(replay.lease_digest, renewed.lease_digest);
        assert_eq!(runtime.spawn_count.load(Ordering::SeqCst), 1);

        exit_sender
            .send(WorkflowProcessExitV1 {
                exit_code: Some(0),
                signal: None,
            })
            .expect("finish process");
        let completed = wait_for_state(
            &supervisor,
            renewed.lease_id,
            renewed.lease_generation,
            WorkflowLaunchStateV1::Succeeded,
        );
        let terminal_digest = completed
            .terminal
            .as_ref()
            .expect("terminal evidence")
            .evidence_digest
            .clone();
        let cleanup_at_ms = completed
            .terminal
            .as_ref()
            .expect("terminal evidence")
            .completed_at_ms
            .checked_add(1)
            .expect("cleanup time");
        assert!(completed.terminal.expect("terminal evidence").succeeded);

        let later_renewal = renewed.renewed(25_000).expect("later renewal");
        let later_grant = fixture
            .signer
            .issue(&later_renewal, 103, Uuid::from_u128(25))
            .expect("later grant");
        let terminal_replay = supervisor
            .launch(&later_renewal, &later_grant, 103)
            .expect("replay completed launch");
        assert_eq!(terminal_replay.state, WorkflowLaunchStateV1::Succeeded);
        assert_eq!(
            terminal_replay
                .terminal
                .as_ref()
                .expect("replayed terminal")
                .evidence_digest,
            terminal_digest
        );
        assert_eq!(runtime.spawn_count.load(Ordering::SeqCst), 1);

        let cleaned = supervisor
            .cleanup(&later_renewal, cleanup_at_ms)
            .expect("cleanup launch");
        assert_eq!(cleaned.state, WorkflowLaunchStateV1::Cleaned);
        assert_eq!(runtime.terminate_count.load(Ordering::SeqCst), 1);
        let replayed_cleanup = supervisor
            .cleanup(&later_renewal, cleanup_at_ms + 1)
            .expect("replay cleanup");
        assert_eq!(replayed_cleanup, cleaned);
        assert_eq!(runtime.terminate_count.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.operation_states.counts(), (1, 1));
    }

    #[test]
    fn cleanup_remains_authorized_after_an_adapter_is_removed_from_launch_policy() {
        let fixture = fixture();
        let mut rotated_policy = fixture.policy;
        rotated_policy.allowed_adapters = vec![WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1];
        rotated_policy.validate().expect("rotated launcher policy");

        assert!(matches!(
            validate_launcher_lease(&rotated_policy, &fixture.lease),
            Err(WorkflowLauncherError::UnsupportedLease)
        ));
        validate_launcher_cleanup_lease(&rotated_policy, &fixture.lease)
            .expect("an already-owned unit must remain cleanable after policy rotation");
    }

    #[test]
    fn startup_turns_an_ambiguous_running_job_into_cleanup_debt() {
        let fixture = fixture();
        let grant = fixture
            .signer
            .issue(&fixture.lease, 101, Uuid::from_u128(24))
            .expect("grant");
        let launch = AuthorizedWorkflowLaunchV1::authorize(
            &fixture.policy,
            &fixture.reader,
            &fixture.lease,
            &grant,
            101,
        )
        .expect("authorization");
        {
            let journal = WorkflowLaunchJournalV1::open(
                &fixture.journal_root,
                fixture.owner_uid,
                fixture.policy.max_journal_records,
                100,
            )
            .expect("open initial journal");
            let (_, created) = journal
                .accept(&launch, 101, fixture.policy.max_concurrent_jobs)
                .expect("accept launch");
            assert!(created);
            journal
                .mark_running(&fixture.lease, 102)
                .expect("mark running");
        }

        let reopened = WorkflowLaunchJournalV1::open(
            &fixture.journal_root,
            fixture.owner_uid,
            fixture.policy.max_journal_records,
            200,
        )
        .expect("reopen journal");
        let status = reopened
            .observe(fixture.lease.lease_id, fixture.lease.lease_generation)
            .expect("observe reconciled launch")
            .expect("launch record");
        assert_eq!(status.state, WorkflowLaunchStateV1::NeedsReconcile);
    }

    fn wait_for_state(
        supervisor: &WorkflowLaunchSupervisorV1,
        lease_id: Uuid,
        lease_generation: u32,
        expected: WorkflowLaunchStateV1,
    ) -> WorkflowLaunchStatusV1 {
        for _ in 0..100 {
            let status = supervisor
                .observe(lease_id, lease_generation)
                .expect("observe launch")
                .expect("launch record");
            if status.state == expected {
                return status;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("workflow launch did not reach {expected:?}");
    }
}
