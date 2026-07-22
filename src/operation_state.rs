use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    build_storage::{
        SHARED_BUILD_STORAGE_MIN_BYTES, SHARED_BUILD_STORAGE_ROOT, required_host_available_bytes,
    },
    domain::{
        EvidenceDigest, GitCommitId, ProjectId, WorkflowLeaseV1, WorkflowNodeId,
        WorkflowOperationStateV1,
    },
};

pub const WORKFLOW_OPERATION_STATE_ROOT: &str = "/var/lib/rdashboard-build/operations";

const RECORD_FILE: &str = "record.jcs";
const DATA_DIRECTORY: &str = "data";
const RECORD_PURPOSE: &str = "rdashboard.workflow-operation-state-record.v1";
const RELEASE_PURPOSE: &str = "rdashboard.workflow-operation-state-release.v1";
const RECORD_SCHEMA_VERSION: u16 = 1;
const MAX_RECORD_BYTES: u64 = 256 * 1024;
const MAX_RECORDS: usize = 1_024;
const MAX_RETAINED_TERMINAL_RECORDS: usize = 512;
const MAX_INACTIVE_STATE_IDLE_MS: i64 = 60 * 60 * 1_000;
const MAX_OPERATION_STATE_DEPTH: u16 = 64;
const MIN_ADMISSION_INODES: u64 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowOperationStateOutcomeV1 {
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowOperationStateDispositionV1 {
    NotAcquired,
    Retained,
    Reset,
    RemovedAfterSuccess,
    RemovedAfterFailure,
    RemovedAfterLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOperationStateReleaseV1 {
    pub state_key: EvidenceDigest,
    pub disposition: WorkflowOperationStateDispositionV1,
    pub reusable: bool,
    pub allocated_bytes: u64,
    pub inodes: u64,
    pub completed_at_ms: i64,
    pub record_digest: Option<EvidenceDigest>,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct WorkflowOperationStateReleasePayload<'a> {
    purpose: &'static str,
    lease_digest: &'a EvidenceDigest,
    state_key: &'a EvidenceDigest,
    disposition: WorkflowOperationStateDispositionV1,
    reusable: bool,
    allocated_bytes: u64,
    inodes: u64,
    completed_at_ms: i64,
    record_digest: &'a Option<EvidenceDigest>,
}

impl WorkflowOperationStateReleaseV1 {
    pub fn from_manager(
        lease: &WorkflowLeaseV1,
        disposition: WorkflowOperationStateDispositionV1,
        reusable: bool,
        allocated_bytes: u64,
        inodes: u64,
        completed_at_ms: i64,
        record_digest: Option<EvidenceDigest>,
    ) -> Result<Self, WorkflowOperationStateError> {
        Self::new(
            lease,
            disposition,
            reusable,
            StateUsage {
                allocated_bytes,
                inodes,
            },
            completed_at_ms,
            record_digest,
        )
    }

    fn new(
        lease: &WorkflowLeaseV1,
        disposition: WorkflowOperationStateDispositionV1,
        reusable: bool,
        usage: StateUsage,
        completed_at_ms: i64,
        record_digest: Option<EvidenceDigest>,
    ) -> Result<Self, WorkflowOperationStateError> {
        let state = required_state(lease)?;
        let mut release = Self {
            state_key: state.state_key.clone(),
            disposition,
            reusable,
            allocated_bytes: usage.allocated_bytes,
            inodes: usage.inodes,
            completed_at_ms,
            record_digest,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        release.evidence_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&WorkflowOperationStateReleasePayload {
                purpose: RELEASE_PURPOSE,
                lease_digest: &lease.lease_digest,
                state_key: &release.state_key,
                disposition: release.disposition,
                reusable: release.reusable,
                allocated_bytes: release.allocated_bytes,
                inodes: release.inodes,
                completed_at_ms: release.completed_at_ms,
                record_digest: &release.record_digest,
            })?);
        Ok(release)
    }

    pub fn validate_for(&self, lease: &WorkflowLeaseV1) -> Result<(), WorkflowOperationStateError> {
        let state = required_state(lease)?;
        let expected =
            EvidenceDigest::sha256(serde_jcs::to_vec(&WorkflowOperationStateReleasePayload {
                purpose: RELEASE_PURPOSE,
                lease_digest: &lease.lease_digest,
                state_key: &self.state_key,
                disposition: self.disposition,
                reusable: self.reusable,
                allocated_bytes: self.allocated_bytes,
                inodes: self.inodes,
                completed_at_ms: self.completed_at_ms,
                record_digest: &self.record_digest,
            })?);
        if self.state_key != state.state_key
            || self.completed_at_ms < lease.leased_at_ms
            || !release_shape_is_valid(self.disposition, self.reusable)
            || self.evidence_digest != expected
        {
            return Err(WorkflowOperationStateError::InvalidRelease);
        }
        Ok(())
    }
}

fn release_shape_is_valid(
    disposition: WorkflowOperationStateDispositionV1,
    reusable: bool,
) -> bool {
    match disposition {
        WorkflowOperationStateDispositionV1::Retained
        | WorkflowOperationStateDispositionV1::RemovedAfterSuccess => reusable,
        WorkflowOperationStateDispositionV1::NotAcquired
        | WorkflowOperationStateDispositionV1::Reset
        | WorkflowOperationStateDispositionV1::RemovedAfterFailure
        | WorkflowOperationStateDispositionV1::RemovedAfterLimit => !reusable,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowOperationStateAcquisitionV1 {
    pub data_path: PathBuf,
    pub state_key: EvidenceDigest,
    pub record_digest: EvidenceDigest,
}

pub trait WorkflowOperationStateManagerV1: Send + Sync {
    fn acquire(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<WorkflowOperationStateAcquisitionV1, WorkflowOperationStateError>;

    fn release(
        &self,
        lease: &WorkflowLeaseV1,
        outcome: WorkflowOperationStateOutcomeV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveConsumerV1 {
    lease_id: Uuid,
    lease_generation: u32,
    lease_digest: EvidenceDigest,
    node_id: WorkflowNodeId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationStateReleaseRecordV1 {
    consumer: ActiveConsumerV1,
    disposition: WorkflowOperationStateDispositionV1,
    reusable: bool,
    allocated_bytes: u64,
    inodes: u64,
}

impl OperationStateReleaseRecordV1 {
    fn new(
        consumer: ActiveConsumerV1,
        disposition: WorkflowOperationStateDispositionV1,
        reusable: bool,
        usage: StateUsage,
    ) -> Self {
        Self {
            consumer,
            disposition,
            reusable,
            allocated_bytes: usage.allocated_bytes,
            inodes: usage.inodes,
        }
    }

    fn matches(&self, lease: &WorkflowLeaseV1) -> bool {
        self.consumer.matches(lease)
    }

    fn usage(&self) -> StateUsage {
        StateUsage {
            allocated_bytes: self.allocated_bytes,
            inodes: self.inodes,
        }
    }
}

impl ActiveConsumerV1 {
    fn from_lease(lease: &WorkflowLeaseV1) -> Self {
        Self {
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            lease_digest: lease.lease_digest.clone(),
            node_id: lease.node_id.clone(),
        }
    }

    fn matches(&self, lease: &WorkflowLeaseV1) -> bool {
        self.lease_id == lease.lease_id
            && self.lease_generation == lease.lease_generation
            && self.node_id == lease.node_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StateTerminalV1 {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationStateRecordV1 {
    purpose: String,
    schema_version: u16,
    attempt_id: Uuid,
    project_id: ProjectId,
    source_sha: GitCommitId,
    workflow_policy_digest: EvidenceDigest,
    preparation_key: EvidenceDigest,
    worker_id: String,
    host_id: String,
    state: WorkflowOperationStateV1,
    active_consumer: Option<ActiveConsumerV1>,
    last_release: Option<OperationStateReleaseRecordV1>,
    successful_consumers: Vec<WorkflowNodeId>,
    terminal: Option<StateTerminalV1>,
    data_present: bool,
    data_removal_pending: bool,
    created_at_ms: i64,
    updated_at_ms: i64,
    record_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct OperationStateRecordPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    worker_id: &'a str,
    host_id: &'a str,
    state: &'a WorkflowOperationStateV1,
    active_consumer: &'a Option<ActiveConsumerV1>,
    last_release: &'a Option<OperationStateReleaseRecordV1>,
    successful_consumers: &'a [WorkflowNodeId],
    terminal: Option<StateTerminalV1>,
    data_present: bool,
    data_removal_pending: bool,
    created_at_ms: i64,
    updated_at_ms: i64,
}

impl OperationStateRecordV1 {
    fn new(lease: &WorkflowLeaseV1, now_ms: i64) -> Result<Self, WorkflowOperationStateError> {
        let state = required_state(lease)?.clone();
        let mut record = Self {
            purpose: RECORD_PURPOSE.to_owned(),
            schema_version: RECORD_SCHEMA_VERSION,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            source_sha: lease.source_sha.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
            preparation_key: lease.preparation_key.clone(),
            worker_id: lease.worker_id.clone(),
            host_id: lease.host_id.clone(),
            state,
            active_consumer: Some(ActiveConsumerV1::from_lease(lease)),
            last_release: None,
            successful_consumers: Vec::new(),
            terminal: None,
            data_present: true,
            data_removal_pending: false,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            record_digest: EvidenceDigest::sha256([]),
        };
        record.refresh_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), WorkflowOperationStateError> {
        self.state.validate_for(
            self.attempt_id,
            &self.project_id,
            &self.source_sha,
            &self.workflow_policy_digest,
            &self.preparation_key,
            &self.worker_id,
            &self.host_id,
        )?;
        let active_valid = self.active_consumer.as_ref().is_none_or(|consumer| {
            !consumer.lease_id.is_nil()
                && consumer.lease_generation > 0
                && self.state.consumer_nodes.contains(&consumer.node_id)
                && !self.successful_consumers.contains(&consumer.node_id)
        });
        let release_valid = self.last_release.as_ref().is_none_or(|release| {
            self.state
                .consumer_nodes
                .contains(&release.consumer.node_id)
                && !release.consumer.lease_id.is_nil()
                && release.consumer.lease_generation > 0
                && release_shape_is_valid(release.disposition, release.reusable)
                && release.disposition != WorkflowOperationStateDispositionV1::NotAcquired
                && match release.disposition {
                    WorkflowOperationStateDispositionV1::Retained => {
                        self.terminal.is_none()
                            && self.data_present
                            && !self.data_removal_pending
                            && self
                                .successful_consumers
                                .contains(&release.consumer.node_id)
                    }
                    WorkflowOperationStateDispositionV1::Reset => {
                        self.terminal.is_none()
                            && (!self.data_present || self.data_removal_pending)
                            && !self
                                .successful_consumers
                                .contains(&release.consumer.node_id)
                    }
                    WorkflowOperationStateDispositionV1::RemovedAfterSuccess => {
                        self.terminal == Some(StateTerminalV1::Succeeded)
                            && (!self.data_present || self.data_removal_pending)
                    }
                    WorkflowOperationStateDispositionV1::RemovedAfterFailure
                    | WorkflowOperationStateDispositionV1::RemovedAfterLimit => {
                        self.terminal == Some(StateTerminalV1::Failed)
                            && (!self.data_present || self.data_removal_pending)
                    }
                    WorkflowOperationStateDispositionV1::NotAcquired => false,
                }
        });
        if self.purpose != RECORD_PURPOSE
            || self.schema_version != RECORD_SCHEMA_VERSION
            || self.attempt_id.is_nil()
            || self.created_at_ms < 0
            || self.updated_at_ms < self.created_at_ms
            || !active_valid
            || !release_valid
            || self.active_consumer.is_some() && self.last_release.is_some()
            || self.data_removal_pending
                && (!self.data_present
                    || self.active_consumer.is_some()
                    || match self.last_release.as_ref() {
                        Some(release) => matches!(
                            release.disposition,
                            WorkflowOperationStateDispositionV1::NotAcquired
                                | WorkflowOperationStateDispositionV1::Retained
                        ),
                        None => self.terminal != Some(StateTerminalV1::Failed),
                    })
            || !self
                .successful_consumers
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self
                .successful_consumers
                .iter()
                .any(|node| !self.state.consumer_nodes.contains(node))
            || self.terminal.is_some()
                && (self.active_consumer.is_some()
                    || self.data_present && !self.data_removal_pending)
            || self.terminal == Some(StateTerminalV1::Succeeded)
                && self.successful_consumers != self.state.consumer_nodes
            || self.record_digest != self.calculate_digest()?
        {
            return Err(WorkflowOperationStateError::InvalidRecord);
        }
        Ok(())
    }

    fn matches_lease(&self, lease: &WorkflowLeaseV1) -> Result<bool, WorkflowOperationStateError> {
        let state = required_state(lease)?;
        Ok(self.attempt_id == lease.attempt_id
            && self.project_id == lease.project_id
            && self.source_sha == lease.source_sha
            && self.workflow_policy_digest == lease.workflow_policy_digest
            && self.preparation_key == lease.preparation_key
            && self.worker_id == lease.worker_id
            && self.host_id == lease.host_id
            && self.state == *state)
    }

    fn refresh_digest(&mut self) -> Result<(), WorkflowOperationStateError> {
        self.record_digest = self.calculate_digest()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, WorkflowOperationStateError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &OperationStateRecordPayload {
                purpose: RECORD_PURPOSE,
                schema_version: self.schema_version,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                worker_id: &self.worker_id,
                host_id: &self.host_id,
                state: &self.state,
                active_consumer: &self.active_consumer,
                last_release: &self.last_release,
                successful_consumers: &self.successful_consumers,
                terminal: self.terminal,
                data_present: self.data_present,
                data_removal_pending: self.data_removal_pending,
                created_at_ms: self.created_at_ms,
                updated_at_ms: self.updated_at_ms,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowOperationStateError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkflowOperationStateError> {
        let record: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&record)? != bytes {
            return Err(WorkflowOperationStateError::NoncanonicalRecord);
        }
        record.validate()?;
        Ok(record)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StateUsage {
    allocated_bytes: u64,
    inodes: u64,
}

#[derive(Clone, Copy, Debug)]
struct FilesystemBoundarySnapshot {
    shared_storage_domain: bool,
    total_bytes: u64,
    available_bytes: u64,
    host_available_bytes: u64,
    total_inodes: u64,
    available_inodes: u64,
}

#[derive(Clone, Copy)]
enum DataDirectoryAccessV1 {
    Reuse,
    Cleanup,
}

trait FilesystemBoundaryProbe: Send + Sync {
    fn inspect(
        &self,
        root: &File,
    ) -> Result<FilesystemBoundarySnapshot, WorkflowOperationStateError>;
}

#[derive(Debug)]
struct SystemFilesystemBoundaryProbe {
    root: PathBuf,
}

impl FilesystemBoundaryProbe for SystemFilesystemBoundaryProbe {
    fn inspect(
        &self,
        root: &File,
    ) -> Result<FilesystemBoundarySnapshot, WorkflowOperationStateError> {
        let stats = rustix::fs::fstatvfs(root).map_err(io::Error::from)?;
        let fragment_size = if stats.f_frsize == 0 {
            stats.f_bsize
        } else {
            stats.f_frsize
        };
        let shared_root = Path::new(SHARED_BUILD_STORAGE_ROOT);
        let host = fs2::statvfs("/")?;
        let root_metadata = fs::metadata(&self.root)?;
        let shared_metadata = fs::metadata(shared_root)?;
        Ok(FilesystemBoundarySnapshot {
            shared_storage_domain: root_metadata.dev() == shared_metadata.dev(),
            total_bytes: stats.f_blocks.saturating_mul(fragment_size),
            available_bytes: stats.f_bavail.saturating_mul(fragment_size),
            host_available_bytes: host.available_space(),
            total_inodes: stats.f_files,
            available_inodes: stats.f_favail,
        })
    }
}

pub struct WorkflowOperationStateStoreV1 {
    root: PathBuf,
    expected_root_uid: u32,
    build_uid: u32,
    build_gid: u32,
    root_lock: File,
    operation_lock: Mutex<()>,
    probe: Box<dyn FilesystemBoundaryProbe>,
}

impl WorkflowOperationStateStoreV1 {
    pub fn open_installed(
        executor_uid: u32,
        executor_group: u32,
    ) -> Result<Self, WorkflowOperationStateError> {
        let root = PathBuf::from(WORKFLOW_OPERATION_STATE_ROOT);
        Self::open_with_probe(
            root.clone(),
            0,
            executor_uid,
            executor_group,
            Box::new(SystemFilesystemBoundaryProbe { root }),
        )
    }

    fn open_with_probe(
        root: PathBuf,
        expected_root_uid: u32,
        executor_uid: u32,
        executor_group: u32,
        probe: Box<dyn FilesystemBoundaryProbe>,
    ) -> Result<Self, WorkflowOperationStateError> {
        if executor_uid == 0
            || executor_uid == u32::MAX
            || executor_group == 0
            || executor_group == u32::MAX
        {
            return Err(WorkflowOperationStateError::InvalidConfig);
        }
        validate_private_directory(&root, expected_root_uid)?;
        let root_lock = File::open(&root)?;
        root_lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                WorkflowOperationStateError::AlreadyOpen
            } else {
                WorkflowOperationStateError::Io(error)
            }
        })?;
        validate_opened_directory(&root, &root_lock, expected_root_uid)?;
        validate_boundary(probe.inspect(&root_lock)?)?;
        let store = Self {
            root,
            expected_root_uid,
            build_uid: executor_uid,
            build_gid: executor_group,
            root_lock,
            operation_lock: Mutex::new(()),
            probe,
        };
        store.reconcile_startup()?;
        Ok(store)
    }

    pub fn acquire(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<WorkflowOperationStateAcquisitionV1, WorkflowOperationStateError> {
        validate_time(now_ms)?;
        lease.validate()?;
        let state = required_state(lease)?;
        state.validate_for(
            lease.attempt_id,
            &lease.project_id,
            &lease.source_sha,
            &lease.workflow_policy_digest,
            &lease.preparation_key,
            &lease.worker_id,
            &lease.host_id,
        )?;
        let _guard = self.lock()?;
        self.revalidate()?;
        self.reconcile_inactive_records(now_ms)?;
        let capacity = self.probe.inspect(&self.root_lock)?;
        validate_boundary(capacity)?;
        let required_bytes = required_host_available_bytes(state.max_bytes)
            .ok_or(WorkflowOperationStateError::FilesystemCapacityExceeded)?;
        if capacity.available_bytes < state.max_bytes
            || capacity.host_available_bytes < required_bytes
            || capacity.available_inodes < MIN_ADMISSION_INODES.max(state.max_inodes)
        {
            return Err(WorkflowOperationStateError::FilesystemCapacityExceeded);
        }
        let directory = self.root.join(state.state_key.as_str());
        let mut record = if directory.try_exists()? {
            self.load_record(&directory, DataDirectoryAccessV1::Reuse)?
        } else {
            self.create_record_directory(lease, now_ms)?
        };
        if !record.matches_lease(lease)? {
            return Err(WorkflowOperationStateError::IdentityConflict);
        }
        if record.terminal.is_some() {
            return Err(WorkflowOperationStateError::TerminalState);
        }
        if let Some(active) = &record.active_consumer {
            if !active.matches(lease) {
                return Err(WorkflowOperationStateError::Busy);
            }
        } else {
            if record.successful_consumers.contains(&lease.node_id) {
                return Err(WorkflowOperationStateError::ConsumerAlreadyCompleted);
            }
            if !record.data_present {
                self.create_data_directory(&directory.join(DATA_DIRECTORY))?;
                record.data_present = true;
            }
            record.last_release = None;
            record.active_consumer = Some(ActiveConsumerV1::from_lease(lease));
            record.updated_at_ms = now_ms.max(record.updated_at_ms);
            record.refresh_digest()?;
            self.write_record(&directory, &record)?;
        }
        let data_path = directory.join(DATA_DIRECTORY);
        validate_data_directory(&data_path, self.build_uid, self.build_gid)?;
        let usage = inspect_usage(&data_path)?;
        if usage.allocated_bytes > state.max_bytes || usage.inodes > state.max_inodes {
            return Err(WorkflowOperationStateError::StateLimitExceeded);
        }
        Ok(WorkflowOperationStateAcquisitionV1 {
            data_path,
            state_key: state.state_key.clone(),
            record_digest: record.record_digest,
        })
    }

    pub fn release(
        &self,
        lease: &WorkflowLeaseV1,
        outcome: WorkflowOperationStateOutcomeV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError> {
        validate_time(completed_at_ms)?;
        lease.validate()?;
        let state = required_state(lease)?;
        let _guard = self.lock()?;
        self.revalidate()?;
        validate_boundary(self.probe.inspect(&self.root_lock)?)?;
        let directory = self.root.join(state.state_key.as_str());
        if !directory.try_exists()? {
            return WorkflowOperationStateReleaseV1::new(
                lease,
                WorkflowOperationStateDispositionV1::NotAcquired,
                false,
                StateUsage::default(),
                completed_at_ms,
                None,
            );
        }
        let mut record = self.load_record(&directory, DataDirectoryAccessV1::Cleanup)?;
        if !record.matches_lease(lease)? {
            return Err(WorkflowOperationStateError::IdentityConflict);
        }
        Self::remove_unrecorded_data_directory(&directory, &record)?;
        self.finish_pending_data_removal(&directory, &mut record)?;
        if let Some(active) = &record.active_consumer {
            if !active.matches(lease) {
                return Err(WorkflowOperationStateError::Busy);
            }
        } else if record
            .last_release
            .as_ref()
            .is_some_and(|release| release.matches(lease))
            || record.terminal.is_some()
            || record.successful_consumers.contains(&lease.node_id)
        {
            return Self::replayed_release(lease, &record, completed_at_ms);
        } else {
            return WorkflowOperationStateReleaseV1::new(
                lease,
                WorkflowOperationStateDispositionV1::NotAcquired,
                false,
                StateUsage::default(),
                completed_at_ms,
                Some(record.record_digest),
            );
        }

        self.complete_active_release(lease, state, &directory, record, outcome, completed_at_ms)
    }

    fn complete_active_release(
        &self,
        lease: &WorkflowLeaseV1,
        state: &WorkflowOperationStateV1,
        directory: &Path,
        mut record: OperationStateRecordV1,
        outcome: WorkflowOperationStateOutcomeV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError> {
        let data_path = directory.join(DATA_DIRECTORY);
        let usage = if record.data_present {
            inspect_usage(&data_path)?
        } else {
            StateUsage::default()
        };
        let consumer = record
            .active_consumer
            .take()
            .ok_or(WorkflowOperationStateError::InvalidRecord)?;
        let over_limit = usage.allocated_bytes > state.max_bytes || usage.inodes > state.max_inodes;
        let (disposition, reusable, remove_data) = if over_limit {
            record.terminal = Some(StateTerminalV1::Failed);
            (
                WorkflowOperationStateDispositionV1::RemovedAfterLimit,
                false,
                true,
            )
        } else {
            match outcome {
                WorkflowOperationStateOutcomeV1::Succeeded => {
                    record.successful_consumers.push(lease.node_id.clone());
                    record.successful_consumers.sort();
                    if record.successful_consumers == state.consumer_nodes {
                        record.terminal = Some(StateTerminalV1::Succeeded);
                        (
                            WorkflowOperationStateDispositionV1::RemovedAfterSuccess,
                            true,
                            true,
                        )
                    } else {
                        (WorkflowOperationStateDispositionV1::Retained, true, false)
                    }
                }
                WorkflowOperationStateOutcomeV1::Failed => {
                    record.terminal = Some(StateTerminalV1::Failed);
                    (
                        WorkflowOperationStateDispositionV1::RemovedAfterFailure,
                        false,
                        true,
                    )
                }
                WorkflowOperationStateOutcomeV1::Unknown => {
                    (WorkflowOperationStateDispositionV1::Reset, false, true)
                }
            }
        };
        record.last_release = Some(OperationStateReleaseRecordV1::new(
            consumer,
            disposition,
            reusable,
            usage,
        ));
        record.updated_at_ms = completed_at_ms.max(record.updated_at_ms);
        if remove_data && record.data_present {
            record.data_removal_pending = true;
            record.refresh_digest()?;
            self.write_record(directory, &record)?;
            if data_path.try_exists()? {
                remove_tree(&data_path)?;
            }
            record.data_present = false;
            record.data_removal_pending = false;
        }
        record.refresh_digest()?;
        self.write_record(directory, &record)?;
        WorkflowOperationStateReleaseV1::new(
            lease,
            disposition,
            reusable,
            usage,
            completed_at_ms,
            Some(record.record_digest),
        )
    }

    fn replayed_release(
        lease: &WorkflowLeaseV1,
        record: &OperationStateRecordV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError> {
        if let Some(release) = record
            .last_release
            .as_ref()
            .filter(|release| release.matches(lease))
        {
            return WorkflowOperationStateReleaseV1::new(
                lease,
                release.disposition,
                release.reusable,
                release.usage(),
                completed_at_ms,
                Some(record.record_digest.clone()),
            );
        }
        let (disposition, reusable) = match record.terminal {
            Some(StateTerminalV1::Succeeded) => (
                WorkflowOperationStateDispositionV1::RemovedAfterSuccess,
                true,
            ),
            Some(StateTerminalV1::Failed) => (
                WorkflowOperationStateDispositionV1::RemovedAfterFailure,
                false,
            ),
            None if record.successful_consumers.contains(&lease.node_id) => {
                (WorkflowOperationStateDispositionV1::Retained, true)
            }
            None => return Err(WorkflowOperationStateError::InvalidRecord),
        };
        WorkflowOperationStateReleaseV1::new(
            lease,
            disposition,
            reusable,
            StateUsage::default(),
            completed_at_ms,
            Some(record.record_digest.clone()),
        )
    }

    fn create_record_directory(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<OperationStateRecordV1, WorkflowOperationStateError> {
        let state = required_state(lease)?;
        if self.record_count()? >= MAX_RECORDS {
            self.prune_terminal_records(MAX_RETAINED_TERMINAL_RECORDS)?;
            if self.record_count()? >= MAX_RECORDS {
                return Err(WorkflowOperationStateError::RecordCapacityExceeded);
            }
        }
        let staging_directory = self
            .root
            .join(format!(".staging-{}", Uuid::new_v4().simple()));
        create_private_directory(&staging_directory)?;
        let result = (|| {
            self.create_data_directory(&staging_directory.join(DATA_DIRECTORY))?;
            let record = OperationStateRecordV1::new(lease, now_ms)?;
            write_new_file(
                &staging_directory.join(RECORD_FILE),
                &record.canonical_bytes()?,
                self.expected_root_uid,
            )?;
            File::open(&staging_directory)?.sync_all()?;
            let destination = self.root.join(state.state_key.as_str());
            fs::rename(&staging_directory, &destination)?;
            self.root_lock.sync_all()?;
            Ok(record)
        })();
        if result.is_err() && staging_directory.try_exists().unwrap_or(false) {
            let _ = remove_tree(&staging_directory);
        }
        result
    }

    fn create_data_directory(&self, path: &Path) -> Result<(), WorkflowOperationStateError> {
        create_private_directory(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        std::os::unix::fs::chown(path, Some(self.build_uid), Some(self.build_gid))?;
        validate_data_directory(path, self.build_uid, self.build_gid)
    }

    fn load_record(
        &self,
        directory: &Path,
        data_access: DataDirectoryAccessV1,
    ) -> Result<OperationStateRecordV1, WorkflowOperationStateError> {
        validate_private_directory(directory, self.expected_root_uid)?;
        let bytes = read_stable_file(
            &directory.join(RECORD_FILE),
            self.expected_root_uid,
            MAX_RECORD_BYTES,
        )?;
        let record = OperationStateRecordV1::decode_canonical(&bytes)?;
        if directory.file_name() != Some(OsStr::new(record.state.state_key.as_str())) {
            return Err(WorkflowOperationStateError::InvalidRecord);
        }
        let data = directory.join(DATA_DIRECTORY);
        if record.data_present {
            if data.try_exists()? {
                match data_access {
                    DataDirectoryAccessV1::Reuse => {
                        validate_data_directory(&data, self.build_uid, self.build_gid)?;
                    }
                    DataDirectoryAccessV1::Cleanup => {
                        validate_cleanup_data_directory(
                            &data,
                            self.build_uid,
                            self.expected_root_uid,
                        )?;
                    }
                }
            } else if !record.data_removal_pending
                || matches!(data_access, DataDirectoryAccessV1::Reuse)
            {
                return Err(WorkflowOperationStateError::UnsafePath);
            }
        } else if data.try_exists()? {
            match data_access {
                DataDirectoryAccessV1::Reuse => {
                    return Err(WorkflowOperationStateError::UnsafePath);
                }
                DataDirectoryAccessV1::Cleanup => {
                    validate_cleanup_data_directory(&data, self.build_uid, self.expected_root_uid)?;
                }
            }
        }
        for entry in fs::read_dir(directory)? {
            let name = entry?.file_name();
            if name != OsStr::new(RECORD_FILE)
                && name != OsStr::new(DATA_DIRECTORY)
                && !(name.as_encoded_bytes().starts_with(b".record-")
                    && name.as_encoded_bytes().ends_with(b".tmp"))
            {
                return Err(WorkflowOperationStateError::UnsafePath);
            }
        }
        Ok(record)
    }

    fn write_record(
        &self,
        directory: &Path,
        record: &OperationStateRecordV1,
    ) -> Result<(), WorkflowOperationStateError> {
        record.validate()?;
        let bytes = record.canonical_bytes()?;
        let temporary = directory.join(format!(".record-{}.tmp", Uuid::new_v4().simple()));
        write_new_file(&temporary, &bytes, self.expected_root_uid)?;
        fs::rename(&temporary, directory.join(RECORD_FILE))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn finish_pending_data_removal(
        &self,
        directory: &Path,
        record: &mut OperationStateRecordV1,
    ) -> Result<(), WorkflowOperationStateError> {
        if !record.data_removal_pending {
            return Ok(());
        }
        let data_path = directory.join(DATA_DIRECTORY);
        if data_path.try_exists()? {
            remove_tree(&data_path)?;
        }
        record.data_present = false;
        record.data_removal_pending = false;
        record.refresh_digest()?;
        self.write_record(directory, record)
    }

    fn remove_unrecorded_data_directory(
        directory: &Path,
        record: &OperationStateRecordV1,
    ) -> Result<(), WorkflowOperationStateError> {
        if record.data_present {
            return Ok(());
        }
        let data_path = directory.join(DATA_DIRECTORY);
        if data_path.try_exists()? {
            remove_tree(&data_path)?;
        }
        Ok(())
    }

    fn reconcile_startup(&self) -> Result<(), WorkflowOperationStateError> {
        let _guard = self.lock()?;
        self.revalidate()?;
        let entries = fs::read_dir(&self.root)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > MAX_RECORDS + 32 {
            return Err(WorkflowOperationStateError::RecordCapacityExceeded);
        }
        for entry in entries {
            let name = entry.file_name();
            if is_internal_operation_entry(&name) {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink()
                    || !metadata.file_type().is_dir()
                    || metadata.uid() != self.expected_root_uid
                {
                    return Err(WorkflowOperationStateError::UnsafePath);
                }
                remove_tree(&entry.path())?;
                continue;
            }
            let rendered = name
                .to_str()
                .ok_or(WorkflowOperationStateError::UnsafePath)?;
            if rendered.len() != 64
                || !rendered
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(WorkflowOperationStateError::UnsafePath);
            }
            let directory = entry.path();
            let mut record = self.load_record(&directory, DataDirectoryAccessV1::Cleanup)?;
            remove_record_temporaries(&directory, self.expected_root_uid)?;
            Self::remove_unrecorded_data_directory(&directory, &record)?;
            self.finish_pending_data_removal(&directory, &mut record)?;
        }
        self.prune_terminal_records(MAX_RETAINED_TERMINAL_RECORDS)?;
        self.root_lock.sync_all()?;
        Ok(())
    }

    fn prune_terminal_records(&self, retained: usize) -> Result<(), WorkflowOperationStateError> {
        let mut terminal_records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if is_internal_operation_entry(&entry.file_name()) {
                continue;
            }
            let record = self.load_record(&entry.path(), DataDirectoryAccessV1::Reuse)?;
            if record.terminal.is_some() {
                terminal_records.push((
                    record.updated_at_ms,
                    record.created_at_ms,
                    record.state.state_key.as_str().to_owned(),
                    entry.path(),
                ));
            }
        }
        terminal_records.sort_by(|left, right| {
            (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2))
        });
        let remove_count = terminal_records.len().saturating_sub(retained);
        for (_, _, _, path) in terminal_records.into_iter().take(remove_count) {
            self.remove_terminal_record_directory(&path)?;
        }
        Ok(())
    }

    fn remove_terminal_record_directory(
        &self,
        path: &Path,
    ) -> Result<(), WorkflowOperationStateError> {
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(WorkflowOperationStateError::UnsafePath)?;
        let deleting = self.root.join(format!(".deleting-{name}"));
        fs::rename(path, &deleting)?;
        self.root_lock.sync_all()?;
        remove_tree(&deleting)
    }

    fn reconcile_inactive_records(&self, now_ms: i64) -> Result<(), WorkflowOperationStateError> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if is_internal_operation_entry(&entry.file_name()) {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink()
                    || !metadata.file_type().is_dir()
                    || metadata.uid() != self.expected_root_uid
                {
                    return Err(WorkflowOperationStateError::UnsafePath);
                }
                remove_tree(&entry.path())?;
                continue;
            }
            let directory = entry.path();
            let mut record = self.load_record(&directory, DataDirectoryAccessV1::Cleanup)?;
            Self::remove_unrecorded_data_directory(&directory, &record)?;
            self.finish_pending_data_removal(&directory, &mut record)?;
            if record.terminal.is_some()
                || record.active_consumer.is_some()
                || now_ms.saturating_sub(record.updated_at_ms) < MAX_INACTIVE_STATE_IDLE_MS
            {
                continue;
            }
            record.last_release = None;
            record.terminal = Some(StateTerminalV1::Failed);
            record.updated_at_ms = now_ms.max(record.updated_at_ms);
            if record.data_present {
                record.data_removal_pending = true;
                record.refresh_digest()?;
                self.write_record(&directory, &record)?;
                self.finish_pending_data_removal(&directory, &mut record)?;
            } else {
                record.refresh_digest()?;
                self.write_record(&directory, &record)?;
            }
        }
        Ok(())
    }

    fn record_count(&self) -> Result<usize, WorkflowOperationStateError> {
        let mut count = 0_usize;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !is_internal_operation_entry(&entry.file_name()) {
                count = count
                    .checked_add(1)
                    .ok_or(WorkflowOperationStateError::RecordCapacityExceeded)?;
            }
        }
        Ok(count)
    }

    fn revalidate(&self) -> Result<(), WorkflowOperationStateError> {
        validate_opened_directory(&self.root, &self.root_lock, self.expected_root_uid)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, WorkflowOperationStateError> {
        self.operation_lock
            .lock()
            .map_err(|_| WorkflowOperationStateError::LockPoisoned)
    }
}

impl WorkflowOperationStateManagerV1 for WorkflowOperationStateStoreV1 {
    fn acquire(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<WorkflowOperationStateAcquisitionV1, WorkflowOperationStateError> {
        Self::acquire(self, lease, now_ms)
    }

    fn release(
        &self,
        lease: &WorkflowLeaseV1,
        outcome: WorkflowOperationStateOutcomeV1,
        completed_at_ms: i64,
    ) -> Result<WorkflowOperationStateReleaseV1, WorkflowOperationStateError> {
        Self::release(self, lease, outcome, completed_at_ms)
    }
}

fn is_internal_operation_entry(name: &OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b".staging-")
        || name.as_encoded_bytes().starts_with(b".deleting-")
}

fn required_state(
    lease: &WorkflowLeaseV1,
) -> Result<&WorkflowOperationStateV1, WorkflowOperationStateError> {
    lease
        .operation_state
        .as_ref()
        .ok_or(WorkflowOperationStateError::MissingStateContract)
}

fn validate_boundary(
    boundary: FilesystemBoundarySnapshot,
) -> Result<(), WorkflowOperationStateError> {
    if !boundary.shared_storage_domain
        || boundary.total_bytes < SHARED_BUILD_STORAGE_MIN_BYTES
        || boundary.total_inodes == 0
        || boundary.available_bytes > boundary.total_bytes
        || boundary.available_inodes > boundary.total_inodes
    {
        return Err(WorkflowOperationStateError::InvalidFilesystemBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inspect_usage(root: &Path) -> Result<StateUsage, WorkflowOperationStateError> {
    use rustix::fs::{CWD, Mode, OFlags, fstat, openat};

    let root = openat(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let root_metadata = fstat(&root).map_err(io::Error::from)?;
    let mut usage = StateUsage {
        allocated_bytes: accounted_stat_bytes(&root_metadata)?,
        inodes: 1,
    };
    inspect_open_directory(&root, 0, &mut usage)?;
    Ok(usage)
}

#[cfg(target_os = "linux")]
fn inspect_open_directory(
    directory: &OwnedFd,
    depth: u16,
    usage: &mut StateUsage,
) -> Result<(), WorkflowOperationStateError> {
    use rustix::fs::Dir;

    let mut entries = Dir::read_from(directory).map_err(io::Error::from)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(io::Error::from)?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        let (entry_usage, child_directory) = open_accounted_entry(directory, entry.file_name())?;
        usage.inodes = usage
            .inodes
            .checked_add(entry_usage.inodes)
            .ok_or(WorkflowOperationStateError::StateLimitExceeded)?;
        usage.allocated_bytes = usage
            .allocated_bytes
            .checked_add(entry_usage.allocated_bytes)
            .ok_or(WorkflowOperationStateError::StateLimitExceeded)?;
        if let Some(child_directory) = child_directory {
            let child_depth = depth
                .checked_add(1)
                .ok_or(WorkflowOperationStateError::StateLimitExceeded)?;
            if child_depth > MAX_OPERATION_STATE_DEPTH {
                return Err(WorkflowOperationStateError::StateLimitExceeded);
            }
            // Depth-first traversal holds at most two descriptors per level
            // (the pinned directory and its iterator). The explicit depth cap
            // therefore stays safely below the launcher's LimitNOFILE=256 even
            // for a repository-created tree with hundreds of sibling folders.
            inspect_open_directory(&child_directory, child_depth, usage)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_accounted_entry<Fd: std::os::fd::AsFd>(
    directory: &Fd,
    name: &std::ffi::CStr,
) -> Result<(StateUsage, Option<OwnedFd>), WorkflowOperationStateError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, openat};

    // O_PATH|O_NOFOLLOW pins the directory entry itself. If an untrusted writer
    // renames or replaces the pathname after this point, traversal remains on
    // the opened inode and can never follow the replacement outside the state.
    let entry = openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let metadata = fstat(&entry).map_err(io::Error::from)?;
    let usage = StateUsage {
        allocated_bytes: accounted_stat_bytes(&metadata)?,
        inodes: 1,
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
        return Ok((usage, None));
    }

    let child = openat(
        &entry,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let opened = fstat(&child).map_err(io::Error::from)?;
    if metadata.st_dev != opened.st_dev
        || metadata.st_ino != opened.st_ino
        || metadata.st_mode != opened.st_mode
        || metadata.st_uid != opened.st_uid
        || metadata.st_gid != opened.st_gid
    {
        return Err(WorkflowOperationStateError::PathChanged);
    }
    Ok((usage, Some(child)))
}

#[cfg(target_os = "linux")]
fn accounted_stat_bytes(metadata: &rustix::fs::Stat) -> Result<u64, WorkflowOperationStateError> {
    let logical = u64::try_from(metadata.st_size)
        .map_err(|_| WorkflowOperationStateError::StateLimitExceeded)?;
    let blocks = u64::try_from(metadata.st_blocks)
        .map_err(|_| WorkflowOperationStateError::StateLimitExceeded)?;
    Ok(logical.max(blocks.saturating_mul(512)))
}

#[cfg(not(target_os = "linux"))]
fn inspect_usage(_root: &Path) -> Result<StateUsage, WorkflowOperationStateError> {
    Err(WorkflowOperationStateError::InvalidFilesystemBoundary)
}

fn remove_tree(path: &Path) -> Result<(), WorkflowOperationStateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), WorkflowOperationStateError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    Ok(())
}

fn validate_private_directory(
    path: &Path,
    expected_uid: u32,
) -> Result<(), WorkflowOperationStateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    Ok(())
}

fn validate_opened_directory(
    path: &Path,
    opened: &File,
    expected_uid: u32,
) -> Result<(), WorkflowOperationStateError> {
    validate_private_directory(path, expected_uid)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let opened_metadata = opened.metadata()?;
    if !same_file(&path_metadata, &opened_metadata) {
        return Err(WorkflowOperationStateError::PathChanged);
    }
    Ok(())
}

fn validate_data_directory(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), WorkflowOperationStateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    Ok(())
}

fn validate_cleanup_data_directory(
    path: &Path,
    build_uid: u32,
    root_uid: u32,
) -> Result<(), WorkflowOperationStateError> {
    let metadata = fs::symlink_metadata(path)?;
    // The build identity may chmod or chgrp its own mount through a supplementary group. The
    // root-owned non-writable parent fixes the entry name; only the expected build owner or a
    // launcher-owned directory interrupted before chown is accepted for removal.
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != build_uid && metadata.uid() != root_uid
        || metadata.nlink() < 2
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    Ok(())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
}

fn write_new_file(
    path: &Path,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<(), WorkflowOperationStateError> {
    if bytes.is_empty() || bytes.len() > usize::try_from(MAX_RECORD_BYTES).unwrap_or(usize::MAX) {
        return Err(WorkflowOperationStateError::RecordTooLarge);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    Ok(())
}

fn read_stable_file(
    path: &Path,
    expected_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, WorkflowOperationStateError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != expected_uid
        || before.permissions().mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(WorkflowOperationStateError::UnsafePath);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file(&before, &opened) {
        return Err(WorkflowOperationStateError::PathChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if !same_file(&opened, &after)
        || bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
    {
        return Err(WorkflowOperationStateError::PathChanged);
    }
    Ok(bytes)
}

fn remove_record_temporaries(
    path: &Path,
    expected_uid: u32,
) -> Result<(), WorkflowOperationStateError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.as_encoded_bytes().starts_with(b".record-") {
            continue;
        }
        if !name.as_encoded_bytes().ends_with(b".tmp") {
            return Err(WorkflowOperationStateError::UnsafePath);
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
        {
            return Err(WorkflowOperationStateError::UnsafePath);
        }
        fs::remove_file(entry.path())?;
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

fn validate_time(value: i64) -> Result<(), WorkflowOperationStateError> {
    if value < 0 {
        Err(WorkflowOperationStateError::InvalidTime)
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowOperationStateError {
    #[error("workflow operation-state configuration is invalid")]
    InvalidConfig,
    #[error("workflow operation-state root is already open")]
    AlreadyOpen,
    #[error("workflow operation-state root or entry is unsafe")]
    UnsafePath,
    #[error("workflow operation-state path changed while open")]
    PathChanged,
    #[error("workflow operation-state requires the fixed shared build domain")]
    InvalidFilesystemBoundary,
    #[error("workflow operation-state filesystem has insufficient free capacity")]
    FilesystemCapacityExceeded,
    #[error("workflow operation-state contract is missing")]
    MissingStateContract,
    #[error("workflow operation-state identity conflicts with its lease")]
    IdentityConflict,
    #[error("workflow operation-state is currently owned by another consumer")]
    Busy,
    #[error("workflow operation-state is already terminal")]
    TerminalState,
    #[error("workflow operation-state consumer already completed")]
    ConsumerAlreadyCompleted,
    #[error("workflow operation-state exceeds its byte or inode limit")]
    StateLimitExceeded,
    #[error("workflow operation-state record capacity is exhausted")]
    RecordCapacityExceeded,
    #[error("workflow operation-state record is invalid")]
    InvalidRecord,
    #[error("workflow operation-state record is not canonical JCS")]
    NoncanonicalRecord,
    #[error("workflow operation-state record exceeds its size limit")]
    RecordTooLarge,
    #[error("workflow operation-state release evidence is invalid")]
    InvalidRelease,
    #[error("workflow operation-state timestamp is invalid")]
    InvalidTime,
    #[error("workflow operation-state lock is poisoned")]
    LockPoisoned,
    #[error("workflow operation-state lease contract failed: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("workflow operation-state JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("workflow operation-state filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::MetadataExt as _, str::FromStr as _};

    use tempfile::TempDir;

    use super::*;
    use crate::domain::{
        WorkflowAdapterIdV1, WorkflowArtifactKindV1, WorkflowCacheClassV1,
        WorkflowExecutionProfileV1, WorkflowNetworkClassV1, WorkflowNodeActivationV1,
        WorkflowNodeKindV1, WorkflowNodeV1, WorkflowResourceEnvelopeV1, WorkflowWorkerPoolV1,
    };

    #[derive(Debug)]
    struct TestProbe(FilesystemBoundarySnapshot);

    impl FilesystemBoundaryProbe for TestProbe {
        fn inspect(
            &self,
            _root: &File,
        ) -> Result<FilesystemBoundarySnapshot, WorkflowOperationStateError> {
            Ok(self.0)
        }
    }

    struct Fixture {
        _directory: TempDir,
        store: WorkflowOperationStateStoreV1,
        verify: WorkflowLeaseV1,
        release: WorkflowLeaseV1,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary operation root");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("private operation root");
            let metadata = fs::metadata(directory.path()).expect("operation root metadata");
            let store = WorkflowOperationStateStoreV1::open_with_probe(
                directory.path().to_owned(),
                metadata.uid(),
                metadata.uid(),
                metadata.gid(),
                Box::new(TestProbe(valid_boundary())),
            )
            .expect("open operation store");
            let attempt_id = Uuid::new_v4();
            let consumers = vec![
                WorkflowNodeId::from_str("release").expect("release ID"),
                WorkflowNodeId::from_str("verify").expect("verify ID"),
            ];
            Self {
                _directory: directory,
                store,
                verify: operation_lease(
                    attempt_id,
                    "verify",
                    WorkflowNodeKindV1::Verification,
                    consumers.clone(),
                ),
                release: operation_lease(
                    attempt_id,
                    "release",
                    WorkflowNodeKindV1::ReleaseBuild,
                    consumers,
                ),
            }
        }
    }

    fn valid_boundary() -> FilesystemBoundarySnapshot {
        FilesystemBoundarySnapshot {
            shared_storage_domain: true,
            total_bytes: 64 * 1024 * 1024 * 1024,
            available_bytes: 32 * 1024 * 1024 * 1024,
            host_available_bytes: 64 * 1024 * 1024 * 1024,
            total_inodes: 1_000_000,
            available_inodes: 1_000_000,
        }
    }

    fn operation_lease(
        attempt_id: Uuid,
        node_id: &str,
        kind: WorkflowNodeKindV1,
        consumers: Vec<WorkflowNodeId>,
    ) -> WorkflowLeaseV1 {
        let node = WorkflowNodeV1 {
            node_id: node_id.parse().expect("node ID"),
            display_name: node_id.to_owned(),
            kind,
            activation: WorkflowNodeActivationV1::Always,
            profile_id: format!("{node_id}-profile").parse().expect("profile ID"),
            depends_on: vec!["prepare".parse().expect("prepare ID")],
            input_contracts: vec![WorkflowArtifactKindV1::PreparedRun],
            output_contract: if kind == WorkflowNodeKindV1::Verification {
                WorkflowArtifactKindV1::VerificationReceipt
            } else {
                WorkflowArtifactKindV1::ReleaseBuildResult
            },
        };
        let profile = WorkflowExecutionProfileV1 {
            profile_id: node.profile_id.clone(),
            adapter_id: if kind == WorkflowNodeKindV1::Verification {
                WorkflowAdapterIdV1::WorkerBareBinCiV1
            } else {
                WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
            },
            worker_pool: if kind == WorkflowNodeKindV1::Verification {
                WorkflowWorkerPoolV1::BuildCompute
            } else {
                WorkflowWorkerPoolV1::VpsRequired
            },
            network_class: WorkflowNetworkClassV1::Offline,
            cache_class: WorkflowCacheClassV1::PreparedRun,
            timeout_ms: 60_000,
            resources: Some(WorkflowResourceEnvelopeV1 {
                cpu_millicores: 1_000,
                memory_max_bytes: 1024 * 1024 * 1024,
                tasks_max: 128,
                scratch_max_bytes: 1024 * 1024 * 1024,
                scratch_max_inodes: 100_000,
                output_max_bytes: 1024 * 1024,
            }),
        };
        let project_id = ProjectId::from_str("project").expect("project ID");
        let source_sha = GitCommitId::from_str(&"a".repeat(40)).expect("source SHA");
        let policy = EvidenceDigest::sha256("policy");
        let preparation = EvidenceDigest::sha256("preparation");
        let state = WorkflowOperationStateV1::new(
            attempt_id,
            &project_id,
            &source_sha,
            &policy,
            &preparation,
            "worker",
            "host",
            consumers,
            1024 * 1024,
            4_096,
        )
        .expect("operation state");
        WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            attempt_id,
            project_id,
            source_sha,
            1,
            EvidenceDigest::sha256("attestation"),
            policy,
            preparation,
            &node,
            &profile,
            None,
            Vec::new(),
            EvidenceDigest::sha256("input"),
            "worker".to_owned(),
            "host".to_owned(),
            100,
            10_000,
        )
        .and_then(|lease| lease.with_operation_state(state))
        .expect("operation lease")
    }

    #[test]
    fn successful_consumers_reuse_one_state_then_remove_its_payload() {
        let fixture = Fixture::new();
        let verify = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        fs::create_dir(verify.data_path.join("target")).expect("target directory");
        fs::write(verify.data_path.join("target/artifact"), b"compiled")
            .expect("compiled artifact");
        let renewed_verify = fixture.verify.renewed(20_000).expect("renew verify lease");
        let retained = fixture
            .store
            .release(
                &renewed_verify,
                WorkflowOperationStateOutcomeV1::Succeeded,
                102,
            )
            .expect("retain verify state");
        assert_eq!(
            retained.disposition,
            WorkflowOperationStateDispositionV1::Retained
        );
        assert!(retained.reusable);

        let release = fixture
            .store
            .acquire(&fixture.release, 103)
            .expect("acquire release");
        assert_eq!(
            fs::read(release.data_path.join("target/artifact")).expect("shared artifact"),
            b"compiled"
        );
        let removed = fixture
            .store
            .release(
                &fixture.release,
                WorkflowOperationStateOutcomeV1::Succeeded,
                104,
            )
            .expect("finish operation state");
        assert_eq!(
            removed.disposition,
            WorkflowOperationStateDispositionV1::RemovedAfterSuccess
        );
        assert!(removed.reusable);
        assert!(!release.data_path.exists());
    }

    #[test]
    fn concurrent_consumer_is_rejected_and_failure_removes_state() {
        let fixture = Fixture::new();
        let acquired = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        let metadata = fs::metadata(&acquired.data_path).expect("state metadata");
        fs::set_permissions(&acquired.data_path, fs::Permissions::from_mode(0o500))
            .expect("simulate repository-owned mode change");
        assert!(matches!(
            validate_data_directory(&acquired.data_path, metadata.uid(), metadata.gid()),
            Err(WorkflowOperationStateError::UnsafePath)
        ));
        validate_cleanup_data_directory(&acquired.data_path, metadata.uid(), metadata.uid())
            .expect("cleanup still recognizes exact data root");
        fs::set_permissions(&acquired.data_path, fs::Permissions::from_mode(0o700))
            .expect("restore test traversal");
        assert!(matches!(
            fixture.store.acquire(&fixture.release, 102),
            Err(WorkflowOperationStateError::Busy)
        ));
        let failed = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Failed,
                103,
            )
            .expect("fail operation state");
        assert_eq!(
            failed.disposition,
            WorkflowOperationStateDispositionV1::RemovedAfterFailure
        );
        assert!(!acquired.data_path.exists());
        assert!(matches!(
            fixture.store.acquire(&fixture.release, 104),
            Err(WorkflowOperationStateError::TerminalState)
        ));
    }

    #[test]
    fn uncertain_cleanup_resets_partial_state_for_retry() {
        let fixture = Fixture::new();
        let acquired = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        fs::write(acquired.data_path.join("partial"), b"partial").expect("partial artifact");
        let reset = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Unknown,
                102,
            )
            .expect("reset state");
        assert_eq!(
            reset.disposition,
            WorkflowOperationStateDispositionV1::Reset
        );
        assert!(!acquired.data_path.exists());
        let replayed = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Unknown,
                103,
            )
            .expect("replay reset");
        assert_eq!(replayed.disposition, reset.disposition);
        assert_eq!(replayed.reusable, reset.reusable);
        assert_eq!(replayed.allocated_bytes, reset.allocated_bytes);
        assert_eq!(replayed.inodes, reset.inodes);
        fixture
            .store
            .create_data_directory(&acquired.data_path)
            .expect("simulate interrupted retry directory");
        fs::write(acquired.data_path.join("unrecorded"), b"partial")
            .expect("unrecorded retry output");
        fixture
            .store
            .reconcile_startup()
            .expect("remove unrecorded retry directory");
        assert!(!acquired.data_path.exists());
        let retry = fixture
            .store
            .acquire(&fixture.verify, 104)
            .expect("retry verify");
        assert!(retry.data_path.exists());
        assert!(!retry.data_path.join("partial").exists());
    }

    #[test]
    fn limit_violation_removes_payload_and_replays_the_exact_disposition() {
        let fixture = Fixture::new();
        let acquired = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        fs::write(
            acquired.data_path.join("oversized"),
            vec![0_u8; 2 * 1024 * 1024],
        )
        .expect("oversized output");
        let removed = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Succeeded,
                102,
            )
            .expect("remove oversized state");
        assert_eq!(
            removed.disposition,
            WorkflowOperationStateDispositionV1::RemovedAfterLimit
        );
        assert!(!removed.reusable);
        assert!(removed.allocated_bytes > 1024 * 1024);
        assert!(!acquired.data_path.exists());

        let replayed = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Succeeded,
                103,
            )
            .expect("replay limit cleanup");
        assert_eq!(replayed.disposition, removed.disposition);
        assert_eq!(replayed.allocated_bytes, removed.allocated_bytes);
        assert_eq!(replayed.inodes, removed.inodes);
    }

    #[test]
    fn abandoned_retained_state_is_removed_before_it_can_block_future_work() {
        let fixture = Fixture::new();
        let acquired = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        fs::write(acquired.data_path.join("target"), b"compiled").expect("compiled state");
        fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Succeeded,
                102,
            )
            .expect("retain first consumer");

        fixture
            .store
            .reconcile_inactive_records(102 + MAX_INACTIVE_STATE_IDLE_MS - 1)
            .expect("retain state inside idle window");
        assert!(acquired.data_path.exists());
        fixture
            .store
            .reconcile_inactive_records(102 + MAX_INACTIVE_STATE_IDLE_MS)
            .expect("reconcile abandoned state");
        assert!(!acquired.data_path.exists());
        assert!(matches!(
            fixture
                .store
                .acquire(&fixture.release, 103 + MAX_INACTIVE_STATE_IDLE_MS),
            Err(WorkflowOperationStateError::TerminalState)
        ));
        let cleanup = fixture
            .store
            .release(
                &fixture.release,
                WorkflowOperationStateOutcomeV1::Unknown,
                104 + MAX_INACTIVE_STATE_IDLE_MS,
            )
            .expect("replay abandoned cleanup");
        assert_eq!(
            cleanup.disposition,
            WorkflowOperationStateDispositionV1::RemovedAfterFailure
        );
        assert!(!cleanup.reusable);
    }

    #[test]
    fn startup_finishes_a_data_removal_interrupted_after_unlink() {
        let fixture = Fixture::new();
        let acquired = fixture
            .store
            .acquire(&fixture.verify, 101)
            .expect("acquire verify");
        fs::write(acquired.data_path.join("partial"), b"partial").expect("partial output");
        let record_directory = acquired.data_path.parent().expect("record directory");
        let mut record = fixture
            .store
            .load_record(record_directory, DataDirectoryAccessV1::Cleanup)
            .expect("load active record");
        let consumer = record.active_consumer.take().expect("active consumer");
        record.terminal = Some(StateTerminalV1::Failed);
        record.last_release = Some(OperationStateReleaseRecordV1::new(
            consumer,
            WorkflowOperationStateDispositionV1::RemovedAfterFailure,
            false,
            StateUsage {
                allocated_bytes: 4_096,
                inodes: 2,
            },
        ));
        record.data_removal_pending = true;
        record.updated_at_ms = 102;
        record.refresh_digest().expect("refresh pending record");
        fixture
            .store
            .write_record(record_directory, &record)
            .expect("persist removal intent");
        remove_tree(&acquired.data_path).expect("simulate completed unlink before crash");

        fixture
            .store
            .reconcile_startup()
            .expect("finish interrupted removal");
        let recovered = fixture
            .store
            .load_record(record_directory, DataDirectoryAccessV1::Reuse)
            .expect("load recovered record");
        assert!(!recovered.data_present);
        assert!(!recovered.data_removal_pending);
        let replayed = fixture
            .store
            .release(
                &fixture.verify,
                WorkflowOperationStateOutcomeV1::Failed,
                103,
            )
            .expect("replay recovered release");
        assert_eq!(
            replayed.disposition,
            WorkflowOperationStateDispositionV1::RemovedAfterFailure
        );
        assert_eq!(replayed.allocated_bytes, 4_096);
        assert_eq!(replayed.inodes, 2);
    }

    #[test]
    fn terminal_tombstone_retention_removes_only_the_oldest_records() {
        let fixture = Fixture::new();
        let mut record_paths = Vec::new();
        for index in 0..3_i64 {
            let node_id = WorkflowNodeId::from_str("verify").expect("verify ID");
            let lease = operation_lease(
                Uuid::new_v4(),
                "verify",
                WorkflowNodeKindV1::Verification,
                vec![node_id],
            );
            let acquired = fixture
                .store
                .acquire(&lease, 200 + index * 2)
                .expect("acquire terminal fixture");
            record_paths.push(acquired.data_path.parent().expect("record path").to_owned());
            fixture
                .store
                .release(
                    &lease,
                    WorkflowOperationStateOutcomeV1::Succeeded,
                    201 + index * 2,
                )
                .expect("complete terminal fixture");
        }

        fixture
            .store
            .prune_terminal_records(1)
            .expect("prune old tombstones");
        assert!(!record_paths[0].exists());
        assert!(!record_paths[1].exists());
        assert!(record_paths[2].exists());
        assert_eq!(fixture.store.record_count().expect("record count"), 1);

        let state_name = record_paths[2]
            .file_name()
            .and_then(OsStr::to_str)
            .expect("state name");
        let deleting = record_paths[2]
            .parent()
            .expect("operation root")
            .join(format!(".deleting-{state_name}"));
        fs::rename(&record_paths[2], &deleting).expect("simulate interrupted tombstone pruning");
        fixture
            .store
            .reconcile_startup()
            .expect("reconcile deleting tombstone");
        assert!(!deleting.exists());
        assert_eq!(fixture.store.record_count().expect("empty record count"), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn usage_walk_remains_on_the_opened_directory_after_path_replacement() {
        use std::ffi::CString;

        use rustix::fs::Dir;

        let root = tempfile::tempdir().expect("usage root");
        let external = tempfile::tempdir().expect("external root");
        let child = root.path().join("child");
        let moved = root.path().join("moved");
        fs::create_dir(&child).expect("create child");
        fs::write(child.join("inside"), b"inside").expect("write inside file");
        fs::write(external.path().join("outside"), b"outside").expect("write outside file");

        let root_fd = File::open(root.path()).expect("open usage root");
        let name = CString::new("child").expect("entry name");
        let (_, child_fd) =
            open_accounted_entry(&root_fd, &name).expect("open accounted child before replacement");
        let child_fd = child_fd.expect("child is a directory");
        fs::rename(&child, &moved).expect("move opened child");
        std::os::unix::fs::symlink(external.path(), &child)
            .expect("replace child path with external symlink");

        let mut opened_entries = Dir::read_from(&child_fd).expect("read pinned child");
        let mut names = Vec::new();
        while let Some(entry) = opened_entries.read() {
            let entry = entry.expect("read pinned entry");
            let name = entry.file_name().to_bytes();
            if !matches!(name, b"." | b"..") {
                names.push(name.to_vec());
            }
        }
        assert_eq!(names, vec![b"inside".to_vec()]);

        let usage = inspect_usage(root.path()).expect("account replaced tree");
        assert_eq!(
            usage.inodes, 4,
            "external symlink target must not be walked"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn usage_walk_bounds_descriptor_depth_before_scanning_an_adversarial_tree() {
        let root = tempfile::tempdir().expect("usage root");
        let mut current = root.path().to_owned();
        for _ in 0..=MAX_OPERATION_STATE_DEPTH {
            current = current.join("d");
            fs::create_dir(&current).expect("create nested directory");
        }

        assert!(matches!(
            inspect_usage(root.path()),
            Err(WorkflowOperationStateError::StateLimitExceeded)
        ));
    }

    #[test]
    fn filesystem_domain_is_shared_and_capacity_is_internally_consistent() {
        for invalid in [
            FilesystemBoundarySnapshot {
                shared_storage_domain: false,
                ..valid_boundary()
            },
            FilesystemBoundarySnapshot {
                available_bytes: valid_boundary().total_bytes + 1,
                ..valid_boundary()
            },
            FilesystemBoundarySnapshot {
                available_inodes: valid_boundary().total_inodes + 1,
                ..valid_boundary()
            },
        ] {
            assert!(matches!(
                validate_boundary(invalid),
                Err(WorkflowOperationStateError::InvalidFilesystemBoundary)
            ));
        }
    }
}
