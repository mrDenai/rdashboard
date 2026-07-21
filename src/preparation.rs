use std::{
    collections::{BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, Mutex, MutexGuard, Weak},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    build_source::{
        OpenedSourceArchiveV1, SourceArchiveError, SourceArchiveManifestV1, SourceArchiveReaderV1,
    },
    domain::{EvidenceDigest, GitCommitId, ProjectId, WorkflowLeaseV1, WorkflowNodeKindV1},
};

pub const PREPARATION_STORE_ROOT: &str = "/var/lib/rdashboard-build/preparation";
pub const MAX_PREPARATION_STORE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
pub const MAX_PREPARATION_STORE_INODES: u64 = 100_000;
pub const MIN_ROOT_EMERGENCY_RESERVE_BYTES: u64 = 12 * 1024 * 1024 * 1024;

const PREPARATION_KEY_SCHEMA_VERSION: u16 = 1;
const PREPARATION_KEY_PURPOSE: &str = "rdashboard.preparation-key.v1";
const PREPARATION_ENTRY_SCHEMA_VERSION: u16 = 1;
const PREPARATION_ENTRY_PURPOSE: &str = "rdashboard.preparation-entry.v1";
const PREPARATION_PIN_SCHEMA_VERSION: u16 = 1;
const PREPARATION_PIN_PURPOSE: &str = "rdashboard.preparation-pin.v1";
const PREPARATION_ACCESS_SCHEMA_VERSION: u16 = 1;
const PREPARATION_ACCESS_PURPOSE: &str = "rdashboard.preparation-access.v1";
const MAX_ENTRY_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PAYLOAD_PATH_BYTES: usize = 4_096;
const MAX_PLATFORM_BYTES: usize = 256;
const MAX_PIN_DURATION_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_LIVE_PINS: usize = 4_096;
const DEFAULT_WARM_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;
const FILE_COPY_BUFFER_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationObjectKindV1 {
    SourceSnapshot,
    DependencySnapshot,
    PreparedRun,
}

impl PreparationObjectKindV1 {
    const ALL: [Self; 3] = [
        Self::SourceSnapshot,
        Self::DependencySnapshot,
        Self::PreparedRun,
    ];

    const fn directory_name(self) -> &'static str {
        match self {
            Self::SourceSnapshot => "source-snapshot",
            Self::DependencySnapshot => "dependency-snapshot",
            Self::PreparedRun => "prepared-run",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparationKeyMaterialV1 {
    SourceSnapshot {
        project_id: ProjectId,
        source_sha: GitCommitId,
        source_sequence: u64,
        source_attestation_digest: EvidenceDigest,
        workflow_policy_digest: EvidenceDigest,
        repository_identity: EvidenceDigest,
        archive_digest: EvidenceDigest,
        archive_bytes: u64,
    },
    DependencySnapshot {
        toolchain_digest: EvidenceDigest,
        lockfile_digest: EvidenceDigest,
        platform: String,
        workflow_policy_digest: EvidenceDigest,
    },
    PreparedRun {
        source_snapshot_key: EvidenceDigest,
        dependency_snapshot_key: EvidenceDigest,
        workflow_policy_digest: EvidenceDigest,
        generated_input_digest: EvidenceDigest,
    },
}

#[derive(Serialize)]
struct PreparationKeyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    material: &'a PreparationKeyMaterialV1,
}

impl PreparationKeyMaterialV1 {
    pub const fn kind(&self) -> PreparationObjectKindV1 {
        match self {
            Self::SourceSnapshot { .. } => PreparationObjectKindV1::SourceSnapshot,
            Self::DependencySnapshot { .. } => PreparationObjectKindV1::DependencySnapshot,
            Self::PreparedRun { .. } => PreparationObjectKindV1::PreparedRun,
        }
    }

    pub fn key(&self) -> Result<EvidenceDigest, PreparationStoreError> {
        self.validate()?;
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &PreparationKeyPayload {
                purpose: PREPARATION_KEY_PURPOSE,
                schema_version: PREPARATION_KEY_SCHEMA_VERSION,
                material: self,
            },
        )?))
    }

    fn validate(&self) -> Result<(), PreparationStoreError> {
        match self {
            Self::SourceSnapshot {
                source_sequence,
                archive_bytes,
                ..
            } if *source_sequence == 0
                || *archive_bytes == 0
                || *archive_bytes > MAX_PREPARATION_STORE_BYTES =>
            {
                Err(PreparationStoreError::InvalidKeyMaterial)
            }
            Self::DependencySnapshot { platform, .. }
                if platform.is_empty()
                    || platform.len() > MAX_PLATFORM_BYTES
                    || !platform.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    }) =>
            {
                Err(PreparationStoreError::InvalidKeyMaterial)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PreparationPayloadEntryKindV1 {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparationPayloadEntryV1 {
    path_base64url: String,
    entry_kind: PreparationPayloadEntryKindV1,
    mode: u32,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationEntryManifestV1 {
    purpose: String,
    schema_version: u16,
    pub kind: PreparationObjectKindV1,
    pub key: EvidenceDigest,
    entries: Vec<PreparationPayloadEntryV1>,
    pub payload_bytes: u64,
    pub total_inodes: u64,
    pub created_at_ms: i64,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct PreparationEntryManifestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    kind: PreparationObjectKindV1,
    key: &'a EvidenceDigest,
    entries: &'a [PreparationPayloadEntryV1],
    payload_bytes: u64,
    total_inodes: u64,
    created_at_ms: i64,
}

impl PreparationEntryManifestV1 {
    fn new(
        kind: PreparationObjectKindV1,
        key: EvidenceDigest,
        entries: Vec<PreparationPayloadEntryV1>,
        created_at_ms: i64,
    ) -> Result<Self, PreparationStoreError> {
        let payload_bytes = entries.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.bytes)
                .ok_or(PreparationStoreError::PayloadTooLarge)
        })?;
        let total_inodes = u64::try_from(entries.len())
            .map_err(|_| PreparationStoreError::PayloadTooLarge)?
            .checked_add(3)
            .ok_or(PreparationStoreError::PayloadTooLarge)?;
        let mut manifest = Self {
            purpose: PREPARATION_ENTRY_PURPOSE.to_owned(),
            schema_version: PREPARATION_ENTRY_SCHEMA_VERSION,
            kind,
            key,
            entries,
            payload_bytes,
            total_inodes,
            created_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        manifest.document_digest = manifest.calculate_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, PreparationStoreError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&manifest)? != bytes {
            return Err(PreparationStoreError::NonCanonicalDocument);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PreparationStoreError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn validate(&self) -> Result<(), PreparationStoreError> {
        let mut previous: Option<Vec<u8>> = None;
        let mut payload_bytes = 0_u64;
        for entry in &self.entries {
            let path = decode_relative_path(&entry.path_base64url)?;
            let bytes = path.as_os_str().as_bytes();
            if previous
                .as_ref()
                .is_some_and(|value| value.as_slice() >= bytes)
            {
                return Err(PreparationStoreError::InvalidEntryManifest);
            }
            previous = Some(bytes.to_vec());
            match entry.entry_kind {
                PreparationPayloadEntryKindV1::Directory
                    if entry.mode != 0o555 || entry.bytes != 0 || entry.sha256.is_some() =>
                {
                    return Err(PreparationStoreError::InvalidEntryManifest);
                }
                PreparationPayloadEntryKindV1::RegularFile
                    if !matches!(entry.mode, 0o444 | 0o555) || entry.sha256.is_none() =>
                {
                    return Err(PreparationStoreError::InvalidEntryManifest);
                }
                PreparationPayloadEntryKindV1::RegularFile => {
                    payload_bytes = payload_bytes
                        .checked_add(entry.bytes)
                        .ok_or(PreparationStoreError::PayloadTooLarge)?;
                }
                PreparationPayloadEntryKindV1::Directory => {}
            }
        }
        let expected_inodes = u64::try_from(self.entries.len())
            .map_err(|_| PreparationStoreError::PayloadTooLarge)?
            .checked_add(3)
            .ok_or(PreparationStoreError::PayloadTooLarge)?;
        if self.purpose != PREPARATION_ENTRY_PURPOSE
            || self.schema_version != PREPARATION_ENTRY_SCHEMA_VERSION
            || self.entries.is_empty()
            || self.created_at_ms < 0
            || payload_bytes != self.payload_bytes
            || expected_inodes != self.total_inodes
            || self.total_inodes > MAX_PREPARATION_STORE_INODES
            || self.payload_bytes > MAX_PREPARATION_STORE_BYTES
            || self.document_digest != self.calculate_digest()?
        {
            return Err(PreparationStoreError::InvalidEntryManifest);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, PreparationStoreError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &PreparationEntryManifestPayload {
                purpose: PREPARATION_ENTRY_PURPOSE,
                schema_version: self.schema_version,
                kind: self.kind,
                key: &self.key,
                entries: &self.entries,
                payload_bytes: self.payload_bytes,
                total_inodes: self.total_inodes,
                created_at_ms: self.created_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedEntryV1 {
    pub manifest: PreparationEntryManifestV1,
    path: PathBuf,
}

impl PreparedEntryV1 {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn payload_path(&self) -> PathBuf {
        self.path.join("payload")
    }
}

#[derive(Clone, Debug)]
struct PreparationStorePolicy {
    max_bytes: u64,
    max_inodes: u64,
    root_emergency_reserve_bytes: u64,
    warm_window_ms: i64,
}

impl PreparationStorePolicy {
    fn production() -> Self {
        Self {
            max_bytes: MAX_PREPARATION_STORE_BYTES,
            max_inodes: MAX_PREPARATION_STORE_INODES,
            root_emergency_reserve_bytes: MIN_ROOT_EMERGENCY_RESERVE_BYTES,
            warm_window_ms: DEFAULT_WARM_WINDOW_MS,
        }
    }

    fn validate(&self) -> Result<(), PreparationStoreError> {
        if self.max_bytes == 0
            || self.max_bytes > MAX_PREPARATION_STORE_BYTES
            || self.max_inodes == 0
            || self.max_inodes > MAX_PREPARATION_STORE_INODES
            || self.root_emergency_reserve_bytes < MIN_ROOT_EMERGENCY_RESERVE_BYTES
            || self.warm_window_ms < 0
        {
            return Err(PreparationStoreError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct FilesystemBoundarySnapshot {
    dedicated_mount: bool,
    store_total_bytes: u64,
    store_available_bytes: u64,
    root_available_bytes: u64,
    allocation_granularity: u64,
}

trait FilesystemBoundaryProbe: Send + Sync {
    fn inspect(&self) -> Result<FilesystemBoundarySnapshot, PreparationStoreError>;
}

#[derive(Debug)]
struct SystemFilesystemBoundaryProbe {
    root: PathBuf,
}

impl FilesystemBoundaryProbe for SystemFilesystemBoundaryProbe {
    fn inspect(&self) -> Result<FilesystemBoundarySnapshot, PreparationStoreError> {
        let store = fs2::statvfs(&self.root)?;
        let root = fs2::statvfs("/")?;
        Ok(FilesystemBoundarySnapshot {
            dedicated_mount: is_exact_mount_point(&self.root)?,
            store_total_bytes: store.total_space(),
            store_available_bytes: store.available_space(),
            root_available_bytes: root.available_space(),
            allocation_granularity: store.allocation_granularity(),
        })
    }
}

#[derive(Debug, Default)]
struct AdmissionState {
    reserved_bytes: u64,
    reserved_inodes: u64,
}

struct AdmissionReservation {
    state: Arc<Mutex<AdmissionState>>,
    bytes: u64,
    inodes: u64,
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.reserved_bytes = state.reserved_bytes.saturating_sub(self.bytes);
            state.reserved_inodes = state.reserved_inodes.saturating_sub(self.inodes);
        }
    }
}

#[derive(Clone)]
pub struct PreparationStore {
    root: PathBuf,
    expected_owner_uid: u32,
    root_lock: Arc<File>,
    policy: PreparationStorePolicy,
    probe: Arc<dyn FilesystemBoundaryProbe>,
    key_locks: Arc<Mutex<HashMap<EvidenceDigest, Weak<Mutex<()>>>>>,
    commit_lock: Arc<Mutex<()>>,
    admission: Arc<Mutex<AdmissionState>>,
}

impl PreparationStore {
    pub fn open_root_owned(root: impl AsRef<Path>) -> Result<Self, PreparationStoreError> {
        Self::open_for_owner(root, 0)
    }

    pub fn open_for_owner(
        root: impl AsRef<Path>,
        expected_owner_uid: u32,
    ) -> Result<Self, PreparationStoreError> {
        let root = root.as_ref().to_path_buf();
        let probe = Arc::new(SystemFilesystemBoundaryProbe { root: root.clone() });
        Self::open_with_policy(
            root,
            expected_owner_uid,
            PreparationStorePolicy::production(),
            probe,
        )
    }

    fn open_with_policy(
        root: PathBuf,
        expected_owner_uid: u32,
        policy: PreparationStorePolicy,
        probe: Arc<dyn FilesystemBoundaryProbe>,
    ) -> Result<Self, PreparationStoreError> {
        policy.validate()?;
        validate_store_root(&root, expected_owner_uid)?;
        let root_lock = File::open(&root)?;
        root_lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                PreparationStoreError::StoreAlreadyOpen
            } else {
                PreparationStoreError::Io(error)
            }
        })?;
        revalidate_store_root(&root, &root_lock, expected_owner_uid)?;
        validate_boundary(&policy, probe.inspect()?, 0)?;
        initialize_layout(&root, expected_owner_uid)?;
        reconcile_staging(&root, expected_owner_uid)?;
        reconcile_sidecar_temporaries(&root.join("pins"), expected_owner_uid)?;
        reconcile_sidecar_temporaries(&root.join("access"), expected_owner_uid)?;
        reconcile_sidecar_temporaries(&root.join("evictions"), expected_owner_uid)?;

        let store = Self {
            root,
            expected_owner_uid,
            root_lock: Arc::new(root_lock),
            policy,
            probe,
            key_locks: Arc::new(Mutex::new(HashMap::new())),
            commit_lock: Arc::new(Mutex::new(())),
            admission: Arc::new(Mutex::new(AdmissionState::default())),
        };
        store.reconcile_evictions()?;
        store.reconcile_committing_entries()?;
        store.reconcile_access_records()?;
        let now_ms = crate::unix_time_ms().map_err(|_| PreparationStoreError::ClockUnavailable)?;
        store.cleanup_expired_pins(now_ms)?;
        let usage = store.scan_usage()?;
        if usage.bytes > store.policy.max_bytes || usage.inodes > store.policy.max_inodes {
            return Err(PreparationStoreError::StoreOverCapacity);
        }
        Ok(store)
    }

    pub fn publish_source_snapshot(
        &self,
        reader: &SourceArchiveReaderV1,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<PreparedEntryV1, PreparationStoreError> {
        validate_time(now_ms)?;
        lease.validate()?;
        if lease.node_kind != WorkflowNodeKindV1::HostPrepare {
            return Err(PreparationStoreError::SourceLeaseMismatch);
        }
        let source_identity = lease.required_source_identity()?;
        let opened = reader.exact(
            &lease.project_id,
            &lease.source_sha,
            source_identity.sequence,
        )?;
        if opened.manifest.source_attestation_digest != source_identity.attestation_digest
            || opened.manifest.installed_policy.digest != lease.workflow_policy_digest
        {
            return Err(PreparationStoreError::SourceLeaseMismatch);
        }
        let material = source_key_material(lease, &opened.manifest)?;
        let key = material.key()?;
        let kind = material.kind();
        let key_lock = self.key_lock(&key)?;
        let _key_guard = lock(&key_lock)?;
        if let Some(entry) = self.open_existing(kind, &key, now_ms)? {
            return Ok(entry);
        }

        let manifest_bytes = opened.manifest.canonical_bytes()?;
        let estimate = estimate_payload(
            opened
                .manifest
                .archive_bytes
                .checked_add(
                    u64::try_from(manifest_bytes.len())
                        .map_err(|_| PreparationStoreError::PayloadTooLarge)?,
                )
                .ok_or(PreparationStoreError::PayloadTooLarge)?,
            6,
            self.probe.inspect()?.allocation_granularity,
        )?;
        let reservation = self.reserve(estimate, now_ms)?;
        let stage = self.stage_source_snapshot(kind, &key, opened, &manifest_bytes, now_ms)?;
        self.commit_stage(kind, &key, &stage, &reservation, now_ms)
    }

    pub fn get_or_prepare_directory<F, E>(
        &self,
        material: &PreparationKeyMaterialV1,
        now_ms: i64,
        producer: F,
    ) -> Result<PreparedEntryV1, PreparationStoreError>
    where
        F: FnOnce() -> Result<PathBuf, E>,
        E: std::fmt::Display,
    {
        validate_time(now_ms)?;
        let key = material.key()?;
        let kind = material.kind();
        if kind == PreparationObjectKindV1::SourceSnapshot {
            return Err(PreparationStoreError::InvalidKeyMaterial);
        }
        let key_lock = self.key_lock(&key)?;
        let _key_guard = lock(&key_lock)?;
        if let Some(entry) = self.open_existing(kind, &key, now_ms)? {
            return Ok(entry);
        }

        let source_root =
            producer().map_err(|error| PreparationStoreError::ProducerFailed(error.to_string()))?;
        let inventory = inspect_input_directory(&source_root)?;
        let estimate =
            estimate_inventory(&inventory, self.probe.inspect()?.allocation_granularity)?;
        let reservation = self.reserve(estimate, now_ms)?;
        let stage = self.stage_directory(kind, &key, &inventory, now_ms)?;
        let repeated = match inspect_input_directory(&source_root) {
            Ok(repeated) => repeated,
            Err(error) => {
                remove_owned_tree(&stage, self.expected_owner_uid)?;
                return Err(error);
            }
        };
        if inventory != repeated {
            remove_owned_tree(&stage, self.expected_owner_uid)?;
            return Err(PreparationStoreError::InputChanged);
        }
        self.commit_stage(kind, &key, &stage, &reservation, now_ms)
    }

    pub fn open_pinned(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        pin_id: Uuid,
        pin_expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<PreparedEntryV1, PreparationStoreError> {
        validate_time(now_ms)?;
        if pin_id.is_nil()
            || pin_expires_at_ms <= now_ms
            || pin_expires_at_ms - now_ms > MAX_PIN_DURATION_MS
        {
            return Err(PreparationStoreError::InvalidPin);
        }
        let _commit = lock(&self.commit_lock)?;
        self.revalidate()?;
        self.reconcile_evictions()?;
        self.cleanup_expired_pins(now_ms)?;
        let entry = self.validate_entry(kind, key)?;
        self.write_pin(&PinRecordV1::new(pin_id, key.clone(), pin_expires_at_ms)?)?;
        self.touch_access(key, now_ms, true)?;
        Ok(entry)
    }

    pub fn unpin(
        &self,
        pin_id: Uuid,
        expected_key: &EvidenceDigest,
    ) -> Result<(), PreparationStoreError> {
        if pin_id.is_nil() {
            return Err(PreparationStoreError::InvalidPin);
        }
        let _commit = lock(&self.commit_lock)?;
        self.revalidate()?;
        self.reconcile_evictions()?;
        let path = self.pin_path(pin_id);
        let record = load_pin(&path, self.expected_owner_uid)?;
        if record.key != *expected_key || record.pin_id != pin_id {
            return Err(PreparationStoreError::InvalidPin);
        }
        fs::remove_file(&path)?;
        sync_directory(
            path.parent()
                .ok_or(PreparationStoreError::UntrustedLayout)?,
        )?;
        Ok(())
    }

    fn stage_source_snapshot(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        opened: OpenedSourceArchiveV1,
        source_manifest_bytes: &[u8],
        now_ms: i64,
    ) -> Result<PathBuf, PreparationStoreError> {
        let stage = self.create_stage()?;
        let result = (|| {
            let payload = stage.join("payload");
            create_directory(&payload, 0o700)?;
            let mut entries = Vec::with_capacity(2);
            let archive_entry = write_payload_reader(
                &payload,
                Path::new("source.tar"),
                opened.archive,
                opened.manifest.archive_bytes,
                &opened.manifest.archive_sha256,
                false,
            )?;
            entries.push(archive_entry);
            let manifest_digest = EvidenceDigest::sha256(source_manifest_bytes);
            entries.push(write_payload_reader(
                &payload,
                Path::new("source-manifest.jcs"),
                io::Cursor::new(source_manifest_bytes),
                u64::try_from(source_manifest_bytes.len())
                    .map_err(|_| PreparationStoreError::PayloadTooLarge)?,
                &manifest_digest,
                false,
            )?);
            entries.sort_by(compare_manifest_entries);
            seal_stage(
                &stage,
                &PreparationEntryManifestV1::new(kind, key.clone(), entries, now_ms)?,
                self.expected_owner_uid,
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            remove_owned_tree(&stage, self.expected_owner_uid)?;
            return Err(error);
        }
        Ok(stage)
    }

    fn stage_directory(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        inventory: &InputInventory,
        now_ms: i64,
    ) -> Result<PathBuf, PreparationStoreError> {
        let stage = self.create_stage()?;
        let result = (|| {
            let payload = stage.join("payload");
            create_directory(&payload, 0o700)?;
            let entries = copy_inventory(inventory, &payload)?;
            seal_stage(
                &stage,
                &PreparationEntryManifestV1::new(kind, key.clone(), entries, now_ms)?,
                self.expected_owner_uid,
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            remove_owned_tree(&stage, self.expected_owner_uid)?;
            return Err(error);
        }
        Ok(stage)
    }

    fn commit_stage(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        stage: &Path,
        reservation: &AdmissionReservation,
        now_ms: i64,
    ) -> Result<PreparedEntryV1, PreparationStoreError> {
        let result = (|| {
            let _commit = lock(&self.commit_lock)?;
            self.revalidate()?;
            self.reconcile_evictions()?;
            let stage_usage = measure_owned_tree(stage, self.expected_owner_uid)?;
            if stage_usage.bytes > reservation.bytes || stage_usage.inodes > reservation.inodes {
                return Err(PreparationStoreError::PayloadExceededReservation);
            }
            let usage = self.scan_usage()?;
            let admission = lock(&self.admission)?;
            if usage
                .bytes
                .checked_add(admission.reserved_bytes)
                .ok_or(PreparationStoreError::StoreCapacityExceeded)?
                > self.policy.max_bytes
                || usage
                    .inodes
                    .checked_add(admission.reserved_inodes)
                    .ok_or(PreparationStoreError::StoreInodeCapacityExceeded)?
                    > self.policy.max_inodes
            {
                return Err(PreparationStoreError::StoreCapacityExceeded);
            }
            drop(admission);
            validate_boundary(&self.policy, self.probe.inspect()?, 0)?;
            let final_path = self.entry_path(kind, key);
            if final_path.try_exists()? {
                return Err(PreparationStoreError::ExistingEntryConflict);
            }
            fs::rename(stage, &final_path)?;
            fs::set_permissions(&final_path, fs::Permissions::from_mode(0o555))?;
            sync_directory(
                final_path
                    .parent()
                    .ok_or(PreparationStoreError::UntrustedLayout)?,
            )?;
            sync_directory(&self.root.join("staging"))?;
            let entry = self.validate_entry(kind, key)?;
            self.touch_access(key, now_ms, false)?;
            Ok(entry)
        })();
        if result.is_err() && stage.try_exists().unwrap_or(false) {
            remove_owned_tree(stage, self.expected_owner_uid)?;
        }
        result
    }

    fn reserve(
        &self,
        estimate: StoreUsage,
        now_ms: i64,
    ) -> Result<AdmissionReservation, PreparationStoreError> {
        if estimate.bytes == 0
            || estimate.inodes == 0
            || estimate.bytes > self.policy.max_bytes
            || estimate.inodes > self.policy.max_inodes
        {
            return Err(PreparationStoreError::PayloadTooLarge);
        }
        let _commit = lock(&self.commit_lock)?;
        self.revalidate()?;
        self.reconcile_evictions()?;
        self.cleanup_expired_pins(now_ms)?;
        self.evict_until_admissible(estimate, now_ms)?;
        let boundary = self.probe.inspect()?;
        validate_boundary(&self.policy, boundary, estimate.bytes)?;
        if boundary.store_available_bytes < estimate.bytes {
            return Err(PreparationStoreError::FilesystemCapacityExceeded);
        }
        let mut admission = lock(&self.admission)?;
        admission.reserved_bytes = admission
            .reserved_bytes
            .checked_add(estimate.bytes)
            .ok_or(PreparationStoreError::StoreCapacityExceeded)?;
        admission.reserved_inodes = admission
            .reserved_inodes
            .checked_add(estimate.inodes)
            .ok_or(PreparationStoreError::StoreInodeCapacityExceeded)?;
        Ok(AdmissionReservation {
            state: Arc::clone(&self.admission),
            bytes: estimate.bytes,
            inodes: estimate.inodes,
        })
    }

    fn evict_until_admissible(
        &self,
        incoming: StoreUsage,
        now_ms: i64,
    ) -> Result<(), PreparationStoreError> {
        let admission = lock(&self.admission)?;
        let mut usage = self.scan_usage()?;
        let fits = |usage: StoreUsage| -> Result<bool, PreparationStoreError> {
            Ok(usage
                .bytes
                .checked_add(admission.reserved_bytes)
                .and_then(|value| value.checked_add(incoming.bytes))
                .ok_or(PreparationStoreError::StoreCapacityExceeded)?
                <= self.policy.max_bytes
                && usage
                    .inodes
                    .checked_add(admission.reserved_inodes)
                    .and_then(|value| value.checked_add(incoming.inodes))
                    .ok_or(PreparationStoreError::StoreInodeCapacityExceeded)?
                    <= self.policy.max_inodes)
        };
        if fits(usage)? {
            return Ok(());
        }
        let pinned = self.live_pinned_keys(now_ms)?;
        let warm_cutoff = now_ms.saturating_sub(self.policy.warm_window_ms);
        let mut candidates = self.eviction_candidates()?;
        candidates.retain(|candidate| {
            !pinned.contains(&candidate.key) && candidate.last_accessed_at_ms <= warm_cutoff
        });
        candidates.sort_by(|left, right| {
            left.last_accessed_at_ms
                .cmp(&right.last_accessed_at_ms)
                .then_with(|| left.key.cmp(&right.key))
        });
        for candidate in candidates {
            self.remove_entry(candidate.kind, &candidate.key)?;
            usage = self.scan_usage()?;
            if fits(usage)? {
                return Ok(());
            }
        }
        Err(
            if usage
                .inodes
                .checked_add(admission.reserved_inodes)
                .and_then(|value| value.checked_add(incoming.inodes))
                .is_none_or(|value| value > self.policy.max_inodes)
            {
                PreparationStoreError::StoreInodeCapacityExceeded
            } else {
                PreparationStoreError::StoreCapacityExceeded
            },
        )
    }

    fn open_existing(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<Option<PreparedEntryV1>, PreparationStoreError> {
        let _commit = lock(&self.commit_lock)?;
        self.revalidate()?;
        self.reconcile_evictions()?;
        if !self.entry_path(kind, key).try_exists()? {
            return Ok(None);
        }
        self.reconcile_entry_if_committing(kind, key)?;
        let entry = self.validate_entry(kind, key)?;
        self.touch_access(key, now_ms, true)?;
        Ok(Some(entry))
    }

    fn validate_entry(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
    ) -> Result<PreparedEntryV1, PreparationStoreError> {
        self.validate_entry_with_root_mode(kind, key, 0o555)
    }

    fn validate_entry_with_root_mode(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
        root_mode: u32,
    ) -> Result<PreparedEntryV1, PreparationStoreError> {
        let path = self.entry_path(kind, key);
        validate_directory(&path, self.expected_owner_uid, root_mode)?;
        let manifest_path = path.join("manifest.jcs");
        let manifest_bytes = read_trusted_file(
            &manifest_path,
            self.expected_owner_uid,
            0o444,
            MAX_ENTRY_MANIFEST_BYTES,
        )?;
        let manifest = PreparationEntryManifestV1::decode_canonical(&manifest_bytes)?;
        if manifest.kind != kind || manifest.key != *key {
            return Err(PreparationStoreError::EntryIdentityMismatch);
        }
        let payload = path.join("payload");
        validate_directory(&payload, self.expected_owner_uid, 0o555)?;
        let entries = inspect_sealed_payload(&payload, self.expected_owner_uid)?;
        if entries != manifest.entries {
            return Err(PreparationStoreError::EntryChecksumMismatch);
        }
        Ok(PreparedEntryV1 { manifest, path })
    }

    fn reconcile_committing_entries(&self) -> Result<(), PreparationStoreError> {
        for kind in PreparationObjectKindV1::ALL {
            for entry in sorted_directory_entries(&self.kind_directory(kind))? {
                let key = parse_digest_filename(&entry.file_name())?;
                self.reconcile_entry_if_committing(kind, &key)?;
            }
        }
        Ok(())
    }

    fn reconcile_entry_if_committing(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
    ) -> Result<(), PreparationStoreError> {
        let path = self.entry_path(kind, key);
        let metadata = fs::symlink_metadata(&path)?;
        let mode = metadata.mode() & 0o7777;
        match mode {
            0o555 => Ok(()),
            0o700 => {
                self.validate_entry_with_root_mode(kind, key, 0o700)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
                sync_directory(&self.kind_directory(kind))?;
                self.validate_entry(kind, key)?;
                Ok(())
            }
            _ => Err(PreparationStoreError::UntrustedEntry),
        }
    }

    fn create_stage(&self) -> Result<PathBuf, PreparationStoreError> {
        self.revalidate()?;
        let staging = self.root.join("staging");
        for _ in 0..8 {
            let path = staging.join(Uuid::new_v4().to_string());
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    sync_directory(&staging)?;
                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(PreparationStoreError::TemporaryNameExhausted)
    }

    fn key_lock(&self, key: &EvidenceDigest) -> Result<Arc<Mutex<()>>, PreparationStoreError> {
        let mut locks = lock(&self.key_locks)?;
        locks.retain(|_, value| value.strong_count() > 0);
        if let Some(existing) = locks.get(key).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        let created = Arc::new(Mutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&created));
        Ok(created)
    }

    fn revalidate(&self) -> Result<(), PreparationStoreError> {
        revalidate_store_root(&self.root, self.root_lock.as_ref(), self.expected_owner_uid)?;
        validate_layout(&self.root, self.expected_owner_uid)
    }

    fn scan_usage(&self) -> Result<StoreUsage, PreparationStoreError> {
        let mut usage = StoreUsage::default();
        for kind in PreparationObjectKindV1::ALL {
            let directory = self.kind_directory(kind);
            validate_directory(&directory, self.expected_owner_uid, 0o700)?;
            for entry in sorted_directory_entries(&directory)? {
                let name = entry.file_name();
                let key = parse_digest_filename(&name)?;
                let path = entry.path();
                validate_directory(&path, self.expected_owner_uid, 0o555)?;
                let measured = measure_owned_tree(&path, self.expected_owner_uid)?;
                usage = usage.checked_add(measured)?;
                if path != self.entry_path(kind, &key) {
                    return Err(PreparationStoreError::UntrustedLayout);
                }
            }
        }
        for entry in sorted_directory_entries(&self.root.join("pins"))? {
            let rendered = entry
                .file_name()
                .to_str()
                .ok_or(PreparationStoreError::UntrustedLayout)?
                .to_owned();
            let pin_id = rendered
                .strip_suffix(".jcs")
                .ok_or(PreparationStoreError::UntrustedLayout)
                .and_then(|value| {
                    Uuid::parse_str(value).map_err(|_| PreparationStoreError::UntrustedLayout)
                })?;
            let record = load_pin(&entry.path(), self.expected_owner_uid)?;
            if record.pin_id != pin_id {
                return Err(PreparationStoreError::InvalidPin);
            }
            usage =
                usage.checked_add(measure_owned_tree(&entry.path(), self.expected_owner_uid)?)?;
        }
        for entry in sorted_directory_entries(&self.root.join("access"))? {
            let rendered = entry
                .file_name()
                .to_str()
                .ok_or(PreparationStoreError::UntrustedLayout)?
                .to_owned();
            let key = rendered
                .strip_suffix(".jcs")
                .ok_or(PreparationStoreError::UntrustedLayout)
                .and_then(|value| {
                    EvidenceDigest::from_str(value)
                        .map_err(|_| PreparationStoreError::UntrustedLayout)
                })?;
            let record = load_access(&entry.path(), self.expected_owner_uid)?;
            if record.key != key {
                return Err(PreparationStoreError::InvalidAccessRecord);
            }
            usage =
                usage.checked_add(measure_owned_tree(&entry.path(), self.expected_owner_uid)?)?;
        }
        Ok(usage)
    }

    fn reconcile_access_records(&self) -> Result<(), PreparationStoreError> {
        let mut live = HashMap::new();
        for kind in PreparationObjectKindV1::ALL {
            for entry in sorted_directory_entries(&self.kind_directory(kind))? {
                let key = parse_digest_filename(&entry.file_name())?;
                let bytes = read_trusted_file(
                    &entry.path().join("manifest.jcs"),
                    self.expected_owner_uid,
                    0o444,
                    MAX_ENTRY_MANIFEST_BYTES,
                )?;
                let manifest = PreparationEntryManifestV1::decode_canonical(&bytes)?;
                if manifest.kind != kind
                    || manifest.key != key
                    || live.insert(key, manifest.created_at_ms).is_some()
                {
                    return Err(PreparationStoreError::EntryIdentityMismatch);
                }
            }
        }
        let directory = self.root.join("access");
        for entry in sorted_directory_entries(&directory)? {
            let record = load_access(&entry.path(), self.expected_owner_uid)?;
            if !live.contains_key(&record.key) {
                fs::remove_file(entry.path())?;
            }
        }
        sync_directory(&directory)?;
        for (key, created_at_ms) in live {
            let path = self.access_path(&key);
            if !path.try_exists()? {
                let record = AccessRecordV1::new(key, created_at_ms)?;
                write_atomic_document(&path, &record.canonical_bytes()?, self.expected_owner_uid)?;
            }
        }
        Ok(())
    }

    fn eviction_candidates(&self) -> Result<Vec<EvictionCandidate>, PreparationStoreError> {
        let mut candidates = Vec::new();
        for kind in PreparationObjectKindV1::ALL {
            let directory = self.kind_directory(kind);
            for entry in sorted_directory_entries(&directory)? {
                let key = parse_digest_filename(&entry.file_name())?;
                let manifest_path = entry.path().join("manifest.jcs");
                let bytes = read_trusted_file(
                    &manifest_path,
                    self.expected_owner_uid,
                    0o444,
                    MAX_ENTRY_MANIFEST_BYTES,
                )?;
                let manifest = PreparationEntryManifestV1::decode_canonical(&bytes)?;
                if manifest.key != key || manifest.kind != kind {
                    return Err(PreparationStoreError::EntryIdentityMismatch);
                }
                let access_path = self.access_path(&key);
                let last_accessed_at_ms = if access_path.try_exists()? {
                    let access = load_access(&access_path, self.expected_owner_uid)?;
                    if access.key != key {
                        return Err(PreparationStoreError::InvalidAccessRecord);
                    }
                    access.last_accessed_at_ms
                } else {
                    manifest.created_at_ms
                };
                candidates.push(EvictionCandidate {
                    kind,
                    key,
                    last_accessed_at_ms,
                });
            }
        }
        Ok(candidates)
    }

    fn remove_entry(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
    ) -> Result<(), PreparationStoreError> {
        self.validate_entry(kind, key)?;
        self.begin_eviction(kind, key)?;
        self.finish_eviction(kind, key)
    }

    fn begin_eviction(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
    ) -> Result<(), PreparationStoreError> {
        let access = self.access_path(key);
        let eviction = self.eviction_path(kind, key);
        if eviction.try_exists()? {
            let record = load_access(&eviction, self.expected_owner_uid)?;
            if record.key != *key || access.try_exists()? {
                return Err(PreparationStoreError::InvalidEvictionRecord);
            }
            return Ok(());
        }
        let record = load_access(&access, self.expected_owner_uid)?;
        if record.key != *key {
            return Err(PreparationStoreError::InvalidAccessRecord);
        }
        fs::rename(&access, &eviction)?;
        sync_directory(&self.root.join("access"))?;
        sync_directory(&self.root.join("evictions"))?;
        Ok(())
    }

    fn finish_eviction(
        &self,
        kind: PreparationObjectKindV1,
        key: &EvidenceDigest,
    ) -> Result<(), PreparationStoreError> {
        let eviction = self.eviction_path(kind, key);
        let record = load_access(&eviction, self.expected_owner_uid)?;
        if record.key != *key {
            return Err(PreparationStoreError::InvalidEvictionRecord);
        }
        let entry = self.entry_path(kind, key);
        if entry.try_exists()? {
            remove_owned_tree(&entry, self.expected_owner_uid)?;
            sync_directory(&self.kind_directory(kind))?;
        }
        fs::remove_file(&eviction)?;
        sync_directory(&self.root.join("evictions"))?;
        Ok(())
    }

    fn reconcile_evictions(&self) -> Result<(), PreparationStoreError> {
        let directory = self.root.join("evictions");
        let pending = sorted_directory_entries(&directory)?
            .into_iter()
            .map(|entry| parse_eviction_filename(&entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        for (kind, key) in pending {
            self.finish_eviction(kind, &key)?;
        }
        Ok(())
    }

    fn cleanup_expired_pins(&self, now_ms: i64) -> Result<(), PreparationStoreError> {
        let directory = self.root.join("pins");
        for entry in sorted_directory_entries(&directory)? {
            let name = entry.file_name();
            let rendered = name
                .to_str()
                .ok_or(PreparationStoreError::UntrustedLayout)?;
            let pin_id = rendered
                .strip_suffix(".jcs")
                .ok_or(PreparationStoreError::UntrustedLayout)
                .and_then(|value| {
                    Uuid::parse_str(value).map_err(|_| PreparationStoreError::UntrustedLayout)
                })?;
            let record = load_pin(&entry.path(), self.expected_owner_uid)?;
            if record.pin_id != pin_id {
                return Err(PreparationStoreError::InvalidPin);
            }
            if record.expires_at_ms <= now_ms {
                fs::remove_file(entry.path())?;
            }
        }
        sync_directory(&directory)?;
        Ok(())
    }

    fn live_pinned_keys(
        &self,
        now_ms: i64,
    ) -> Result<BTreeSet<EvidenceDigest>, PreparationStoreError> {
        let mut keys = BTreeSet::new();
        for entry in sorted_directory_entries(&self.root.join("pins"))? {
            let record = load_pin(&entry.path(), self.expected_owner_uid)?;
            if record.expires_at_ms > now_ms {
                keys.insert(record.key);
            }
        }
        Ok(keys)
    }

    fn write_pin(&self, record: &PinRecordV1) -> Result<(), PreparationStoreError> {
        let path = self.pin_path(record.pin_id);
        if path.try_exists()? {
            let existing = load_pin(&path, self.expected_owner_uid)?;
            if existing.pin_id != record.pin_id || existing.key != record.key {
                return Err(PreparationStoreError::InvalidPin);
            }
        } else {
            if sorted_directory_entries(&self.root.join("pins"))?.len() >= MAX_LIVE_PINS {
                return Err(PreparationStoreError::PinCapacityExceeded);
            }
            self.ensure_sidecar_admissible()?;
        }
        write_atomic_document(&path, &record.canonical_bytes()?, self.expected_owner_uid)
    }

    fn touch_access(
        &self,
        key: &EvidenceDigest,
        now_ms: i64,
        account_new_sidecar: bool,
    ) -> Result<(), PreparationStoreError> {
        let path = self.access_path(key);
        let last_accessed_at_ms = if path.try_exists()? {
            let existing = load_access(&path, self.expected_owner_uid)?;
            if existing.key != *key {
                return Err(PreparationStoreError::InvalidAccessRecord);
            }
            existing.last_accessed_at_ms.max(now_ms)
        } else {
            if account_new_sidecar {
                self.ensure_sidecar_admissible()?;
            }
            now_ms
        };
        let record = AccessRecordV1::new(key.clone(), last_accessed_at_ms)?;
        write_atomic_document(&path, &record.canonical_bytes()?, self.expected_owner_uid)
    }

    fn ensure_sidecar_admissible(&self) -> Result<(), PreparationStoreError> {
        let boundary = self.probe.inspect()?;
        let sidecar_bytes = boundary
            .allocation_granularity
            .checked_mul(2)
            .ok_or(PreparationStoreError::StoreCapacityExceeded)?;
        validate_boundary(&self.policy, boundary, sidecar_bytes)?;
        if boundary.store_available_bytes < sidecar_bytes {
            return Err(PreparationStoreError::FilesystemCapacityExceeded);
        }
        let usage = self.scan_usage()?;
        let admission = lock(&self.admission)?;
        if usage
            .bytes
            .checked_add(admission.reserved_bytes)
            .and_then(|value| value.checked_add(sidecar_bytes))
            .is_none_or(|value| value > self.policy.max_bytes)
        {
            return Err(PreparationStoreError::StoreCapacityExceeded);
        }
        if usage
            .inodes
            .checked_add(admission.reserved_inodes)
            .and_then(|value| value.checked_add(1))
            .is_none_or(|value| value > self.policy.max_inodes)
        {
            return Err(PreparationStoreError::StoreInodeCapacityExceeded);
        }
        Ok(())
    }

    fn kind_directory(&self, kind: PreparationObjectKindV1) -> PathBuf {
        self.root.join("objects").join(kind.directory_name())
    }

    fn entry_path(&self, kind: PreparationObjectKindV1, key: &EvidenceDigest) -> PathBuf {
        self.kind_directory(kind).join(key.as_str())
    }

    fn pin_path(&self, pin_id: Uuid) -> PathBuf {
        self.root.join("pins").join(format!("{pin_id}.jcs"))
    }

    fn access_path(&self, key: &EvidenceDigest) -> PathBuf {
        self.root
            .join("access")
            .join(format!("{}.jcs", key.as_str()))
    }

    fn eviction_path(&self, kind: PreparationObjectKindV1, key: &EvidenceDigest) -> PathBuf {
        self.root
            .join("evictions")
            .join(format!("{}-{}.jcs", kind.directory_name(), key.as_str()))
    }
}

fn source_key_material(
    lease: &WorkflowLeaseV1,
    manifest: &SourceArchiveManifestV1,
) -> Result<PreparationKeyMaterialV1, PreparationStoreError> {
    let source_identity = lease.required_source_identity()?;
    if manifest.project_id != lease.project_id
        || manifest.head != lease.source_sha
        || manifest.sequence != source_identity.sequence
        || manifest.source_attestation_digest != source_identity.attestation_digest
        || manifest.installed_policy.digest != lease.workflow_policy_digest
    {
        return Err(PreparationStoreError::SourceLeaseMismatch);
    }
    Ok(PreparationKeyMaterialV1::SourceSnapshot {
        project_id: manifest.project_id.clone(),
        source_sha: manifest.head.clone(),
        source_sequence: manifest.sequence,
        source_attestation_digest: manifest.source_attestation_digest.clone(),
        workflow_policy_digest: manifest.installed_policy.digest.clone(),
        repository_identity: manifest.repository_identity.clone(),
        archive_digest: manifest.archive_sha256.clone(),
        archive_bytes: manifest.archive_bytes,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct StoreUsage {
    bytes: u64,
    inodes: u64,
}

impl StoreUsage {
    fn checked_add(self, other: Self) -> Result<Self, PreparationStoreError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(PreparationStoreError::StoreCapacityExceeded)?,
            inodes: self
                .inodes
                .checked_add(other.inodes)
                .ok_or(PreparationStoreError::StoreInodeCapacityExceeded)?,
        })
    }
}

#[derive(Clone, Debug)]
struct EvictionCandidate {
    kind: PreparationObjectKindV1,
    key: EvidenceDigest,
    last_accessed_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputInventory {
    root: PathBuf,
    root_identity: InputIdentity,
    entries: Vec<InputInventoryEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
    links: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputInventoryEntry {
    relative: PathBuf,
    identity: InputIdentity,
    kind: PreparationPayloadEntryKindV1,
    sealed_mode: u32,
}

fn inspect_input_directory(root: &Path) -> Result<InputInventory, PreparationStoreError> {
    if !root.is_absolute() || fs::canonicalize(root)? != root {
        return Err(PreparationStoreError::UntrustedInput);
    }
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PreparationStoreError::UntrustedInput);
    }
    let root_identity = input_identity(&metadata);
    let mut entries = Vec::new();
    collect_input_entries(root, Path::new(""), &mut entries)?;
    if entries.is_empty()
        || u64::try_from(entries.len()).map_err(|_| PreparationStoreError::PayloadTooLarge)? + 3
            > MAX_PREPARATION_STORE_INODES
    {
        return Err(PreparationStoreError::PayloadTooLarge);
    }
    entries.sort_by(|left, right| {
        left.relative
            .as_os_str()
            .as_bytes()
            .cmp(right.relative.as_os_str().as_bytes())
    });
    Ok(InputInventory {
        root: root.to_path_buf(),
        root_identity,
        entries,
    })
}

fn collect_input_entries(
    root: &Path,
    relative: &Path,
    entries: &mut Vec<InputInventoryEntry>,
) -> Result<(), PreparationStoreError> {
    let directory = root.join(relative);
    for entry in sorted_directory_entries(&directory)? {
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        validate_relative_path(&child_relative)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let identity = input_identity(&metadata);
        if metadata.file_type().is_symlink() {
            return Err(PreparationStoreError::UnsupportedInputType);
        }
        if metadata.is_dir() {
            entries.push(InputInventoryEntry {
                relative: child_relative.clone(),
                identity,
                kind: PreparationPayloadEntryKindV1::Directory,
                sealed_mode: 0o555,
            });
            collect_input_entries(root, &child_relative, entries)?;
        } else if metadata.is_file() {
            if metadata.nlink() != 1 {
                return Err(PreparationStoreError::UnsupportedInputType);
            }
            let executable = metadata.mode() & 0o111 != 0;
            entries.push(InputInventoryEntry {
                relative: child_relative,
                identity,
                kind: PreparationPayloadEntryKindV1::RegularFile,
                sealed_mode: if executable { 0o555 } else { 0o444 },
            });
        } else {
            return Err(PreparationStoreError::UnsupportedInputType);
        }
        if entries.len() > usize::try_from(MAX_PREPARATION_STORE_INODES).unwrap_or(usize::MAX) {
            return Err(PreparationStoreError::PayloadTooLarge);
        }
    }
    Ok(())
}

fn input_identity(metadata: &fs::Metadata) -> InputIdentity {
    InputIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        length: metadata.len(),
        links: metadata.nlink(),
    }
}

fn copy_inventory(
    inventory: &InputInventory,
    destination: &Path,
) -> Result<Vec<PreparationPayloadEntryV1>, PreparationStoreError> {
    let root_metadata = fs::symlink_metadata(&inventory.root)?;
    if input_identity(&root_metadata) != inventory.root_identity {
        return Err(PreparationStoreError::InputChanged);
    }
    let mut manifest_entries = Vec::with_capacity(inventory.entries.len());
    for entry in &inventory.entries {
        let source_path = inventory.root.join(&entry.relative);
        let destination_path = destination.join(&entry.relative);
        let metadata = fs::symlink_metadata(&source_path)?;
        if input_identity(&metadata) != entry.identity {
            return Err(PreparationStoreError::InputChanged);
        }
        match entry.kind {
            PreparationPayloadEntryKindV1::Directory => {
                create_directory(&destination_path, 0o700)?;
                manifest_entries.push(PreparationPayloadEntryV1 {
                    path_base64url: encode_relative_path(&entry.relative)?,
                    entry_kind: PreparationPayloadEntryKindV1::Directory,
                    mode: 0o555,
                    bytes: 0,
                    sha256: None,
                });
            }
            PreparationPayloadEntryKindV1::RegularFile => {
                let source = File::open(&source_path)?;
                if input_identity(&source.metadata()?) != entry.identity {
                    return Err(PreparationStoreError::InputChanged);
                }
                let copied = write_payload_reader_unverified(
                    destination,
                    &entry.relative,
                    source,
                    entry.identity.length,
                    entry.sealed_mode == 0o555,
                )?;
                if input_identity(&fs::symlink_metadata(&source_path)?) != entry.identity {
                    return Err(PreparationStoreError::InputChanged);
                }
                manifest_entries.push(copied);
            }
        }
    }
    manifest_entries.sort_by(compare_manifest_entries);
    Ok(manifest_entries)
}

fn estimate_inventory(
    inventory: &InputInventory,
    block_size: u64,
) -> Result<StoreUsage, PreparationStoreError> {
    let payload_bytes = inventory.entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(
                if entry.kind == PreparationPayloadEntryKindV1::RegularFile {
                    entry.identity.length
                } else {
                    0
                },
            )
            .ok_or(PreparationStoreError::PayloadTooLarge)
    })?;
    let inodes = u64::try_from(inventory.entries.len())
        .map_err(|_| PreparationStoreError::PayloadTooLarge)?
        .checked_add(4)
        .ok_or(PreparationStoreError::PayloadTooLarge)?;
    estimate_payload(payload_bytes, inodes, block_size)
}

fn estimate_payload(
    payload_bytes: u64,
    inodes: u64,
    block_size: u64,
) -> Result<StoreUsage, PreparationStoreError> {
    if block_size == 0 {
        return Err(PreparationStoreError::InvalidFilesystemBoundary);
    }
    let rounded_payload = round_up(payload_bytes, block_size)?;
    let inode_overhead = inodes
        .checked_mul(block_size)
        .and_then(|value| value.checked_mul(2))
        .ok_or(PreparationStoreError::PayloadTooLarge)?;
    let manifest_overhead = inodes
        .checked_mul(512)
        .ok_or(PreparationStoreError::PayloadTooLarge)?;
    Ok(StoreUsage {
        bytes: rounded_payload
            .checked_add(inode_overhead)
            .and_then(|value| value.checked_add(round_up(manifest_overhead, block_size).ok()?))
            .ok_or(PreparationStoreError::PayloadTooLarge)?,
        inodes,
    })
}

fn round_up(value: u64, granularity: u64) -> Result<u64, PreparationStoreError> {
    if granularity == 0 {
        return Err(PreparationStoreError::InvalidFilesystemBoundary);
    }
    value
        .checked_add(granularity - 1)
        .map(|rounded| rounded / granularity * granularity)
        .ok_or(PreparationStoreError::PayloadTooLarge)
}

fn write_payload_reader<R: io::Read>(
    payload: &Path,
    relative: &Path,
    reader: R,
    expected_bytes: u64,
    expected_digest: &EvidenceDigest,
    executable: bool,
) -> Result<PreparationPayloadEntryV1, PreparationStoreError> {
    let entry =
        write_payload_reader_unverified(payload, relative, reader, expected_bytes, executable)?;
    if entry.sha256.as_ref() != Some(expected_digest) {
        return Err(PreparationStoreError::InputDigestMismatch);
    }
    Ok(entry)
}

fn write_payload_reader_unverified<R: io::Read>(
    payload: &Path,
    relative: &Path,
    mut reader: R,
    expected_bytes: u64,
    executable: bool,
) -> Result<PreparationPayloadEntryV1, PreparationStoreError> {
    validate_relative_path(relative)?;
    let destination = payload.join(relative);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; FILE_COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| PreparationStoreError::PayloadTooLarge)?)
            .ok_or(PreparationStoreError::PayloadTooLarge)?;
        if copied > expected_bytes {
            return Err(PreparationStoreError::InputChanged);
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    if copied != expected_bytes {
        return Err(PreparationStoreError::InputChanged);
    }
    output.flush()?;
    output.set_permissions(fs::Permissions::from_mode(if executable {
        0o555
    } else {
        0o444
    }))?;
    output.sync_all()?;
    let digest = digest_hasher(hasher)?;
    Ok(PreparationPayloadEntryV1 {
        path_base64url: encode_relative_path(relative)?,
        entry_kind: PreparationPayloadEntryKindV1::RegularFile,
        mode: if executable { 0o555 } else { 0o444 },
        bytes: copied,
        sha256: Some(digest),
    })
}

fn seal_stage(
    stage: &Path,
    manifest: &PreparationEntryManifestV1,
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    let manifest_bytes = manifest.canonical_bytes()?;
    if u64::try_from(manifest_bytes.len()).map_err(|_| PreparationStoreError::PayloadTooLarge)?
        > MAX_ENTRY_MANIFEST_BYTES
    {
        return Err(PreparationStoreError::PayloadTooLarge);
    }
    let manifest_path = stage.join("manifest.jcs");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)?;
    file.write_all(&manifest_bytes)?;
    file.flush()?;
    file.set_permissions(fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    let payload = stage.join("payload");
    seal_directories_bottom_up(&payload, expected_owner_uid)?;
    sync_directory(&payload)?;
    sync_directory(stage)?;
    Ok(())
}

fn seal_directories_bottom_up(
    directory: &Path,
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    validate_directory(directory, expected_owner_uid, 0o700)?;
    for entry in sorted_directory_entries(directory)? {
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            seal_directories_bottom_up(&entry.path(), expected_owner_uid)?;
        }
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    sync_directory(directory)
}

fn inspect_sealed_payload(
    payload: &Path,
    expected_owner_uid: u32,
) -> Result<Vec<PreparationPayloadEntryV1>, PreparationStoreError> {
    let mut entries = Vec::new();
    collect_sealed_entries(payload, Path::new(""), expected_owner_uid, &mut entries)?;
    entries.sort_by(compare_manifest_entries);
    Ok(entries)
}

fn collect_sealed_entries(
    payload: &Path,
    relative: &Path,
    expected_owner_uid: u32,
    entries: &mut Vec<PreparationPayloadEntryV1>,
) -> Result<(), PreparationStoreError> {
    for entry in sorted_directory_entries(&payload.join(relative))? {
        let child_relative = relative.join(entry.file_name());
        validate_relative_path(&child_relative)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || metadata.uid() != expected_owner_uid {
            return Err(PreparationStoreError::UntrustedEntry);
        }
        if metadata.is_dir() {
            if metadata.mode() & 0o7777 != 0o555 {
                return Err(PreparationStoreError::UntrustedEntry);
            }
            entries.push(PreparationPayloadEntryV1 {
                path_base64url: encode_relative_path(&child_relative)?,
                entry_kind: PreparationPayloadEntryKindV1::Directory,
                mode: 0o555,
                bytes: 0,
                sha256: None,
            });
            collect_sealed_entries(payload, &child_relative, expected_owner_uid, entries)?;
        } else if metadata.is_file() {
            let mode = metadata.mode() & 0o7777;
            if !matches!(mode, 0o444 | 0o555) || metadata.nlink() != 1 {
                return Err(PreparationStoreError::UntrustedEntry);
            }
            let (bytes, digest) = hash_trusted_file(
                &entry.path(),
                expected_owner_uid,
                mode,
                MAX_PREPARATION_STORE_BYTES,
            )?;
            entries.push(PreparationPayloadEntryV1 {
                path_base64url: encode_relative_path(&child_relative)?,
                entry_kind: PreparationPayloadEntryKindV1::RegularFile,
                mode,
                bytes,
                sha256: Some(digest),
            });
        } else {
            return Err(PreparationStoreError::UntrustedEntry);
        }
        if entries.len() > usize::try_from(MAX_PREPARATION_STORE_INODES).unwrap_or(usize::MAX) {
            return Err(PreparationStoreError::PayloadTooLarge);
        }
    }
    Ok(())
}

fn compare_manifest_entries(
    left: &PreparationPayloadEntryV1,
    right: &PreparationPayloadEntryV1,
) -> std::cmp::Ordering {
    let left = URL_SAFE_NO_PAD
        .decode(&left.path_base64url)
        .unwrap_or_default();
    let right = URL_SAFE_NO_PAD
        .decode(&right.path_base64url)
        .unwrap_or_default();
    left.cmp(&right)
}

fn encode_relative_path(path: &Path) -> Result<String, PreparationStoreError> {
    validate_relative_path(path)?;
    Ok(URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes()))
}

fn decode_relative_path(encoded: &str) -> Result<PathBuf, PreparationStoreError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PreparationStoreError::InvalidEntryManifest)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(PreparationStoreError::InvalidEntryManifest);
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    validate_relative_path(&path)?;
    Ok(path)
}

fn validate_relative_path(path: &Path) -> Result<(), PreparationStoreError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_PATH_BYTES || bytes.contains(&0) {
        return Err(PreparationStoreError::InvalidPayloadPath);
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(PreparationStoreError::InvalidPayloadPath);
    }
    Ok(())
}

fn digest_hasher(hasher: Sha256) -> Result<EvidenceDigest, PreparationStoreError> {
    let mut rendered = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut rendered, "{byte:02x}");
    }
    EvidenceDigest::from_str(&rendered).map_err(|_| PreparationStoreError::InvalidDigest)
}

fn validate_time(now_ms: i64) -> Result<(), PreparationStoreError> {
    if now_ms < 0 {
        Err(PreparationStoreError::InvalidTime)
    } else {
        Ok(())
    }
}

fn validate_boundary(
    policy: &PreparationStorePolicy,
    boundary: FilesystemBoundarySnapshot,
    incoming_bytes: u64,
) -> Result<(), PreparationStoreError> {
    if !boundary.dedicated_mount
        || boundary.allocation_granularity == 0
        || boundary.store_total_bytes < policy.max_bytes
    {
        return Err(PreparationStoreError::InvalidFilesystemBoundary);
    }
    let required_root = policy
        .root_emergency_reserve_bytes
        .checked_add(incoming_bytes)
        .ok_or(PreparationStoreError::RootEmergencyReserveViolated)?;
    if boundary.root_available_bytes < required_root {
        return Err(PreparationStoreError::RootEmergencyReserveViolated);
    }
    Ok(())
}

fn initialize_layout(root: &Path, expected_owner_uid: u32) -> Result<(), PreparationStoreError> {
    for path in [
        root.join("objects"),
        root.join("staging"),
        root.join("pins"),
        root.join("access"),
        root.join("evictions"),
    ] {
        ensure_private_directory(&path, expected_owner_uid)?;
    }
    for kind in PreparationObjectKindV1::ALL {
        ensure_private_directory(
            &root.join("objects").join(kind.directory_name()),
            expected_owner_uid,
        )?;
    }
    sync_directory(root)
}

fn validate_layout(root: &Path, expected_owner_uid: u32) -> Result<(), PreparationStoreError> {
    validate_directory(&root.join("objects"), expected_owner_uid, 0o700)?;
    validate_directory(&root.join("staging"), expected_owner_uid, 0o700)?;
    validate_directory(&root.join("pins"), expected_owner_uid, 0o700)?;
    validate_directory(&root.join("access"), expected_owner_uid, 0o700)?;
    validate_directory(&root.join("evictions"), expected_owner_uid, 0o700)?;
    for kind in PreparationObjectKindV1::ALL {
        validate_directory(
            &root.join("objects").join(kind.directory_name()),
            expected_owner_uid,
            0o700,
        )?;
    }
    Ok(())
}

fn ensure_private_directory(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            sync_directory(
                path.parent()
                    .ok_or(PreparationStoreError::UntrustedLayout)?,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_directory(path, expected_owner_uid, 0o700)
}

fn create_directory(path: &Path, mode: u32) -> Result<(), PreparationStoreError> {
    DirBuilder::new().mode(mode).create(path)?;
    Ok(())
}

fn validate_store_root(root: &Path, expected_owner_uid: u32) -> Result<(), PreparationStoreError> {
    if !root.is_absolute() || fs::canonicalize(root)? != root {
        return Err(PreparationStoreError::UntrustedRoot);
    }
    validate_directory(root, expected_owner_uid, 0o700)
        .map_err(|_| PreparationStoreError::UntrustedRoot)
}

fn revalidate_store_root(
    root: &Path,
    root_lock: &File,
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    validate_store_root(root, expected_owner_uid)?;
    let path_metadata = fs::symlink_metadata(root)?;
    let locked_metadata = root_lock.metadata()?;
    if path_metadata.dev() != locked_metadata.dev()
        || path_metadata.ino() != locked_metadata.ino()
        || locked_metadata.uid() != expected_owner_uid
        || locked_metadata.mode() & 0o7777 != 0o700
        || !locked_metadata.is_dir()
    {
        return Err(PreparationStoreError::UntrustedRoot);
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<(), PreparationStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(PreparationStoreError::UntrustedLayout);
    }
    Ok(())
}

fn read_trusted_file(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, PreparationStoreError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != expected_owner_uid
        || path_metadata.mode() & 0o7777 != expected_mode
        || path_metadata.nlink() != 1
        || path_metadata.len() > max_bytes
    {
        return Err(PreparationStoreError::UntrustedEntry);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.uid() != path_metadata.uid()
        || opened.mode() != path_metadata.mode()
        || opened.nlink() != 1
        || opened.len() != path_metadata.len()
    {
        return Err(PreparationStoreError::EntryChanged);
    }
    let capacity =
        usize::try_from(opened.len()).map_err(|_| PreparationStoreError::PayloadTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| PreparationStoreError::PayloadTooLarge)?
        != opened.len()
        || input_identity(&fs::symlink_metadata(path)?) != input_identity(&opened)
    {
        return Err(PreparationStoreError::EntryChanged);
    }
    Ok(bytes)
}

fn hash_trusted_file(
    path: &Path,
    expected_owner_uid: u32,
    expected_mode: u32,
    max_bytes: u64,
) -> Result<(u64, EvidenceDigest), PreparationStoreError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != expected_owner_uid
        || path_metadata.mode() & 0o7777 != expected_mode
        || path_metadata.nlink() != 1
        || path_metadata.len() > max_bytes
    {
        return Err(PreparationStoreError::UntrustedEntry);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if input_identity(&opened) != input_identity(&path_metadata) {
        return Err(PreparationStoreError::EntryChanged);
    }
    let mut hasher = Sha256::new();
    let mut read_total = 0_u64;
    let mut buffer = vec![0_u8; FILE_COPY_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(u64::try_from(read).map_err(|_| PreparationStoreError::PayloadTooLarge)?)
            .ok_or(PreparationStoreError::PayloadTooLarge)?;
        if read_total > opened.len() {
            return Err(PreparationStoreError::EntryChanged);
        }
        hasher.update(&buffer[..read]);
    }
    if read_total != opened.len()
        || input_identity(&fs::symlink_metadata(path)?) != input_identity(&opened)
    {
        return Err(PreparationStoreError::EntryChanged);
    }
    Ok((read_total, digest_hasher(hasher)?))
}

fn measure_owned_tree(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<StoreUsage, PreparationStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner_uid
        || (!metadata.is_dir() && !metadata.is_file())
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err(PreparationStoreError::UntrustedEntry);
    }
    let mut usage = StoreUsage {
        bytes: metadata
            .blocks()
            .checked_mul(512)
            .ok_or(PreparationStoreError::StoreCapacityExceeded)?,
        inodes: 1,
    };
    if metadata.is_dir() {
        for entry in sorted_directory_entries(path)? {
            usage = usage.checked_add(measure_owned_tree(&entry.path(), expected_owner_uid)?)?;
        }
    }
    Ok(usage)
}

fn remove_owned_tree(path: &Path, expected_owner_uid: u32) -> Result<(), PreparationStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner_uid
        || (!metadata.is_dir() && !metadata.is_file())
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err(PreparationStoreError::UntrustedEntry);
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in sorted_directory_entries(path)? {
            remove_owned_tree(&entry.path(), expected_owner_uid)?;
        }
        fs::remove_dir(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn reconcile_staging(root: &Path, expected_owner_uid: u32) -> Result<(), PreparationStoreError> {
    let staging = root.join("staging");
    for entry in sorted_directory_entries(&staging)? {
        let name = entry
            .file_name()
            .to_str()
            .ok_or(PreparationStoreError::UntrustedLayout)?
            .to_owned();
        Uuid::parse_str(&name).map_err(|_| PreparationStoreError::UntrustedLayout)?;
        remove_owned_tree(&entry.path(), expected_owner_uid)?;
    }
    sync_directory(&staging)
}

fn reconcile_sidecar_temporaries(
    directory: &Path,
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    for entry in sorted_directory_entries(directory)? {
        let name = entry.file_name();
        let Some(rendered) = name.to_str() else {
            return Err(PreparationStoreError::UntrustedLayout);
        };
        if !rendered.starts_with('.')
            || !Path::new(rendered)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != expected_owner_uid
            || metadata.nlink() != 1
            || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
        {
            return Err(PreparationStoreError::UntrustedLayout);
        }
        fs::remove_file(entry.path())?;
    }
    sync_directory(directory)
}

fn sorted_directory_entries(path: &Path) -> Result<Vec<fs::DirEntry>, PreparationStoreError> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    Ok(entries)
}

fn parse_digest_filename(name: &OsStr) -> Result<EvidenceDigest, PreparationStoreError> {
    let rendered = name
        .to_str()
        .ok_or(PreparationStoreError::UntrustedLayout)?;
    EvidenceDigest::from_str(rendered).map_err(|_| PreparationStoreError::UntrustedLayout)
}

fn parse_eviction_filename(
    name: &OsStr,
) -> Result<(PreparationObjectKindV1, EvidenceDigest), PreparationStoreError> {
    let rendered = name
        .to_str()
        .and_then(|value| value.strip_suffix(".jcs"))
        .ok_or(PreparationStoreError::InvalidEvictionRecord)?;
    for kind in PreparationObjectKindV1::ALL {
        let prefix = format!("{}-", kind.directory_name());
        if let Some(key) = rendered.strip_prefix(&prefix) {
            return Ok((
                kind,
                EvidenceDigest::from_str(key)
                    .map_err(|_| PreparationStoreError::InvalidEvictionRecord)?,
            ));
        }
    }
    Err(PreparationStoreError::InvalidEvictionRecord)
}

fn sync_directory(path: &Path) -> Result<(), PreparationStoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, PreparationStoreError> {
    mutex
        .lock()
        .map_err(|_| PreparationStoreError::OperationLockPoisoned)
}

#[cfg(target_os = "linux")]
fn is_exact_mount_point(path: &Path) -> Result<bool, PreparationStoreError> {
    let contents = fs::read("/proc/self/mountinfo")?;
    for line in contents.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
        if fields.len() < 6 {
            return Err(PreparationStoreError::InvalidFilesystemBoundary);
        }
        let mount_point = decode_mountinfo_field(fields[4])?;
        if Path::new(&OsString::from_vec(mount_point)) == path {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn is_exact_mount_point(_path: &Path) -> Result<bool, PreparationStoreError> {
    Ok(false)
}

fn decode_mountinfo_field(field: &[u8]) -> Result<Vec<u8>, PreparationStoreError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        let escaped = field
            .get(index + 1..index + 4)
            .ok_or(PreparationStoreError::InvalidFilesystemBoundary)?;
        let byte = match escaped {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(PreparationStoreError::InvalidFilesystemBoundary),
        };
        decoded.push(byte);
        index += 4;
    }
    Ok(decoded)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PinRecordV1 {
    purpose: String,
    schema_version: u16,
    pin_id: Uuid,
    key: EvidenceDigest,
    expires_at_ms: i64,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct PinRecordPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    pin_id: Uuid,
    key: &'a EvidenceDigest,
    expires_at_ms: i64,
}

impl PinRecordV1 {
    fn new(
        pin_id: Uuid,
        key: EvidenceDigest,
        expires_at_ms: i64,
    ) -> Result<Self, PreparationStoreError> {
        let mut record = Self {
            purpose: PREPARATION_PIN_PURPOSE.to_owned(),
            schema_version: PREPARATION_PIN_SCHEMA_VERSION,
            pin_id,
            key,
            expires_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        record.document_digest = record.calculate_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), PreparationStoreError> {
        if self.purpose != PREPARATION_PIN_PURPOSE
            || self.schema_version != PREPARATION_PIN_SCHEMA_VERSION
            || self.pin_id.is_nil()
            || self.expires_at_ms < 0
            || self.document_digest != self.calculate_digest()?
        {
            return Err(PreparationStoreError::InvalidPin);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, PreparationStoreError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &PinRecordPayload {
                purpose: PREPARATION_PIN_PURPOSE,
                schema_version: self.schema_version,
                pin_id: self.pin_id,
                key: &self.key,
                expires_at_ms: self.expires_at_ms,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PreparationStoreError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, PreparationStoreError> {
        let record: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&record)? != bytes {
            return Err(PreparationStoreError::NonCanonicalDocument);
        }
        record.validate()?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessRecordV1 {
    purpose: String,
    schema_version: u16,
    key: EvidenceDigest,
    last_accessed_at_ms: i64,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct AccessRecordPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    key: &'a EvidenceDigest,
    last_accessed_at_ms: i64,
}

impl AccessRecordV1 {
    fn new(key: EvidenceDigest, last_accessed_at_ms: i64) -> Result<Self, PreparationStoreError> {
        let mut record = Self {
            purpose: PREPARATION_ACCESS_PURPOSE.to_owned(),
            schema_version: PREPARATION_ACCESS_SCHEMA_VERSION,
            key,
            last_accessed_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        record.document_digest = record.calculate_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), PreparationStoreError> {
        if self.purpose != PREPARATION_ACCESS_PURPOSE
            || self.schema_version != PREPARATION_ACCESS_SCHEMA_VERSION
            || self.last_accessed_at_ms < 0
            || self.document_digest != self.calculate_digest()?
        {
            return Err(PreparationStoreError::InvalidAccessRecord);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, PreparationStoreError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &AccessRecordPayload {
                purpose: PREPARATION_ACCESS_PURPOSE,
                schema_version: self.schema_version,
                key: &self.key,
                last_accessed_at_ms: self.last_accessed_at_ms,
            },
        )?))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PreparationStoreError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, PreparationStoreError> {
        let record: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&record)? != bytes {
            return Err(PreparationStoreError::NonCanonicalDocument);
        }
        record.validate()?;
        Ok(record)
    }
}

fn load_pin(path: &Path, expected_owner_uid: u32) -> Result<PinRecordV1, PreparationStoreError> {
    let bytes = read_trusted_file(path, expected_owner_uid, 0o400, MAX_ENTRY_MANIFEST_BYTES)?;
    PinRecordV1::decode_canonical(&bytes)
}

fn load_access(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<AccessRecordV1, PreparationStoreError> {
    let bytes = read_trusted_file(path, expected_owner_uid, 0o400, MAX_ENTRY_MANIFEST_BYTES)?;
    AccessRecordV1::decode_canonical(&bytes)
}

fn write_atomic_document(
    path: &Path,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<(), PreparationStoreError> {
    if u64::try_from(bytes.len()).map_err(|_| PreparationStoreError::PayloadTooLarge)?
        > MAX_ENTRY_MANIFEST_BYTES
    {
        return Err(PreparationStoreError::PayloadTooLarge);
    }
    let parent = path
        .parent()
        .ok_or(PreparationStoreError::UntrustedLayout)?;
    validate_directory(parent, expected_owner_uid, 0o700)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() && temporary.try_exists().unwrap_or(false) {
        fs::remove_file(&temporary)?;
        sync_directory(parent)?;
    }
    result
}

#[derive(Debug, thiserror::Error)]
pub enum PreparationStoreError {
    #[error("preparation key material is invalid")]
    InvalidKeyMaterial,
    #[error("preparation store policy is invalid")]
    InvalidPolicy,
    #[error("preparation store root is not a canonical private owner directory")]
    UntrustedRoot,
    #[error("preparation store layout is not trusted")]
    UntrustedLayout,
    #[error("preparation store is already open by another process")]
    StoreAlreadyOpen,
    #[error("preparation store requires its own mounted filesystem and valid capacity facts")]
    InvalidFilesystemBoundary,
    #[error("preparation would violate the root filesystem emergency reserve")]
    RootEmergencyReserveViolated,
    #[error("preparation filesystem does not have enough available space")]
    FilesystemCapacityExceeded,
    #[error("preparation store byte capacity is exhausted")]
    StoreCapacityExceeded,
    #[error("preparation store inode capacity is exhausted")]
    StoreInodeCapacityExceeded,
    #[error("preparation store is already over its configured capacity")]
    StoreOverCapacity,
    #[error("preparation payload exceeds the bounded store contract")]
    PayloadTooLarge,
    #[error("preparation payload used more disk than its conservative reservation")]
    PayloadExceededReservation,
    #[error("preparation input directory is not a canonical directory")]
    UntrustedInput,
    #[error("preparation input contains a symlink, hard link, or special file")]
    UnsupportedInputType,
    #[error("preparation input changed while it was copied")]
    InputChanged,
    #[error("preparation input digest does not match its accepted manifest")]
    InputDigestMismatch,
    #[error("preparation payload path is invalid")]
    InvalidPayloadPath,
    #[error("preparation entry manifest is invalid")]
    InvalidEntryManifest,
    #[error("preparation document is not canonical JCS")]
    NonCanonicalDocument,
    #[error("preparation entry identity does not match its object path")]
    EntryIdentityMismatch,
    #[error("preparation entry contains an untrusted file or directory")]
    UntrustedEntry,
    #[error("preparation entry changed while it was opened")]
    EntryChanged,
    #[error("preparation entry payload does not match its sealed checksums")]
    EntryChecksumMismatch,
    #[error("preparation source archive does not match the exact workflow lease")]
    SourceLeaseMismatch,
    #[error("preparation producer failed: {0}")]
    ProducerFailed(String),
    #[error("preparation entry unexpectedly already exists")]
    ExistingEntryConflict,
    #[error("preparation pin is invalid")]
    InvalidPin,
    #[error("preparation store has too many live pins")]
    PinCapacityExceeded,
    #[error("preparation access record is invalid")]
    InvalidAccessRecord,
    #[error("preparation eviction record is invalid")]
    InvalidEvictionRecord,
    #[error("preparation operation lock is poisoned")]
    OperationLockPoisoned,
    #[error("preparation temporary name allocation was exhausted")]
    TemporaryNameExhausted,
    #[error("preparation timestamp is invalid")]
    InvalidTime,
    #[error("preparation store clock is unavailable")]
    ClockUnavailable,
    #[error("preparation digest rendering failed")]
    InvalidDigest,
    #[error("source archive contract failed: {0}")]
    SourceArchive(#[from] SourceArchiveError),
    #[error("workflow lease contract failed: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("preparation JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("preparation I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read as _, Write as _},
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{
        build_source::{SourceArchiveInputV1, SourceArchivePublisherV1},
        domain::{
            InstalledPolicyIdentity, ProjectManifestV2, WorkflowNodeKindV1, WorkflowWorkerPoolV1,
        },
    };

    #[derive(Debug)]
    struct TestProbe {
        snapshot: Mutex<FilesystemBoundarySnapshot>,
    }

    impl FilesystemBoundaryProbe for TestProbe {
        fn inspect(&self) -> Result<FilesystemBoundarySnapshot, PreparationStoreError> {
            self.snapshot
                .lock()
                .map(|snapshot| *snapshot)
                .map_err(|_| PreparationStoreError::OperationLockPoisoned)
        }
    }

    fn policy(max_bytes: u64, max_inodes: u64, warm_window_ms: i64) -> PreparationStorePolicy {
        PreparationStorePolicy {
            max_bytes,
            max_inodes,
            root_emergency_reserve_bytes: MIN_ROOT_EMERGENCY_RESERVE_BYTES,
            warm_window_ms,
        }
    }

    fn probe(max_bytes: u64) -> Arc<TestProbe> {
        Arc::new(TestProbe {
            snapshot: Mutex::new(FilesystemBoundarySnapshot {
                dedicated_mount: true,
                store_total_bytes: max_bytes.max(1024 * 1024 * 1024),
                store_available_bytes: 1024 * 1024 * 1024,
                root_available_bytes: 64 * 1024 * 1024 * 1024,
                allocation_granularity: 4_096,
            }),
        })
    }

    fn store_root(directory: &TempDir) -> PathBuf {
        let root = directory.path().join("preparation");
        fs::create_dir(&root).expect("create preparation root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("set preparation root mode");
        root
    }

    fn open_test_store(
        root: &Path,
        policy: PreparationStorePolicy,
        probe: Arc<TestProbe>,
    ) -> PreparationStore {
        let owner = fs::metadata(root).expect("store root metadata").uid();
        PreparationStore::open_with_policy(root.to_path_buf(), owner, policy, probe)
            .expect("open test preparation store")
    }

    fn dependency_material(label: &str) -> PreparationKeyMaterialV1 {
        PreparationKeyMaterialV1::DependencySnapshot {
            toolchain_digest: EvidenceDigest::sha256(format!("toolchain-{label}")),
            lockfile_digest: EvidenceDigest::sha256(format!("lockfile-{label}")),
            platform: "linux-x86_64".to_owned(),
            workflow_policy_digest: EvidenceDigest::sha256(format!("policy-{label}")),
        }
    }

    fn input_directory(directory: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let root = directory.path().join(name);
        fs::create_dir(&root).expect("create input root");
        let mut file = File::create(root.join("payload.bin")).expect("create input file");
        file.write_all(bytes).expect("write input file");
        file.sync_all().expect("sync input file");
        root
    }

    #[test]
    fn preparation_keys_are_deterministic_typed_and_policy_bound() {
        let dependency = dependency_material("same");
        assert_eq!(
            dependency.key().expect("first key"),
            dependency.key().expect("repeated key")
        );
        assert_ne!(
            dependency.key().expect("dependency key"),
            dependency_material("other").key().expect("other key")
        );
        let source_key = EvidenceDigest::sha256("source");
        let prepared = PreparationKeyMaterialV1::PreparedRun {
            source_snapshot_key: source_key.clone(),
            dependency_snapshot_key: dependency.key().expect("dependency key"),
            workflow_policy_digest: EvidenceDigest::sha256("policy-same"),
            generated_input_digest: EvidenceDigest::sha256("generated"),
        };
        let changed_policy = PreparationKeyMaterialV1::PreparedRun {
            source_snapshot_key: source_key,
            dependency_snapshot_key: dependency.key().expect("dependency key"),
            workflow_policy_digest: EvidenceDigest::sha256("changed-policy"),
            generated_input_digest: EvidenceDigest::sha256("generated"),
        };
        assert_ne!(
            prepared.key().expect("prepared key"),
            changed_policy.key().expect("policy-bound key")
        );
    }

    #[test]
    fn same_key_runs_one_producer_and_returns_one_sealed_entry() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            probe(8 * 1024 * 1024),
        );
        let input = Arc::new(input_directory(
            &directory,
            "input",
            b"shared dependency bytes",
        ));
        let material = Arc::new(dependency_material("single-flight"));
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(4));
        let mut threads = Vec::new();
        for index in 0..4_i64 {
            let store = store.clone();
            let input = Arc::clone(&input);
            let material = Arc::clone(&material);
            let producer_calls = Arc::clone(&producer_calls);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                store
                    .get_or_prepare_directory(material.as_ref(), 10 + index, || {
                        producer_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, io::Error>(input.as_ref().clone())
                    })
                    .expect("single-flight preparation")
                    .manifest
                    .document_digest
            }));
        }
        let digests = threads
            .into_iter()
            .map(|thread| thread.join().expect("join producer"))
            .collect::<BTreeSet<_>>();
        assert_eq!(producer_calls.load(Ordering::SeqCst), 1);
        assert_eq!(digests.len(), 1);
        let key = material.key().expect("preparation key");
        let entry = store
            .open_pinned(
                PreparationObjectKindV1::DependencySnapshot,
                &key,
                Uuid::new_v4(),
                10_000,
                100,
            )
            .expect("open sealed entry");
        assert_eq!(
            fs::metadata(entry.path())
                .expect("entry metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            fs::metadata(entry.payload_path().join("payload.bin"))
                .expect("payload metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
    }

    #[test]
    fn producer_failure_and_orphan_stage_never_publish_a_readable_entry() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let orphan = root.join("staging").join(Uuid::new_v4().to_string());
        fs::create_dir_all(&orphan).expect("create orphan stage");
        fs::set_permissions(root.join("staging"), fs::Permissions::from_mode(0o700))
            .expect("set staging mode");
        fs::write(orphan.join("partial"), b"partial").expect("write orphan bytes");
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            probe(8 * 1024 * 1024),
        );
        assert!(!orphan.exists(), "startup removed the owned orphan stage");

        let material = dependency_material("producer-error");
        let failed = store.get_or_prepare_directory(&material, 10, || {
            Err::<PathBuf, _>(io::Error::other("expected producer failure"))
        });
        assert!(matches!(
            failed,
            Err(PreparationStoreError::ProducerFailed(_))
        ));
        assert!(
            fs::read_dir(root.join("staging"))
                .expect("read staging")
                .next()
                .is_none()
        );
        assert!(
            !store
                .entry_path(
                    PreparationObjectKindV1::DependencySnapshot,
                    &material.key().expect("material key")
                )
                .exists()
        );
    }

    #[test]
    fn startup_finishes_a_fully_written_entry_interrupted_after_rename() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let boundary = probe(8 * 1024 * 1024);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            Arc::clone(&boundary),
        );
        let input = input_directory(&directory, "commit-input", b"complete payload");
        let material = dependency_material("commit-recovery");
        let entry = store
            .get_or_prepare_directory(&material, 10, || Ok::<_, io::Error>(input.clone()))
            .expect("publish entry before recovery fixture");
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))
            .expect("simulate rename before final root seal");
        drop(store);

        let reopened = open_test_store(&root, policy(8 * 1024 * 1024, 1_000, 0), boundary);
        let recovered = reopened
            .open_pinned(
                material.kind(),
                &material.key().expect("material key"),
                Uuid::new_v4(),
                crate::unix_time_ms().expect("test clock") + 1_000,
                crate::unix_time_ms().expect("test clock"),
            )
            .expect("open recovered entry");
        assert_eq!(
            fs::metadata(recovered.path())
                .expect("recovered metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
    }

    #[test]
    fn startup_finishes_an_eviction_interrupted_after_manifest_removal() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let boundary = probe(8 * 1024 * 1024);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            Arc::clone(&boundary),
        );
        let input = input_directory(&directory, "eviction-input", b"eviction payload");
        let material = dependency_material("eviction-recovery");
        let key = material.key().expect("eviction key");
        let entry = store
            .get_or_prepare_directory(&material, 10, || Ok::<_, io::Error>(input.clone()))
            .expect("publish entry before eviction fixture");
        store
            .begin_eviction(material.kind(), &key)
            .expect("persist eviction marker");
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))
            .expect("start destructive eviction");
        fs::remove_file(entry.path().join("manifest.jcs"))
            .expect("simulate crash after manifest removal");
        drop(store);

        let reopened = open_test_store(&root, policy(8 * 1024 * 1024, 1_000, 0), boundary);
        assert!(!entry.path().exists());
        assert!(!reopened.eviction_path(material.kind(), &key).exists());
        assert!(
            fs::read_dir(root.join("evictions"))
                .expect("read eviction journal")
                .next()
                .is_none()
        );
    }

    #[test]
    fn checksum_tampering_is_detected_before_a_pin_is_granted() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            probe(8 * 1024 * 1024),
        );
        let input = input_directory(&directory, "input", b"original bytes");
        let material = dependency_material("tamper");
        let entry = store
            .get_or_prepare_directory(&material, 10, || Ok::<_, io::Error>(input.clone()))
            .expect("prepare entry");
        let payload = entry.payload_path().join("payload.bin");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644))
            .expect("make payload writable for tamper fixture");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&payload)
            .expect("open tampered payload");
        file.write_all(b"tampered bytes").expect("tamper payload");
        file.sync_all().expect("sync tampered payload");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o444))
            .expect("restore sealed mode");
        let pin_id = Uuid::new_v4();
        assert!(matches!(
            store.open_pinned(
                material.kind(),
                &material.key().expect("material key"),
                pin_id,
                10_000,
                20,
            ),
            Err(PreparationStoreError::EntryChecksumMismatch)
        ));
        assert!(!store.pin_path(pin_id).exists());
    }

    #[test]
    fn symlinks_and_hard_links_are_rejected_instead_of_entering_the_cas() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            probe(8 * 1024 * 1024),
        );
        let symlink_root = directory.path().join("symlink-input");
        fs::create_dir(&symlink_root).expect("create symlink input");
        symlink("/etc/passwd", symlink_root.join("escape")).expect("create symlink fixture");
        assert!(matches!(
            store.get_or_prepare_directory(&dependency_material("symlink"), 10, || {
                Ok::<_, io::Error>(symlink_root.clone())
            }),
            Err(PreparationStoreError::UnsupportedInputType)
        ));

        let hardlink_root = directory.path().join("hardlink-input");
        fs::create_dir(&hardlink_root).expect("create hardlink input");
        fs::write(hardlink_root.join("first"), b"same inode").expect("write hardlink source");
        fs::hard_link(hardlink_root.join("first"), hardlink_root.join("second"))
            .expect("create hardlink fixture");
        assert!(matches!(
            store.get_or_prepare_directory(&dependency_material("hardlink"), 20, || {
                Ok::<_, io::Error>(hardlink_root.clone())
            }),
            Err(PreparationStoreError::UnsupportedInputType)
        ));
    }

    #[test]
    fn pins_block_lru_eviction_and_unpinning_allows_bounded_replacement() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let store = open_test_store(&root, policy(60 * 1024, 10, 0), probe(60 * 1024));
        let first_input = input_directory(&directory, "first", &[1_u8; 8 * 1024]);
        let second_input = input_directory(&directory, "second", &[2_u8; 8 * 1024]);
        let first_material = dependency_material("first");
        let second_material = dependency_material("second");
        let first = store
            .get_or_prepare_directory(&first_material, 10, || {
                Ok::<_, io::Error>(first_input.clone())
            })
            .expect("prepare first entry");
        let pin_id = Uuid::new_v4();
        store
            .open_pinned(
                first_material.kind(),
                &first_material.key().expect("first key"),
                pin_id,
                1_000,
                11,
            )
            .expect("pin first entry");
        assert!(matches!(
            store.get_or_prepare_directory(&second_material, 20, || {
                Ok::<_, io::Error>(second_input.clone())
            }),
            Err(PreparationStoreError::StoreCapacityExceeded
                | PreparationStoreError::StoreInodeCapacityExceeded)
        ));
        assert!(first.path().exists());

        store
            .unpin(pin_id, &first_material.key().expect("first key"))
            .expect("unpin first entry");
        let second = store
            .get_or_prepare_directory(&second_material, 21, || {
                Ok::<_, io::Error>(second_input.clone())
            })
            .expect("replace cold unpinned entry");
        assert!(second.path().exists());
        assert!(
            !first.path().exists(),
            "cold entry was evicted within the cap"
        );
    }

    #[test]
    fn root_emergency_reserve_rejects_work_before_staging() {
        let directory = tempdir().expect("temp dir");
        let root = store_root(&directory);
        let boundary = probe(8 * 1024 * 1024);
        let store = open_test_store(
            &root,
            policy(8 * 1024 * 1024, 1_000, 0),
            Arc::clone(&boundary),
        );
        boundary
            .snapshot
            .lock()
            .expect("boundary lock")
            .root_available_bytes = MIN_ROOT_EMERGENCY_RESERVE_BYTES;
        let input = input_directory(&directory, "reserve-input", b"payload");
        assert!(matches!(
            store.get_or_prepare_directory(&dependency_material("reserve"), 10, || {
                Ok::<_, io::Error>(input.clone())
            }),
            Err(PreparationStoreError::RootEmergencyReserveViolated)
        ));
        assert!(
            fs::read_dir(root.join("staging"))
                .expect("read staging")
                .next()
                .is_none()
        );
    }

    #[test]
    fn source_snapshot_uses_the_exact_leased_publication_not_latest() {
        let directory = tempdir().expect("temp dir");
        let source_root = directory.path().join("source-exports");
        fs::create_dir(&source_root).expect("create source root");
        fs::set_permissions(&source_root, fs::Permissions::from_mode(0o2750))
            .expect("set source root mode");
        let source_metadata = fs::metadata(&source_root).expect("source root metadata");
        let publisher = SourceArchivePublisherV1::open(
            &source_root,
            source_metadata.uid(),
            source_metadata.gid(),
        )
        .expect("open source publisher");
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("decode workflow manifest");
        let policy_digest = manifest
            .workflow_policy_digest()
            .expect("workflow policy digest");
        let sha = GitCommitId::from_str(&"a".repeat(40)).expect("source SHA");
        let attestation_nine = EvidenceDigest::sha256("attestation-nine");
        let base = SourceArchiveInputV1 {
            project_id: manifest.project_id.clone(),
            head: sha.clone(),
            sequence: 9,
            source_attestation_digest: attestation_nine.clone(),
            installed_policy: InstalledPolicyIdentity {
                digest: policy_digest.clone(),
                version: 1,
            },
            repository_identity: EvidenceDigest::sha256("repository"),
            exported_at_ms: 9,
        };
        publisher
            .publish(base.clone(), |archive| {
                archive.write_all(b"leased source bytes")
            })
            .expect("publish leased source");
        let mut latest = base;
        latest.sequence = 10;
        latest.source_attestation_digest = EvidenceDigest::sha256("attestation-ten");
        latest.exported_at_ms = 10;
        publisher
            .publish(latest, |archive| archive.write_all(b"newer source bytes"))
            .expect("publish newer source");
        let reader =
            SourceArchiveReaderV1::open(&source_root, source_metadata.uid(), source_metadata.gid())
                .expect("open source reader");

        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .expect("host prepare node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("host prepare profile");
        assert_eq!(profile.worker_pool, WorkflowWorkerPoolV1::VpsRequired);
        let lease = WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            manifest.project_id.clone(),
            sha,
            9,
            attestation_nine,
            policy_digest,
            EvidenceDigest::sha256("scheduler preparation key"),
            node,
            profile,
            EvidenceDigest::sha256("expected input"),
            "vps-build-1".to_owned(),
            "vps-1".to_owned(),
            1,
            10_001,
        )
        .expect("exact source lease");

        let preparation_root = store_root(&directory);
        let store = open_test_store(
            &preparation_root,
            policy(8 * 1024 * 1024, 1_000, 0),
            probe(8 * 1024 * 1024),
        );
        let entry = store
            .publish_source_snapshot(&reader, &lease, 20)
            .expect("publish exact source snapshot");
        let mut bytes = Vec::new();
        File::open(entry.payload_path().join("source.tar"))
            .expect("open prepared source archive")
            .read_to_end(&mut bytes)
            .expect("read prepared source archive");
        assert_eq!(bytes, b"leased source bytes");
    }
}
