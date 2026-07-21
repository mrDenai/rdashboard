use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr as _,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    domain::EvidenceDigest,
    self_update::{SelfReleaseStoreV1, SelfUpdatePlatformFailureV1, SelfUpdatePlatformV1},
};

pub const SELF_UPDATE_ROOT: &str = "/var/lib/rdashboard-bootstrap";
pub const SELF_RELEASE_ROOT: &str = "/var/lib/rdashboard-bootstrap/releases";
pub const SELF_UPDATE_JOURNAL_ROOT: &str = "/var/lib/rdashboard-bootstrap/journal";
pub const SELF_UPDATE_BACKUP_ROOT: &str = "/var/lib/rdashboard-bootstrap/backups";
pub const SELF_UPDATE_CURRENT_LINK: &str = "/var/lib/rdashboard-bootstrap/current";
pub const SELF_UPDATE_LKG_LINK: &str = "/var/lib/rdashboard-bootstrap/last-known-good";
pub const SYSTEMCTL_EXECUTABLE: &str = "/usr/bin/systemctl";
pub const HEALTH_ADDRESS: &str = "127.0.0.1:3100";

const STATE_BACKUP_PURPOSE: &str = "rdashboard.self-update-state-backup.v1";
const STATE_BACKUP_SCHEMA_VERSION: u16 = 1;
const STATE_BACKUP_RECEIPT_FILE: &str = "receipt.jcs";
const MAX_BACKUP_DATABASES: usize = 16;
const MAX_BACKUP_DATABASE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_BACKUP_RECEIPT_BYTES: u64 = 128 * 1024;
const HEALTH_ATTEMPTS: usize = 20;
const HEALTH_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const HEALTH_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_HEALTH_RESPONSE_BYTES: usize = 16 * 1024;

pub const SELF_UPDATE_SERVICE_ORDER: &[&str] = &[
    "rdashboard-source.service",
    "rdashboard-observer.service",
    "rdashboard-executor.service",
    "rdashboard-workflow-launcher.service",
    "rdashboard-workflow-gateway.service",
    "rdashboard-dependency-fetcher.service",
    "rdashboard-buildkit.service",
    "rdashboard-worker.service",
    "rdashboard-source-dispatcher.service",
    "rdashboard-source-ingress.service",
    "rdashboard-source-ingress-bridge.service",
    "rdashboard.service",
];

pub const SELF_UPDATE_QUIESCE_ONLY_SERVICES: &[&str] = &["rdashboard-rimg-health.service"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfUpdateStateDatabaseV1 {
    pub name: String,
    pub path: PathBuf,
    pub maximum_bytes: u64,
}

impl SelfUpdateStateDatabaseV1 {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<PathBuf>,
        maximum_bytes: u64,
    ) -> Result<Self, SelfUpdateRuntimeError> {
        let database = Self {
            name: name.into(),
            path: path.into(),
            maximum_bytes,
        };
        database.validate()?;
        Ok(database)
    }

    fn validate(&self) -> Result<(), SelfUpdateRuntimeError> {
        if !valid_database_name(&self.name)
            || !self.path.is_absolute()
            || self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none()
            || self.maximum_bytes == 0
            || self.maximum_bytes > MAX_BACKUP_DATABASE_BYTES
        {
            return Err(SelfUpdateRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }
}

pub fn installed_state_databases() -> Vec<SelfUpdateStateDatabaseV1> {
    [
        ("control", "/var/lib/rdashboard/control.sqlite"),
        ("integrations", "/var/lib/rdashboard/integrations.sqlite"),
        ("metrics", "/var/lib/rdashboard/metrics.sqlite"),
        (
            "executor-security",
            "/var/lib/rdashboard-executor/security.sqlite",
        ),
        ("source", "/var/lib/rdashboard-source/source.sqlite"),
    ]
    .into_iter()
    .map(|(name, path)| {
        SelfUpdateStateDatabaseV1::new(name, path, MAX_BACKUP_DATABASE_BYTES)
            .expect("compiled self-update database contract must be valid")
    })
    .collect()
}

#[derive(Clone, Debug)]
pub struct SelfUpdateRuntimePathsV1 {
    pub root: PathBuf,
    pub releases: PathBuf,
    pub backups: PathBuf,
    pub current_link: PathBuf,
    pub last_known_good_link: PathBuf,
    pub databases: Vec<SelfUpdateStateDatabaseV1>,
}

impl SelfUpdateRuntimePathsV1 {
    pub fn installed() -> Self {
        Self {
            root: PathBuf::from(SELF_UPDATE_ROOT),
            releases: PathBuf::from(SELF_RELEASE_ROOT),
            backups: PathBuf::from(SELF_UPDATE_BACKUP_ROOT),
            current_link: PathBuf::from(SELF_UPDATE_CURRENT_LINK),
            last_known_good_link: PathBuf::from(SELF_UPDATE_LKG_LINK),
            databases: installed_state_databases(),
        }
    }

    fn validate(&self) -> Result<(), SelfUpdateRuntimeError> {
        if self.releases.parent() != Some(self.root.as_path())
            || self.backups.parent() != Some(self.root.as_path())
            || self.current_link.parent() != Some(self.root.as_path())
            || self.last_known_good_link.parent() != Some(self.root.as_path())
            || self.current_link == self.last_known_good_link
            || self.databases.is_empty()
            || self.databases.len() > MAX_BACKUP_DATABASES
            || self
                .databases
                .iter()
                .any(|database| database.validate().is_err())
        {
            return Err(SelfUpdateRuntimeError::InvalidConfiguration);
        }
        let mut names = self
            .databases
            .iter()
            .map(|database| database.name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SelfUpdateRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }
}

pub trait SelfUpdateServiceRuntimeV1 {
    fn stop_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1>;
    fn start_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1>;
    fn services_are_healthy(&mut self) -> Result<bool, SelfUpdatePlatformFailureV1>;
}

#[derive(Debug, Default)]
pub struct InstalledSelfUpdateServiceRuntimeV1;

impl SelfUpdateServiceRuntimeV1 for InstalledSelfUpdateServiceRuntimeV1 {
    fn stop_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1> {
        for service in SELF_UPDATE_SERVICE_ORDER.iter().rev() {
            run_systemctl(["stop", *service], "service_stop_failed")?;
        }
        for service in SELF_UPDATE_QUIESCE_ONLY_SERVICES {
            run_systemctl(["stop", *service], "service_stop_failed")?;
        }
        Ok(())
    }

    fn start_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1> {
        run_systemctl(["daemon-reload"], "daemon_reload_failed")?;
        for service in SELF_UPDATE_SERVICE_ORDER {
            run_systemctl(["start", *service], "service_start_failed")?;
        }
        Ok(())
    }

    fn services_are_healthy(&mut self) -> Result<bool, SelfUpdatePlatformFailureV1> {
        for service in SELF_UPDATE_SERVICE_ORDER {
            let status = Command::new(SYSTEMCTL_EXECUTABLE)
                .args(["is-active", "--quiet", *service])
                .status()
                .map_err(|_| platform_failure("service_status_failed"))?;
            if !status.success() {
                return Ok(false);
            }
        }
        for attempt in 0..HEALTH_ATTEMPTS {
            if loopback_health_probe().unwrap_or(false) {
                return Ok(true);
            }
            if attempt + 1 < HEALTH_ATTEMPTS {
                std::thread::sleep(HEALTH_RETRY_DELAY);
            }
        }
        Ok(false)
    }
}

fn run_systemctl<const N: usize>(
    arguments: [&str; N],
    reason_code: &'static str,
) -> Result<(), SelfUpdatePlatformFailureV1> {
    let status = Command::new(SYSTEMCTL_EXECUTABLE)
        .args(arguments)
        .status()
        .map_err(|_| platform_failure(reason_code))?;
    if !status.success() {
        return Err(platform_failure(reason_code));
    }
    Ok(())
}

fn loopback_health_probe() -> Result<bool, SelfUpdateRuntimeError> {
    let address: SocketAddr = HEALTH_ADDRESS
        .parse()
        .map_err(|_| SelfUpdateRuntimeError::InvalidConfiguration)?;
    let mut stream = TcpStream::connect_timeout(&address, HEALTH_CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(HEALTH_CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(HEALTH_CONNECT_TIMEOUT))?;
    stream.write_all(
        b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:3100\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
    )?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(MAX_HEALTH_RESPONSE_BYTES).unwrap_or(u64::MAX))
        .read_to_end(&mut response)?;
    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or(SelfUpdateRuntimeError::InvalidHealthResponse)?;
    Ok(status_line.starts_with(b"HTTP/1.1 200 ") || status_line.starts_with(b"HTTP/1.0 200 "))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateBackupFileV1 {
    name: String,
    bytes: u64,
    sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateBackupReceiptV1 {
    purpose: String,
    schema_version: u16,
    operation_id: Uuid,
    candidate_release_digest: EvidenceDigest,
    files: Vec<StateBackupFileV1>,
    receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct StateBackupReceiptPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    operation_id: Uuid,
    candidate_release_digest: &'a EvidenceDigest,
    files: &'a [StateBackupFileV1],
}

impl StateBackupReceiptV1 {
    fn new(
        operation_id: Uuid,
        candidate_release_digest: EvidenceDigest,
        mut files: Vec<StateBackupFileV1>,
    ) -> Result<Self, SelfUpdateRuntimeError> {
        files.sort_by(|left, right| left.name.cmp(&right.name));
        let mut receipt = Self {
            purpose: STATE_BACKUP_PURPOSE.to_owned(),
            schema_version: STATE_BACKUP_SCHEMA_VERSION,
            operation_id,
            candidate_release_digest,
            files,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), SelfUpdateRuntimeError> {
        if self.purpose != STATE_BACKUP_PURPOSE
            || self.schema_version != STATE_BACKUP_SCHEMA_VERSION
            || self.operation_id.is_nil()
            || self.files.is_empty()
            || self.files.len() > MAX_BACKUP_DATABASES
            || self
                .files
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
            || self.files.iter().any(|file| {
                !valid_database_name(&file.name)
                    || file.bytes == 0
                    || file.bytes > MAX_BACKUP_DATABASE_BYTES
            })
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(SelfUpdateRuntimeError::InvalidBackupReceipt);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, SelfUpdateRuntimeError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfUpdateRuntimeError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_BACKUP_RECEIPT_BYTES)
        {
            return Err(SelfUpdateRuntimeError::InvalidBackupReceipt);
        }
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(SelfUpdateRuntimeError::NoncanonicalDocument);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &StateBackupReceiptPayload {
                purpose: STATE_BACKUP_PURPOSE,
                schema_version: STATE_BACKUP_SCHEMA_VERSION,
                operation_id: self.operation_id,
                candidate_release_digest: &self.candidate_release_digest,
                files: &self.files,
            },
        )?))
    }
}

pub struct InstalledSelfUpdatePlatformV1<R> {
    paths: SelfUpdateRuntimePathsV1,
    owner_uid: u32,
    release_store: SelfReleaseStoreV1,
    runtime: R,
}

impl<R: SelfUpdateServiceRuntimeV1> InstalledSelfUpdatePlatformV1<R> {
    pub fn open(
        paths: SelfUpdateRuntimePathsV1,
        owner_uid: u32,
        release_source_uid: u32,
        release_reader_gid: u32,
        runtime: R,
    ) -> Result<Self, SelfUpdateRuntimeError> {
        paths.validate()?;
        validate_runtime_root(&paths.root, owner_uid)?;
        reconcile_release_link_temporaries(&paths.root, owner_uid)?;
        validate_private_directory(&paths.backups, owner_uid)?;
        let release_store = SelfReleaseStoreV1::open(
            &paths.releases,
            owner_uid,
            release_source_uid,
            release_reader_gid,
        )?;
        let platform = Self {
            paths,
            owner_uid,
            release_store,
            runtime,
        };
        platform.validate_database_contract()?;
        Ok(platform)
    }

    fn active_release_checked(&self) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
        read_release_link(
            &self.paths.current_link,
            &self.paths.releases,
            self.owner_uid,
            &self.release_store,
        )
    }

    fn backup_state_checked(
        &self,
        operation_id: Uuid,
        candidate_release_digest: &EvidenceDigest,
    ) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
        let operation_root = self.paths.backups.join(operation_id.to_string());
        if fs::symlink_metadata(&operation_root).is_ok() {
            if fs::symlink_metadata(operation_root.join(STATE_BACKUP_RECEIPT_FILE)).is_err() {
                validate_private_directory(&operation_root, self.owner_uid)?;
                remove_owned_operation_tree(&operation_root, self.owner_uid);
            } else {
                let receipt = self.read_backup_receipt(&operation_root)?;
                if receipt.operation_id != operation_id
                    || receipt.candidate_release_digest != *candidate_release_digest
                {
                    return Err(SelfUpdateRuntimeError::BackupConflict);
                }
                self.verify_backup_files(&operation_root, &receipt)?;
                return Ok(receipt.receipt_digest);
            }
        }
        fs::create_dir(&operation_root)?;
        fs::set_permissions(&operation_root, fs::Permissions::from_mode(0o700))?;
        let result = (|| {
            let mut files = Vec::with_capacity(self.paths.databases.len());
            for database in &self.paths.databases {
                validate_database_source(database)?;
                let destination = operation_root.join(format!("{}.sqlite", database.name));
                let source = Connection::open_with_flags(
                    &database.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                source.backup("main", &destination, None)?;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))?;
                let (sha256, bytes) =
                    hash_private_file(&destination, self.owner_uid, 0o400, database.maximum_bytes)?;
                verify_sqlite_integrity(&destination)?;
                files.push(StateBackupFileV1 {
                    name: database.name.clone(),
                    bytes,
                    sha256,
                });
            }
            let receipt =
                StateBackupReceiptV1::new(operation_id, candidate_release_digest.clone(), files)?;
            write_private_document(
                &operation_root.join(STATE_BACKUP_RECEIPT_FILE),
                &receipt.canonical_bytes()?,
                self.owner_uid,
            )?;
            sync_directory(&operation_root)?;
            sync_directory(&self.paths.backups)?;
            Ok(receipt.receipt_digest)
        })();
        if result.is_err() {
            remove_owned_operation_tree(&operation_root, self.owner_uid);
        }
        result
    }

    fn restore_release_checked(
        &mut self,
        previous_release_digest: &EvidenceDigest,
        backup_receipt_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdateRuntimeError> {
        self.release_store.verify_staged(previous_release_digest)?;
        let (operation_root, receipt) = self.find_backup_receipt(backup_receipt_digest)?;
        self.verify_backup_files(&operation_root, &receipt)?;
        self.runtime
            .stop_services()
            .map_err(SelfUpdateRuntimeError::Platform)?;
        for database in &self.paths.databases {
            let backup_file = receipt
                .files
                .iter()
                .find(|file| file.name == database.name)
                .ok_or(SelfUpdateRuntimeError::InvalidBackupReceipt)?;
            restore_database(
                database,
                &operation_root.join(format!("{}.sqlite", database.name)),
                backup_file,
                self.owner_uid,
                receipt.operation_id,
            )?;
        }
        switch_release_link(
            &self.paths.current_link,
            &self.paths.releases,
            previous_release_digest,
            self.owner_uid,
        )?;
        Ok(())
    }

    fn read_backup_receipt(
        &self,
        operation_root: &Path,
    ) -> Result<StateBackupReceiptV1, SelfUpdateRuntimeError> {
        validate_private_directory(operation_root, self.owner_uid)?;
        let bytes = read_private_file(
            &operation_root.join(STATE_BACKUP_RECEIPT_FILE),
            self.owner_uid,
            0o400,
            MAX_BACKUP_RECEIPT_BYTES,
        )?;
        StateBackupReceiptV1::decode_canonical(&bytes)
    }

    fn verify_backup_files(
        &self,
        operation_root: &Path,
        receipt: &StateBackupReceiptV1,
    ) -> Result<(), SelfUpdateRuntimeError> {
        receipt.validate()?;
        if receipt.files.len() != self.paths.databases.len() {
            return Err(SelfUpdateRuntimeError::InvalidBackupReceipt);
        }
        let expected_names = self
            .paths
            .databases
            .iter()
            .map(|database| database.name.as_str())
            .collect::<BTreeSet<_>>();
        let actual_names = receipt
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect::<BTreeSet<_>>();
        if expected_names != actual_names {
            return Err(SelfUpdateRuntimeError::InvalidBackupReceipt);
        }
        for file in &receipt.files {
            let database = self
                .paths
                .databases
                .iter()
                .find(|database| database.name == file.name)
                .ok_or(SelfUpdateRuntimeError::InvalidBackupReceipt)?;
            let (digest, bytes) = hash_private_file(
                &operation_root.join(format!("{}.sqlite", file.name)),
                self.owner_uid,
                0o400,
                database.maximum_bytes,
            )?;
            if digest != file.sha256 || bytes != file.bytes {
                return Err(SelfUpdateRuntimeError::BackupBinding);
            }
            verify_sqlite_integrity(&operation_root.join(format!("{}.sqlite", file.name)))?;
        }
        Ok(())
    }

    fn find_backup_receipt(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<(PathBuf, StateBackupReceiptV1), SelfUpdateRuntimeError> {
        let mut found = None;
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != self.owner_uid
            {
                return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
            }
            let receipt = self.read_backup_receipt(&entry.path())?;
            if receipt.receipt_digest == *digest {
                if found.is_some() {
                    return Err(SelfUpdateRuntimeError::BackupConflict);
                }
                found = Some((entry.path(), receipt));
            }
        }
        found.ok_or(SelfUpdateRuntimeError::BackupMissing)
    }

    fn validate_database_contract(&self) -> Result<(), SelfUpdateRuntimeError> {
        for database in &self.paths.databases {
            database.validate()?;
            let parent = database
                .path
                .parent()
                .ok_or(SelfUpdateRuntimeError::InvalidConfiguration)?;
            if !parent.is_absolute() || parent == Path::new("/") {
                return Err(SelfUpdateRuntimeError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

pub fn read_current_release(
    paths: &SelfUpdateRuntimePathsV1,
    owner_uid: u32,
    store: &SelfReleaseStoreV1,
) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
    paths.validate()?;
    read_release_link(&paths.current_link, &paths.releases, owner_uid, store)
}

pub fn read_last_known_good_release(
    paths: &SelfUpdateRuntimePathsV1,
    owner_uid: u32,
    store: &SelfReleaseStoreV1,
) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
    paths.validate()?;
    read_release_link(
        &paths.last_known_good_link,
        &paths.releases,
        owner_uid,
        store,
    )
}

impl<R: SelfUpdateServiceRuntimeV1> SelfUpdatePlatformV1 for InstalledSelfUpdatePlatformV1<R> {
    fn active_release(&mut self) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
        self.active_release_checked()
            .map_err(|_| platform_failure("active_release_invalid"))
    }

    fn backup_state(
        &mut self,
        operation_id: Uuid,
        candidate_release_digest: &EvidenceDigest,
    ) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
        self.backup_state_checked(operation_id, candidate_release_digest)
            .map_err(|_| platform_failure("state_backup_failed"))
    }

    fn activate_release(
        &mut self,
        candidate_release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1> {
        self.release_store
            .verify_staged(candidate_release_digest)
            .map_err(|_| platform_failure("candidate_release_invalid"))?;
        self.runtime.stop_services()?;
        switch_release_link(
            &self.paths.current_link,
            &self.paths.releases,
            candidate_release_digest,
            self.owner_uid,
        )
        .map_err(|_| platform_failure("release_switch_failed"))
    }

    fn start_release(
        &mut self,
        release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1> {
        if self
            .active_release_checked()
            .map_err(|_| platform_failure("active_release_invalid"))?
            != *release_digest
        {
            return Err(platform_failure("release_start_mismatch"));
        }
        self.runtime.start_services()
    }

    fn release_is_healthy(
        &mut self,
        release_digest: &EvidenceDigest,
    ) -> Result<bool, SelfUpdatePlatformFailureV1> {
        if self
            .active_release_checked()
            .map_err(|_| platform_failure("active_release_invalid"))?
            != *release_digest
        {
            return Err(platform_failure("release_health_mismatch"));
        }
        self.runtime.services_are_healthy()
    }

    fn commit_release(
        &mut self,
        candidate_release_digest: &EvidenceDigest,
        previous_release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1> {
        if self
            .active_release_checked()
            .map_err(|_| platform_failure("active_release_invalid"))?
            != *candidate_release_digest
        {
            return Err(platform_failure("release_commit_mismatch"));
        }
        self.release_store
            .verify_staged(previous_release_digest)
            .map_err(|_| platform_failure("previous_release_invalid"))?;
        switch_release_link(
            &self.paths.last_known_good_link,
            &self.paths.releases,
            previous_release_digest,
            self.owner_uid,
        )
        .map_err(|_| platform_failure("lkg_switch_failed"))
    }

    fn restore_release(
        &mut self,
        previous_release_digest: &EvidenceDigest,
        backup_receipt_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1> {
        self.restore_release_checked(previous_release_digest, backup_receipt_digest)
            .map_err(|_| platform_failure("release_restore_failed"))
    }
}

fn read_release_link(
    link: &Path,
    releases: &Path,
    owner_uid: u32,
    store: &SelfReleaseStoreV1,
) -> Result<EvidenceDigest, SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(link)?;
    if !metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
        return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
    }
    let target = fs::read_link(link)?;
    let expected_prefix = Path::new("releases");
    let relative = target
        .strip_prefix(expected_prefix)
        .map_err(|_| SelfUpdateRuntimeError::UnsafeReleasePointer)?;
    if relative.components().count() != 1 {
        return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
    }
    let digest = relative
        .to_str()
        .ok_or(SelfUpdateRuntimeError::UnsafeReleasePointer)?
        .parse()
        .map_err(|_| SelfUpdateRuntimeError::UnsafeReleasePointer)?;
    if link.parent() != releases.parent() {
        return Err(SelfUpdateRuntimeError::InvalidConfiguration);
    }
    store.verify_staged(&digest)?;
    Ok(digest)
}

fn switch_release_link(
    link: &Path,
    releases: &Path,
    digest: &EvidenceDigest,
    owner_uid: u32,
) -> Result<(), SelfUpdateRuntimeError> {
    let parent = link
        .parent()
        .ok_or(SelfUpdateRuntimeError::InvalidConfiguration)?;
    validate_runtime_root(parent, owner_uid)?;
    if releases.parent() != Some(parent) {
        return Err(SelfUpdateRuntimeError::InvalidConfiguration);
    }
    let release_path = releases.join(digest.as_str());
    let release_metadata = fs::symlink_metadata(&release_path)?;
    if release_metadata.file_type().is_symlink()
        || !release_metadata.is_dir()
        || release_metadata.uid() != owner_uid
        || release_metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
    }
    let temporary = parent.join(format!(".link-{}", Uuid::new_v4()));
    symlink(Path::new("releases").join(digest.as_str()), &temporary)?;
    let temporary_metadata = fs::symlink_metadata(&temporary)?;
    if !temporary_metadata.file_type().is_symlink() || temporary_metadata.uid() != owner_uid {
        let _ = fs::remove_file(&temporary);
        return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
    }
    if let Err(error) = fs::rename(&temporary, link) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_directory(parent)?;
    Ok(())
}

fn reconcile_release_link_temporaries(
    root: &Path,
    owner_uid: u32,
) -> Result<(), SelfUpdateRuntimeError> {
    let mut removed = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SelfUpdateRuntimeError::UnsafeReleasePointer)?;
        let Some(identifier) = name.strip_prefix(".link-") else {
            continue;
        };
        Uuid::parse_str(identifier).map_err(|_| SelfUpdateRuntimeError::UnsafeReleasePointer)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
            return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
        }
        let target = fs::read_link(entry.path())?;
        let relative = target
            .strip_prefix("releases")
            .map_err(|_| SelfUpdateRuntimeError::UnsafeReleasePointer)?;
        if relative.components().count() != 1
            || relative
                .to_str()
                .and_then(|value| EvidenceDigest::from_str(value).ok())
                .is_none()
        {
            return Err(SelfUpdateRuntimeError::UnsafeReleasePointer);
        }
        fs::remove_file(entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn validate_database_source(
    database: &SelfUpdateStateDatabaseV1,
) -> Result<fs::Metadata, SelfUpdateRuntimeError> {
    database.validate()?;
    let metadata = fs::symlink_metadata(&database.path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > database.maximum_bytes
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(SelfUpdateRuntimeError::UnsafeDatabase);
    }
    Ok(metadata)
}

fn verify_sqlite_integrity(path: &Path) -> Result<(), SelfUpdateRuntimeError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let result: String =
        connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    if result != "ok" {
        return Err(SelfUpdateRuntimeError::DatabaseIntegrity);
    }
    Ok(())
}

fn restore_database(
    database: &SelfUpdateStateDatabaseV1,
    backup_path: &Path,
    backup_file: &StateBackupFileV1,
    backup_owner_uid: u32,
    operation_id: Uuid,
) -> Result<(), SelfUpdateRuntimeError> {
    let target_metadata = validate_database_source(database)?;
    let (backup_digest, backup_bytes) =
        hash_private_file(backup_path, backup_owner_uid, 0o400, database.maximum_bytes)?;
    if backup_digest != backup_file.sha256 || backup_bytes != backup_file.bytes {
        return Err(SelfUpdateRuntimeError::BackupBinding);
    }
    let parent = database
        .path
        .parent()
        .ok_or(SelfUpdateRuntimeError::InvalidConfiguration)?;
    let temporary = parent.join(format!(
        ".self-update-{operation_id}-{}.sqlite",
        database.name
    ));
    reconcile_restore_temporary(
        &temporary,
        backup_owner_uid,
        &target_metadata,
        database.maximum_bytes,
    )?;
    let mut source = File::open(backup_path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut destination = options.open(&temporary)?;
    std::io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    let result = (|| {
        verify_sqlite_integrity(&temporary)?;
        let (copied_digest, copied_bytes) = hash_file_unowned(&temporary, database.maximum_bytes)?;
        if copied_digest != backup_file.sha256 || copied_bytes != backup_file.bytes {
            return Err(SelfUpdateRuntimeError::BackupBinding);
        }
        remove_database_sidecar(&database.path, "-wal")?;
        remove_database_sidecar(&database.path, "-shm")?;
        rustix::fs::chown(
            &temporary,
            Some(rustix::fs::Uid::from_raw(target_metadata.uid())),
            Some(rustix::fs::Gid::from_raw(target_metadata.gid())),
        )?;
        fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(target_metadata.permissions().mode() & 0o7777),
        )?;
        fs::rename(&temporary, &database.path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        remove_open_file_if_still_named(&temporary, &destination);
    }
    result
}

fn reconcile_restore_temporary(
    path: &Path,
    bootstrap_uid: u32,
    target_metadata: &fs::Metadata,
    maximum_bytes: u64,
) -> Result<(), SelfUpdateRuntimeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mode = metadata.permissions().mode() & 0o7777;
    let bootstrap_owned = metadata.uid() == bootstrap_uid && mode == 0o600;
    let target_identity =
        metadata.uid() == target_metadata.uid() && metadata.gid() == target_metadata.gid();
    let target_mode = target_metadata.permissions().mode() & 0o7777;
    let target_owned = target_identity && (mode == 0o600 || mode == target_mode);
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes
        || (!bootstrap_owned && !target_owned)
    {
        return Err(SelfUpdateRuntimeError::UnsafeDatabase);
    }
    fs::remove_file(path)?;
    Ok(())
}

fn remove_open_file_if_still_named(path: &Path, opened: &File) {
    let (Ok(opened_metadata), Ok(named_metadata)) = (opened.metadata(), fs::symlink_metadata(path))
    else {
        return;
    };
    if !named_metadata.file_type().is_symlink()
        && named_metadata.is_file()
        && named_metadata.nlink() == 1
        && named_metadata.dev() == opened_metadata.dev()
        && named_metadata.ino() == opened_metadata.ino()
    {
        let _ = fs::remove_file(path);
    }
}

fn remove_database_sidecar(database: &Path, suffix: &str) -> Result<(), SelfUpdateRuntimeError> {
    let sidecar = PathBuf::from(format!("{}{}", database.display(), suffix));
    match fs::symlink_metadata(&sidecar) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
                return Err(SelfUpdateRuntimeError::UnsafeDatabase);
            }
            fs::remove_file(&sidecar)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn hash_private_file(
    path: &Path,
    owner_uid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<(EvidenceDigest, u64), SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
    }
    let (digest, bytes) = hash_open_file(path, metadata.len())?;
    let after = fs::symlink_metadata(path)?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(SelfUpdateRuntimeError::ConcurrentChange);
    }
    Ok((digest, bytes))
}

fn hash_file_unowned(
    path: &Path,
    maximum_bytes: u64,
) -> Result<(EvidenceDigest, u64), SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfUpdateRuntimeError::UnsafeDatabase);
    }
    hash_open_file(path, metadata.len())
}

fn hash_open_file(
    path: &Path,
    expected_bytes: u64,
) -> Result<(EvidenceDigest, u64), SelfUpdateRuntimeError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| SelfUpdateRuntimeError::ConcurrentChange)?)
            .ok_or(SelfUpdateRuntimeError::ConcurrentChange)?;
        if total > expected_bytes {
            return Err(SelfUpdateRuntimeError::ConcurrentChange);
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_bytes {
        return Err(SelfUpdateRuntimeError::ConcurrentChange);
    }
    let digest = EvidenceDigest::from_str(&hex_sha256(hasher.finalize()))
        .map_err(|_| SelfUpdateRuntimeError::ConcurrentChange)?;
    Ok((digest, total))
}

fn read_private_file(
    path: &Path,
    owner_uid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(SelfUpdateRuntimeError::ConcurrentChange);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(SelfUpdateRuntimeError::ConcurrentChange);
    }
    Ok(bytes)
}

fn write_private_document(
    path: &Path,
    bytes: &[u8],
    owner_uid: u32,
) -> Result<(), SelfUpdateRuntimeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o400
    {
        return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
    }
    Ok(())
}

fn validate_private_directory(path: &Path, owner_uid: u32) -> Result<(), SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
    }
    Ok(())
}

fn validate_runtime_root(path: &Path, owner_uid: u32) -> Result<(), SelfUpdateRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o711
    {
        return Err(SelfUpdateRuntimeError::UnsafeBackupStore);
    }
    Ok(())
}

fn remove_owned_operation_tree(path: &Path, owner_uid: u32) {
    if fs::symlink_metadata(path).is_ok() && validate_private_directory(path, owner_uid).is_ok() {
        let _ = fs::remove_dir_all(path);
    }
}

fn sync_directory(path: &Path) -> Result<(), SelfUpdateRuntimeError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn valid_database_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn platform_failure(reason_code: &'static str) -> SelfUpdatePlatformFailureV1 {
    SelfUpdatePlatformFailureV1::new(reason_code)
        .expect("compiled self-update reason code must be valid")
}

fn hex_sha256(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateRuntimeError {
    #[error("the installed self-update runtime configuration is invalid")]
    InvalidConfiguration,
    #[error("the self-update release pointer is unsafe")]
    UnsafeReleasePointer,
    #[error("the self-update database is unsafe")]
    UnsafeDatabase,
    #[error("the self-update database backup is too large")]
    BackupTooLarge,
    #[error("the self-update backup store is unsafe")]
    UnsafeBackupStore,
    #[error("the self-update backup conflicts with an existing operation")]
    BackupConflict,
    #[error("the requested self-update backup does not exist")]
    BackupMissing,
    #[error("the self-update backup receipt is invalid")]
    InvalidBackupReceipt,
    #[error("the self-update backup does not match its receipt")]
    BackupBinding,
    #[error("the self-update SQLite backup failed its integrity check")]
    DatabaseIntegrity,
    #[error("the self-update runtime document is not canonical JCS")]
    NoncanonicalDocument,
    #[error("the self-update health response is invalid")]
    InvalidHealthResponse,
    #[error("a self-update runtime file changed while it was being verified")]
    ConcurrentChange,
    #[error(transparent)]
    SelfUpdate(#[from] crate::self_update::SelfUpdateError),
    #[error(transparent)]
    Platform(#[from] SelfUpdatePlatformFailureV1),
    #[error("self-update SQLite handling failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("self-update runtime JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("self-update runtime I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("self-update runtime ownership handling failed: {0}")]
    Errno(#[from] rustix::io::Errno),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_update::{
        InstalledSelfUpdatePolicyInputV1, InstalledSelfUpdatePolicyV1,
        SELF_UPDATE_FILESYSTEM_TEST_LOCK, SelfReleaseManifestInputV1, SelfReleaseSignatureInputV1,
        SelfReleaseSourceV1, SelfUpdateFilePolicyV1, build_signed_self_release,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use std::sync::MutexGuard;
    use tempfile::TempDir;

    #[derive(Default)]
    struct FakeRuntime {
        candidate_healthy: bool,
        actions: Vec<&'static str>,
    }

    impl SelfUpdateServiceRuntimeV1 for FakeRuntime {
        fn stop_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1> {
            self.actions.push("stop");
            Ok(())
        }

        fn start_services(&mut self) -> Result<(), SelfUpdatePlatformFailureV1> {
            self.actions.push("start");
            Ok(())
        }

        fn services_are_healthy(&mut self) -> Result<bool, SelfUpdatePlatformFailureV1> {
            self.actions.push("health");
            Ok(self.candidate_healthy)
        }
    }

    struct RuntimeFixture {
        _test_lock: MutexGuard<'static, ()>,
        _directory: TempDir,
        paths: SelfUpdateRuntimePathsV1,
        uid: u32,
        gid: u32,
        build_root: PathBuf,
        signing_key: SigningKey,
        previous: EvidenceDigest,
        candidate: EvidenceDigest,
    }

    impl RuntimeFixture {
        fn new() -> Self {
            let test_lock = SELF_UPDATE_FILESYSTEM_TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let directory = tempfile::tempdir().expect("temporary directory");
            let metadata = fs::symlink_metadata(directory.path()).expect("temporary metadata");
            let uid = metadata.uid();
            let gid = metadata.gid();
            let root = directory.path().join("bootstrap");
            let releases = root.join("releases");
            let backups = root.join("backups");
            for path in [&root, &releases, &backups] {
                fs::create_dir(path).expect("create runtime directory");
                let mode = if path == &root || path == &releases {
                    0o711
                } else {
                    0o700
                };
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .expect("protect runtime directory");
            }
            let database_root = directory.path().join("databases");
            fs::create_dir(&database_root).expect("create database root");
            let control = database_root.join("control.sqlite");
            let security = database_root.join("security.sqlite");
            create_database(&control, "previous-control");
            create_database(&security, "previous-security");
            let paths = SelfUpdateRuntimePathsV1 {
                root: root.clone(),
                releases,
                backups,
                current_link: root.join("current"),
                last_known_good_link: root.join("last-known-good"),
                databases: vec![
                    SelfUpdateStateDatabaseV1::new("control", &control, 8 * 1024 * 1024)
                        .expect("control database"),
                    SelfUpdateStateDatabaseV1::new("security", &security, 8 * 1024 * 1024)
                        .expect("security database"),
                ],
            };
            let build_root = directory.path().join("build");
            fs::create_dir(&build_root).expect("create build root");
            fs::set_permissions(&build_root, fs::Permissions::from_mode(0o2750))
                .expect("protect build root");
            let source = directory.path().join("binary");
            fs::write(&source, b"binary").expect("write binary");
            fs::set_permissions(&source, fs::Permissions::from_mode(0o755))
                .expect("protect binary");
            let signing_key = SigningKey::from_bytes(&[53; 32]);
            let previous = stage_release(
                &paths,
                &build_root,
                &source,
                "previous",
                'a',
                &signing_key,
                uid,
                gid,
            );
            let candidate = stage_release(
                &paths,
                &build_root,
                &source,
                "candidate",
                'b',
                &signing_key,
                uid,
                gid,
            );
            switch_release_link(&paths.current_link, &paths.releases, &previous, uid)
                .expect("activate previous release");
            Self {
                _test_lock: test_lock,
                _directory: directory,
                paths,
                uid,
                gid,
                build_root,
                signing_key,
                previous,
                candidate,
            }
        }

        fn platform(&self, healthy: bool) -> InstalledSelfUpdatePlatformV1<FakeRuntime> {
            InstalledSelfUpdatePlatformV1::open(
                self.paths.clone(),
                self.uid,
                self.uid,
                self.gid,
                FakeRuntime {
                    candidate_healthy: healthy,
                    actions: Vec::new(),
                },
            )
            .expect("open self-update platform")
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_release(
        paths: &SelfUpdateRuntimePathsV1,
        build_root: &Path,
        source: &Path,
        stem: &str,
        sha: char,
        signing_key: &SigningKey,
        uid: u32,
        gid: u32,
    ) -> EvidenceDigest {
        let built = build_signed_self_release(
            build_root,
            stem,
            SelfReleaseManifestInputV1 {
                source_head: sha.to_string().repeat(40).parse().expect("source SHA"),
                source_sequence: 1,
                source_attestation_digest: digest("source"),
                workflow_policy_digest: digest("workflow"),
                verification_receipt_digest: digest("verification"),
                runtime_contract_digest: digest("runtime"),
                state_schema_version: 1,
            },
            vec![SelfReleaseSourceV1 {
                path: "bin/rdashboardd".to_owned(),
                source: source.to_owned(),
                executable: true,
            }],
            SelfReleaseSignatureInputV1 {
                key_id: "self-update-test".to_owned(),
                key_epoch: 1,
                archive_digest: digest("builder replaces"),
                archive_bytes: 1,
                issued_at_ms: 1_000,
                expires_at_ms: 2_000,
            },
            signing_key,
            uid,
            gid,
        )
        .expect("build release");
        let policy = InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
            key_id: "self-update-test".to_owned(),
            key_epoch: 1,
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            runtime_contract_digest: digest("runtime"),
            minimum_state_schema_version: 1,
            maximum_state_schema_version: 1,
            maximum_release_bytes: 8 * 1024 * 1024,
            files: vec![SelfUpdateFilePolicyV1 {
                path: "bin/rdashboardd".to_owned(),
                mode: 0o555,
            }],
        })
        .expect("policy");
        let store = SelfReleaseStoreV1::open(&paths.releases, uid, uid, gid).expect("open store");
        store
            .stage(&built.descriptor_path, &built.archive_path, &policy, 1_500)
            .expect("stage release")
            .manifest_digest
    }

    fn create_database(path: &Path, value: &str) {
        let connection = Connection::open(path).expect("open database");
        connection
            .execute_batch("CREATE TABLE state(value TEXT NOT NULL);")
            .expect("create table");
        connection
            .execute("INSERT INTO state(value) VALUES (?1)", [value])
            .expect("insert state");
        drop(connection);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect database");
    }

    fn database_value(path: &Path) -> String {
        Connection::open(path)
            .expect("open database")
            .query_row("SELECT value FROM state", [], |row| row.get(0))
            .expect("read state")
    }

    fn digest(value: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(value)
    }

    #[test]
    fn online_backups_are_exact_idempotent_and_restore_before_pointer_rollback() {
        let fixture = RuntimeFixture::new();
        let mut platform = fixture.platform(false);
        assert_eq!(
            platform.active_release_checked().expect("active release"),
            fixture.previous
        );
        let operation_id = Uuid::new_v4();
        let receipt = platform
            .backup_state_checked(operation_id, &fixture.candidate)
            .expect("backup state");
        assert_eq!(
            platform
                .backup_state_checked(operation_id, &fixture.candidate)
                .expect("idempotent backup"),
            receipt
        );
        switch_release_link(
            &fixture.paths.current_link,
            &fixture.paths.releases,
            &fixture.candidate,
            fixture.uid,
        )
        .expect("switch candidate");
        for database in &fixture.paths.databases {
            let connection = Connection::open(&database.path).expect("open mutated database");
            connection
                .execute("UPDATE state SET value = 'candidate-state'", [])
                .expect("mutate state");
        }
        fs::write(
            format!("{}-wal", fixture.paths.databases[0].path.display()),
            b"stale candidate wal",
        )
        .expect("write stale WAL");
        platform
            .restore_release_checked(&fixture.previous, &receipt)
            .expect("restore release");
        assert_eq!(
            platform.active_release_checked().expect("restored release"),
            fixture.previous
        );
        assert_eq!(
            database_value(&fixture.paths.databases[0].path),
            "previous-control"
        );
        assert_eq!(
            database_value(&fixture.paths.databases[1].path),
            "previous-security"
        );
        assert_eq!(platform.runtime.actions, ["stop"]);
        assert!(
            !PathBuf::from(format!("{}-wal", fixture.paths.databases[0].path.display())).exists()
        );
    }

    #[test]
    fn interrupted_backup_directory_is_reconciled_before_retry() {
        let fixture = RuntimeFixture::new();
        let platform = fixture.platform(true);
        let operation_id = Uuid::new_v4();
        let operation_root = fixture.paths.backups.join(operation_id.to_string());
        fs::create_dir(&operation_root).expect("create interrupted backup");
        fs::set_permissions(&operation_root, fs::Permissions::from_mode(0o700))
            .expect("protect interrupted backup");
        fs::write(operation_root.join("partial.sqlite"), b"partial").expect("write partial backup");
        let receipt = platform
            .backup_state_checked(operation_id, &fixture.candidate)
            .expect("reconcile and retry backup");
        assert_ne!(receipt, EvidenceDigest::sha256([]));
        assert!(!operation_root.join("partial.sqlite").exists());
        assert!(operation_root.join(STATE_BACKUP_RECEIPT_FILE).exists());
    }

    #[test]
    fn replayed_failed_restore_reconciles_and_removes_its_exact_temporary_database() {
        let fixture = RuntimeFixture::new();
        let platform = fixture.platform(true);
        let operation_id = Uuid::new_v4();
        let receipt_digest = platform
            .backup_state_checked(operation_id, &fixture.candidate)
            .expect("backup state");
        let (operation_root, receipt) = platform
            .find_backup_receipt(&receipt_digest)
            .expect("find backup receipt");
        let database = &fixture.paths.databases[0];
        let backup_file = receipt
            .files
            .iter()
            .find(|file| file.name == database.name)
            .expect("find backup file");
        let unsafe_sidecar = PathBuf::from(format!("{}-shm", database.path.display()));
        symlink("outside", &unsafe_sidecar).expect("substitute database sidecar");
        let parent = database.path.parent().expect("database parent");
        let interrupted = parent.join(format!(
            ".self-update-{operation_id}-{}.sqlite",
            database.name
        ));
        symlink("outside", &interrupted).expect("substitute interrupted restore");
        assert!(matches!(
            restore_database(
                database,
                &operation_root.join(format!("{}.sqlite", database.name)),
                backup_file,
                fixture.uid,
                operation_id,
            ),
            Err(SelfUpdateRuntimeError::UnsafeDatabase)
        ));
        assert!(
            fs::symlink_metadata(&interrupted)
                .expect("substituted restore metadata")
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&interrupted).expect("remove substituted restore");
        fs::write(&interrupted, b"interrupted restore").expect("write interrupted restore");
        fs::set_permissions(&interrupted, fs::Permissions::from_mode(0o600))
            .expect("protect interrupted restore");

        assert!(matches!(
            restore_database(
                database,
                &operation_root.join(format!("{}.sqlite", database.name)),
                backup_file,
                fixture.uid,
                operation_id,
            ),
            Err(SelfUpdateRuntimeError::UnsafeDatabase)
        ));
        assert!(
            fs::read_dir(parent)
                .expect("read database parent")
                .all(|entry| !entry
                    .expect("database parent entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".self-update-"))
        );
    }

    #[test]
    fn release_links_are_relative_exact_and_reject_substituted_targets() {
        let fixture = RuntimeFixture::new();
        assert_eq!(
            fs::read_link(&fixture.paths.current_link).expect("read current link"),
            Path::new("releases").join(fixture.previous.as_str())
        );
        let interrupted = fixture.paths.root.join(format!(".link-{}", Uuid::new_v4()));
        symlink(
            Path::new("releases").join(fixture.previous.as_str()),
            &interrupted,
        )
        .expect("create interrupted release link");
        fs::remove_file(&fixture.paths.current_link).expect("remove current link");
        symlink("/tmp", &fixture.paths.current_link).expect("substitute current link");
        let platform = fixture.platform(true);
        assert!(!interrupted.exists());
        assert!(matches!(
            platform.active_release_checked(),
            Err(SelfUpdateRuntimeError::UnsafeReleasePointer)
        ));
    }

    #[test]
    fn runtime_contract_has_one_fixed_dependency_order() {
        assert_eq!(
            SELF_UPDATE_SERVICE_ORDER.first(),
            Some(&"rdashboard-source.service")
        );
        assert_eq!(
            SELF_UPDATE_SERVICE_ORDER.last(),
            Some(&"rdashboard.service")
        );
        assert_eq!(
            SELF_UPDATE_SERVICE_ORDER
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            SELF_UPDATE_SERVICE_ORDER.len()
        );
        assert_eq!(
            SELF_UPDATE_QUIESCE_ONLY_SERVICES,
            ["rdashboard-rimg-health.service"]
        );
        assert!(
            SELF_UPDATE_QUIESCE_ONLY_SERVICES
                .iter()
                .all(|service| !SELF_UPDATE_SERVICE_ORDER.contains(service))
        );
        assert_eq!(SYSTEMCTL_EXECUTABLE, "/usr/bin/systemctl");
        assert_eq!(HEALTH_ADDRESS, "127.0.0.1:3100");
    }

    #[test]
    fn fixture_keeps_the_signed_handoff_inputs_alive() {
        let fixture = RuntimeFixture::new();
        assert!(fixture.build_root.exists());
        assert_ne!(fixture.signing_key.to_bytes(), [0_u8; 32]);
    }
}
