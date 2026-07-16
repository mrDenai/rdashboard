use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{BackupAdapterError, BackupCaptureRuntimeV1, CapturedBackupEvidenceV1};
use crate::{
    adapter_identity::AdapterOperationIdentityV1,
    backup::{
        BackupCheckEvidenceV1, BackupCheckKindV1, BackupCheckOutcomeV1, BackupObjectKindV1,
        BackupObjectV1,
    },
    domain::EvidenceDigest,
    phase6::AuthorizedPhaseSpecV1,
    rimg_adapter::{
        RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION, RimgAdminRuntimeV1, RimgObservedDocumentV1,
        RimgOperationalStatusV1, RimgRuntimeSchemaCompatibilityV1, RimgRuntimeSchemaInspectionV1,
        runtime::{InstalledRimgAdminRuntimeV1, RIMG_OPERATION_LOCK_PATH, RimgAdminActionV1},
    },
};

pub const RDASHBOARD_BACKUP_ROOT: &str = "/var/lib/rdashboard-executor/backups";
pub const RIMG_MASTERS_PATH: &str = "/var/lib/rimg/masters";

const RIMG_BACKUP_REQUEST_FILE_NAME: &str = "rimg-backup-request.jcs";
const RIMG_BACKUP_SCHEMA_VERSION: u16 = 1;
const MAX_RIMG_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MASTER_FILES: usize = 65_536;
const MAX_MASTER_PATH_BYTES: usize = 512;
const MASTERS_BUNDLE_FILE_NAME: &str = "masters.bundle";
const MASTERS_BUNDLE_PENDING_FILE_NAME: &str = "masters.bundle.pending";
const MASTERS_BUNDLE_MAGIC: &[u8; 8] = b"RDBMSTR1";

#[derive(Serialize)]
struct RimgBackupRequestV1 {
    schema_version: u16,
    epoch: u64,
    token: uuid::Uuid,
    operation_lock_path: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RimgBackupFileV1 {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RimgBackupManifestV1 {
    schema_version: u16,
    created_at: i64,
    application_schema: u32,
    database: RimgBackupFileV1,
    masters: Vec<RimgBackupFileV1>,
    expected_master_count: u64,
    unexpected_master_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RimgBackupReportV1 {
    schema_version: u16,
    output_directory: PathBuf,
    manifest_path: PathBuf,
    manifest_sha256: String,
    database_sha256: String,
    master_file_count: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
struct BackupCheckObservationV1<'a> {
    purpose: &'static str,
    kind: BackupCheckKindV1,
    rimg_manifest_sha256: &'a EvidenceDigest,
    database_sha256: &'a EvidenceDigest,
    masters_bundle_sha256: &'a EvidenceDigest,
    application_schema: u32,
    job_count: u64,
}

impl BackupCaptureRuntimeV1 for InstalledRimgAdminRuntimeV1 {
    fn begin_drain(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
        Ok(RimgAdminRuntimeV1::begin_drain(self, identity)?)
    }

    fn operational_status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
        Ok(RimgAdminRuntimeV1::operational_status(self)?)
    }

    fn capture(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        identity: &AdapterOperationIdentityV1,
        create_if_missing: bool,
    ) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
        self.capture_installed(spec, identity, create_if_missing)
    }

    fn resume(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
        Ok(self.apply_admin_action(RimgAdminActionV1::Resume, identity)?)
    }

    fn wait_before_drain_poll(&mut self) -> Result<(), BackupAdapterError> {
        Ok(RimgAdminRuntimeV1::wait_before_drain_poll(self)?)
    }
}

impl InstalledRimgAdminRuntimeV1 {
    fn capture_installed(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        identity: &AdapterOperationIdentityV1,
        create_if_missing: bool,
    ) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
        let backup = spec
            .backup
            .as_ref()
            .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
        let root = Path::new(RDASHBOARD_BACKUP_ROOT);
        validate_private_directory(root, 0)?;
        let output = root.join(backup.backup_id.to_string());
        match fs::symlink_metadata(&output) {
            Err(error) if error.kind() == io::ErrorKind::NotFound && create_if_missing => {
                self.create_rimg_snapshot(identity, &output)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(BackupAdapterError::MissingCompletedSnapshot);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        inspect_rimg_snapshot(self, spec, &output, 0)
    }

    fn create_rimg_snapshot(
        &mut self,
        identity: &AdapterOperationIdentityV1,
        output: &Path,
    ) -> Result<(), BackupAdapterError> {
        let request = self.materialize_request(
            RIMG_BACKUP_REQUEST_FILE_NAME,
            &RimgBackupRequestV1 {
                schema_version: RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION,
                epoch: identity.epoch,
                token: identity.token,
                operation_lock_path: RIMG_OPERATION_LOCK_PATH,
            },
        )?;
        let database = self.database_argument()?;
        let request = path_argument(&request)?;
        let output_argument = path_argument(output)?;
        let report = self
            .invoke_json::<RimgBackupReportV1>(&[
                "backup",
                "create",
                "--database",
                database,
                "--masters",
                RIMG_MASTERS_PATH,
                "--output",
                output_argument,
                "--request",
                request,
            ])?
            .document;
        validate_rimg_report(&report, output)?;
        Ok(())
    }
}

fn inspect_rimg_snapshot(
    runtime: &InstalledRimgAdminRuntimeV1,
    spec: &AuthorizedPhaseSpecV1,
    output: &Path,
    required_uid: u32,
) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
    validate_private_directory(output, required_uid)?;
    let manifest_path = output.join("manifest.json");
    let manifest_bytes =
        read_stable_private_file(&manifest_path, required_uid, MAX_RIMG_MANIFEST_BYTES)?;
    let manifest: RimgBackupManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    validate_rimg_manifest(&manifest)?;
    let manifest_digest = EvidenceDigest::sha256(&manifest_bytes);
    let database_path = output.join("database.sqlite");
    let database = verified_file(&database_path, required_uid)?;
    if manifest.database.path != "database.sqlite"
        || manifest.database.size != database.size_bytes
        || parse_digest(&manifest.database.sha256)? != database.sha256
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    validate_master_files(output, &manifest, required_uid)?;
    let bundle = materialize_masters_bundle(output, &manifest, required_uid)?;
    validate_snapshot_root_inventory(output)?;
    let inspection = inspect_snapshot_schema(runtime, &database_path, &manifest)?;
    let job_count = validate_snapshot_database(&database_path, &manifest)?;
    build_capture_evidence(
        spec,
        &manifest,
        &manifest_digest,
        database,
        bundle,
        inspection.current_application_schema,
        job_count,
    )
}

fn validate_rimg_report(
    report: &RimgBackupReportV1,
    output: &Path,
) -> Result<(), BackupAdapterError> {
    if report.schema_version != RIMG_BACKUP_SCHEMA_VERSION
        || report.output_directory != output
        || report.manifest_path != output.join("manifest.json")
        || report.master_file_count > u64::try_from(MAX_MASTER_FILES).unwrap_or(u64::MAX)
        || report.total_bytes == 0
        || parse_digest(&report.manifest_sha256).is_err()
        || parse_digest(&report.database_sha256).is_err()
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_rimg_manifest(manifest: &RimgBackupManifestV1) -> Result<(), BackupAdapterError> {
    if manifest.schema_version != RIMG_BACKUP_SCHEMA_VERSION
        || manifest.created_at < 0
        || manifest.application_schema == 0
        || manifest.masters.len() > MAX_MASTER_FILES
        || !manifest.unexpected_master_paths.is_empty()
        || manifest.database.path != "database.sqlite"
        || manifest.database.size == 0
        || parse_digest(&manifest.database.sha256).is_err()
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    let mut previous = None;
    for file in &manifest.masters {
        validate_master_path(&file.path)?;
        if previous.is_some_and(|value| value >= file.path.as_str())
            || parse_digest(&file.sha256).is_err()
        {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
        previous = Some(file.path.as_str());
    }
    Ok(())
}

fn validate_master_files(
    output: &Path,
    manifest: &RimgBackupManifestV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let actual_paths = collect_master_inventory(&output.join("masters"), required_uid)?;
    let expected_paths = manifest
        .masters
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    for expected in &manifest.masters {
        let actual = verified_file(&output.join("masters").join(&expected.path), required_uid)?;
        if actual.size_bytes != expected.size || actual.sha256 != parse_digest(&expected.sha256)? {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn collect_master_inventory(
    root: &Path,
    required_uid: u32,
) -> Result<BTreeSet<String>, BackupAdapterError> {
    validate_private_directory(root, required_uid)?;
    let mut directories = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    let mut nested_directories = BTreeSet::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata.uid() != required_uid {
                return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
            }
            if metadata.is_dir() {
                if metadata.mode().trailing_zeros() < 6 {
                    return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| BackupAdapterError::UnsafeSnapshotFilesystem)?
                    .to_str()
                    .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?
                    .to_owned();
                validate_master_path(&relative)?;
                nested_directories.insert(relative);
                directories.push(path);
            } else if safe_private_file_metadata(&metadata, required_uid) {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| BackupAdapterError::UnsafeSnapshotFilesystem)?
                    .to_str()
                    .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?
                    .to_owned();
                validate_master_path(&relative)?;
                if !files.insert(relative) || files.len() > MAX_MASTER_FILES {
                    return Err(BackupAdapterError::InvalidSnapshot);
                }
            } else {
                return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
            }
        }
    }
    if nested_directories.iter().any(|directory| {
        let prefix = format!("{directory}/");
        !files.iter().any(|path| path.starts_with(&prefix))
    }) {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(files)
}

fn validate_snapshot_root_inventory(output: &Path) -> Result<(), BackupAdapterError> {
    let mut names = fs::read_dir(output)?
        .map(|entry| {
            entry
                .map(|value| value.file_name())
                .map_err(BackupAdapterError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let expected = [
        std::ffi::OsString::from("database.sqlite"),
        std::ffi::OsString::from("manifest.json"),
        std::ffi::OsString::from("masters"),
        std::ffi::OsString::from(MASTERS_BUNDLE_FILE_NAME),
    ];
    if names != expected {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

fn inspect_snapshot_schema(
    runtime: &InstalledRimgAdminRuntimeV1,
    database_path: &Path,
    manifest: &RimgBackupManifestV1,
) -> Result<RimgRuntimeSchemaInspectionV1, BackupAdapterError> {
    let database = path_argument(database_path)?;
    let inspection = runtime
        .invoke_json::<RimgRuntimeSchemaInspectionV1>(&[
            "schema",
            "inspect",
            "--database",
            database,
        ])?
        .document;
    if inspection.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        || !inspection.database_exists
        || inspection.current_application_schema != manifest.application_schema
        || inspection.latest_application_schema != manifest.application_schema
        || inspection.pending_migrations != 0
        || inspection.compatibility != RimgRuntimeSchemaCompatibilityV1::Current
        || inspection.integrity_check != "ok"
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(inspection)
}

fn validate_snapshot_database(
    database_path: &Path,
    manifest: &RimgBackupManifestV1,
) -> Result<u64, BackupAdapterError> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let integrity =
        connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?;
    let foreign_key_violations =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?;
    let expected_masters = expected_master_ids(&connection)?;
    let present_masters = manifest
        .masters
        .iter()
        .filter_map(|file| master_id_from_path(&file.path, "master"))
        .collect::<BTreeSet<_>>();
    let all_files_belong_to_expected_masters = manifest.masters.iter().all(|file| {
        master_id_from_path(&file.path, "master")
            .or_else(|| master_id_from_path(&file.path, "json"))
            .is_some_and(|id| expected_masters.contains(&id))
    });
    let job_count =
        connection.query_row("SELECT count(*) FROM jobs", [], |row| row.get::<_, i64>(0))?;
    if integrity != "ok"
        || foreign_key_violations != 0
        || expected_masters != present_masters
        || !all_files_belong_to_expected_masters
        || manifest.expected_master_count
            != u64::try_from(expected_masters.len()).unwrap_or(u64::MAX)
        || job_count < 0
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    u64::try_from(job_count).map_err(|_| BackupAdapterError::InvalidSnapshot)
}

fn expected_master_ids(connection: &Connection) -> Result<BTreeSet<String>, BackupAdapterError> {
    let mut statement =
        connection.prepare("SELECT md5 FROM jobs WHERE status != 'failed' ORDER BY md5 ASC")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut expected = BTreeSet::new();
    for row in rows {
        let md5 = row?;
        if md5.len() != 32 || !md5.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
        expected.insert(md5.to_ascii_lowercase());
    }
    Ok(expected)
}

fn build_capture_evidence(
    spec: &AuthorizedPhaseSpecV1,
    manifest: &RimgBackupManifestV1,
    manifest_digest: &EvidenceDigest,
    database: BackupObjectMaterialV1,
    bundle: BackupObjectMaterialV1,
    application_schema: u32,
    job_count: u64,
) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
    let backup = spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let database_contract = backup
        .unit
        .expected_objects
        .iter()
        .find(|object| object.path == backup.unit.primary_sqlite_path)
        .ok_or(BackupAdapterError::InvalidSnapshot)?;
    let master_contracts = backup
        .unit
        .expected_objects
        .iter()
        .filter(|object| object.kind == BackupObjectKindV1::Master)
        .collect::<Vec<_>>();
    if backup.unit.expected_objects.len() != 2 || master_contracts.len() != 1 {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    let objects = vec![
        database.into_object(
            database_contract.path.clone(),
            BackupObjectKindV1::SqliteDatabase,
        ),
        bundle.into_object(master_contracts[0].path.clone(), BackupObjectKindV1::Master),
    ];
    let checks = backup
        .unit
        .required_checks
        .iter()
        .map(|check| {
            let observation_digest =
                EvidenceDigest::sha256(serde_jcs::to_vec(&BackupCheckObservationV1 {
                    purpose: "rdashboard.rimg-backup-check-observation.v1",
                    kind: check.kind,
                    rimg_manifest_sha256: manifest_digest,
                    database_sha256: &objects[0].sha256,
                    masters_bundle_sha256: &objects[1].sha256,
                    application_schema,
                    job_count,
                })?);
            Ok(BackupCheckEvidenceV1 {
                name: check.name.clone(),
                kind: check.kind,
                definition_digest: check.definition_digest.clone(),
                checked_object_digest: objects[0].sha256.clone(),
                outcome: BackupCheckOutcomeV1::Passed,
                observation_digest,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    if application_schema != manifest.application_schema {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(CapturedBackupEvidenceV1 {
        captured_at_ms: manifest
            .created_at
            .checked_mul(1_000)
            .ok_or(BackupAdapterError::InvalidSnapshot)?,
        application_schema_version: application_schema.to_string(),
        objects,
        checks,
    })
}

#[derive(Clone, Debug)]
struct BackupObjectMaterialV1 {
    size_bytes: u64,
    sha256: EvidenceDigest,
    uid: u32,
    gid: u32,
    mode: u32,
    hard_link_count: u64,
}

impl BackupObjectMaterialV1 {
    fn into_object(
        self,
        path: crate::domain::RelativePolicyPath,
        kind: BackupObjectKindV1,
    ) -> BackupObjectV1 {
        BackupObjectV1 {
            path,
            kind,
            size_bytes: self.size_bytes,
            sha256: self.sha256,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            hard_link_count: self.hard_link_count,
        }
    }
}

fn materialize_masters_bundle(
    output: &Path,
    manifest: &RimgBackupManifestV1,
    required_uid: u32,
) -> Result<BackupObjectMaterialV1, BackupAdapterError> {
    let final_path = output.join(MASTERS_BUNDLE_FILE_NAME);
    let pending_path = output.join(MASTERS_BUNDLE_PENDING_FILE_NAME);
    if final_path.exists() {
        reconcile_bundle_pending(&pending_path, &final_path, required_uid)?;
        validate_masters_bundle(&final_path, manifest, required_uid)?;
        return verified_file(&final_path, required_uid);
    }
    remove_safe_pending(&pending_path, required_uid)?;
    write_masters_bundle(&pending_path, output, manifest, required_uid)?;
    match fs::hard_link(&pending_path, &final_path) {
        Ok(()) => sync_directory(output)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&pending_path)?;
    sync_directory(output)?;
    validate_masters_bundle(&final_path, manifest, required_uid)?;
    verified_file(&final_path, required_uid)
}

fn write_masters_bundle(
    pending_path: &Path,
    output: &Path,
    manifest: &RimgBackupManifestV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut bundle = options.open(pending_path)?;
    bundle.write_all(MASTERS_BUNDLE_MAGIC)?;
    bundle.write_all(
        &u32::try_from(manifest.masters.len())
            .map_err(|_| BackupAdapterError::InvalidSnapshot)?
            .to_be_bytes(),
    )?;
    for entry in &manifest.masters {
        write_bundle_entry(&mut bundle, output, entry, required_uid)?;
    }
    bundle.sync_all()?;
    Ok(())
}

fn write_bundle_entry(
    bundle: &mut File,
    output: &Path,
    entry: &RimgBackupFileV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let path = entry.path.as_bytes();
    bundle.write_all(
        &u32::try_from(path.len())
            .map_err(|_| BackupAdapterError::InvalidSnapshot)?
            .to_be_bytes(),
    )?;
    bundle.write_all(path)?;
    bundle.write_all(&entry.size.to_be_bytes())?;
    let expected_digest = decode_digest_bytes(&entry.sha256)?;
    bundle.write_all(&expected_digest)?;
    let source_path = output.join("masters").join(&entry.path);
    let path_metadata = fs::symlink_metadata(&source_path)?;
    if !safe_private_file_metadata(&path_metadata, required_uid) {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let mut source = File::open(&source_path)?;
    let opened_metadata = source.metadata()?;
    if opened_metadata.dev() != path_metadata.dev() || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let actual_digest = copy_exact_and_hash(&mut source, bundle, entry.size)?;
    let mut trailing = [0_u8; 1];
    let final_metadata = fs::symlink_metadata(&source_path)?;
    if actual_digest != expected_digest
        || source.read(&mut trailing)? != 0
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_masters_bundle(
    bundle_path: &Path,
    manifest: &RimgBackupManifestV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let _metadata = verified_file(bundle_path, required_uid)?;
    let mut bundle = File::open(bundle_path)?;
    let mut magic = [0_u8; 8];
    bundle.read_exact(&mut magic)?;
    if &magic != MASTERS_BUNDLE_MAGIC
        || read_u32(&mut bundle)?
            != u32::try_from(manifest.masters.len())
                .map_err(|_| BackupAdapterError::MastersBundleMismatch)?
    {
        return Err(BackupAdapterError::MastersBundleMismatch);
    }
    for expected in &manifest.masters {
        validate_bundle_entry(&mut bundle, expected)?;
    }
    let mut trailing = [0_u8; 1];
    if bundle.read(&mut trailing)? != 0 {
        return Err(BackupAdapterError::MastersBundleMismatch);
    }
    Ok(())
}

fn validate_bundle_entry(
    bundle: &mut File,
    expected: &RimgBackupFileV1,
) -> Result<(), BackupAdapterError> {
    let path_length = usize::try_from(read_u32(bundle)?)
        .map_err(|_| BackupAdapterError::MastersBundleMismatch)?;
    if path_length == 0 || path_length > MAX_MASTER_PATH_BYTES {
        return Err(BackupAdapterError::MastersBundleMismatch);
    }
    let mut path = vec![0_u8; path_length];
    bundle.read_exact(&mut path)?;
    let size = read_u64(bundle)?;
    let mut digest = [0_u8; 32];
    bundle.read_exact(&mut digest)?;
    if path != expected.path.as_bytes()
        || size != expected.size
        || digest != decode_digest_bytes(&expected.sha256)?
    {
        return Err(BackupAdapterError::MastersBundleMismatch);
    }
    if copy_exact_and_hash(bundle, &mut io::sink(), size)? != digest {
        return Err(BackupAdapterError::MastersBundleMismatch);
    }
    Ok(())
}

fn copy_exact_and_hash(
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
    expected_size: u64,
) -> Result<[u8; 32], BackupAdapterError> {
    let mut remaining = expected_size;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let maximum =
            usize::try_from(remaining.min(u64::try_from(buffer.len()).unwrap_or(u64::MAX)))
                .map_err(|_| BackupAdapterError::MastersBundleMismatch)?;
        let read = reader.read(&mut buffer[..maximum])?;
        if read == 0 {
            return Err(BackupAdapterError::MastersBundleMismatch);
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(BackupAdapterError::MastersBundleMismatch)?;
    }
    Ok(hasher.finalize().into())
}

fn reconcile_bundle_pending(
    pending: &Path,
    final_path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(pending) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            let final_metadata = fs::symlink_metadata(final_path)?;
            if !private_regular_file_metadata(&metadata, required_uid)
                || metadata.nlink() != 2
                || !private_regular_file_metadata(&final_metadata, required_uid)
                || final_metadata.nlink() != 2
                || metadata.dev() != final_metadata.dev()
                || metadata.ino() != final_metadata.ino()
            {
                return Err(BackupAdapterError::MastersBundleMismatch);
            }
            fs::remove_file(pending)?;
            sync_directory(
                final_path
                    .parent()
                    .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?,
            )?;
            Ok(())
        }
    }
}

fn remove_safe_pending(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if safe_private_file_metadata(&metadata, required_uid) => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(BackupAdapterError::UnsafeSnapshotFilesystem),
    }
}

fn verified_file(
    path: &Path,
    required_uid: u32,
) -> Result<BackupObjectMaterialV1, BackupAdapterError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !safe_private_file_metadata(&path_metadata, required_uid) {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened.dev()
        || final_metadata.ino() != opened.ino()
        || final_metadata.len() != opened.len()
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    Ok(BackupObjectMaterialV1 {
        size_bytes: opened.len(),
        sha256: digest_from_hasher(hasher)?,
        uid: opened.uid(),
        gid: opened.gid(),
        mode: opened.mode() & 0o777,
        hard_link_count: opened.nlink(),
    })
}

fn read_stable_private_file(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, BackupAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if !safe_private_file_metadata(&metadata, required_uid)
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(BackupAdapterError::SnapshotManifestTooLarge);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
        || final_metadata.dev() != opened.dev()
        || final_metadata.ino() != opened.ino()
        || final_metadata.len() != opened.len()
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    Ok(bytes)
}

fn safe_private_file_metadata(metadata: &fs::Metadata, required_uid: u32) -> bool {
    private_regular_file_metadata(metadata, required_uid) && metadata.nlink() == 1
}

fn private_regular_file_metadata(metadata: &fs::Metadata, required_uid: u32) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == required_uid
        && metadata.mode().trailing_zeros() >= 6
}

fn validate_private_directory(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != required_uid
        || metadata.mode().trailing_zeros() < 6
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    Ok(())
}

fn validate_master_path(value: &str) -> Result<(), BackupAdapterError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_MASTER_PATH_BYTES
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.components().collect::<PathBuf>() != path
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

fn master_id_from_path(path: &str, extension: &str) -> Option<String> {
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() != 5
        || components[..4].iter().any(|component| {
            component.len() != 1 || !component.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return None;
    }
    let tail = components[4].strip_suffix(&format!(".{extension}"))?;
    if tail.len() != 28 || !tail.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        format!(
            "{}{}{}{}{}",
            components[0], components[1], components[2], components[3], tail
        )
        .to_ascii_lowercase(),
    )
}

fn path_argument(path: &Path) -> Result<&str, BackupAdapterError> {
    path.to_str().ok_or(BackupAdapterError::InvalidSnapshot)
}

fn parse_digest(value: &str) -> Result<EvidenceDigest, BackupAdapterError> {
    EvidenceDigest::from_str(value).map_err(|_| BackupAdapterError::InvalidSnapshot)
}

fn decode_digest_bytes(value: &str) -> Result<[u8; 32], BackupAdapterError> {
    if value.len() != 64 {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex_nibble(pair[0])? << 4) | decode_hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, BackupAdapterError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(BackupAdapterError::InvalidSnapshot),
    }
}

fn digest_from_hasher(hasher: Sha256) -> Result<EvidenceDigest, BackupAdapterError> {
    EvidenceDigest::from_str(&format!("{:x}", hasher.finalize()))
        .map_err(|_| BackupAdapterError::InvalidSnapshot)
}

fn read_u32(reader: &mut impl io::Read) -> Result<u32, BackupAdapterError> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl io::Read) -> Result<u64, BackupAdapterError> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn sync_directory(path: &Path) -> Result<(), BackupAdapterError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn masters_bundle_is_deterministic_tamper_evident_and_recovers_post_link() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("tempdir metadata: {error}"))
            .uid();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("tempdir permissions: {error}"));
        let relative = "a/b/c/d/1111111111111111111111111111.master";
        let master_path = directory.path().join("masters").join(relative);
        fs::create_dir_all(
            master_path
                .parent()
                .unwrap_or_else(|| panic!("master parent")),
        )
        .unwrap_or_else(|error| panic!("master directories: {error}"));
        fs::write(&master_path, b"master bytes").unwrap_or_else(|error| panic!("master: {error}"));
        fs::set_permissions(&master_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("master permissions: {error}"));
        let manifest = manifest(relative, b"master bytes");

        let first = materialize_masters_bundle(directory.path(), &manifest, uid)
            .unwrap_or_else(|error| panic!("materialize bundle: {error}"));
        let final_path = directory.path().join(MASTERS_BUNDLE_FILE_NAME);
        let pending_path = directory.path().join(MASTERS_BUNDLE_PENDING_FILE_NAME);
        fs::hard_link(&final_path, &pending_path)
            .unwrap_or_else(|error| panic!("simulate post-link crash: {error}"));
        let replay = materialize_masters_bundle(directory.path(), &manifest, uid)
            .unwrap_or_else(|error| panic!("reconcile bundle: {error}"));
        assert_eq!(first.sha256, replay.sha256);
        assert_eq!(
            fs::metadata(&final_path)
                .unwrap_or_else(|error| panic!("bundle metadata: {error}"))
                .nlink(),
            1
        );

        let mut bytes =
            fs::read(&final_path).unwrap_or_else(|error| panic!("read bundle for tamper: {error}"));
        let last = bytes
            .last_mut()
            .unwrap_or_else(|| panic!("nonempty bundle"));
        *last ^= 1;
        fs::write(&final_path, bytes).unwrap_or_else(|error| panic!("tamper bundle: {error}"));
        assert!(matches!(
            validate_masters_bundle(&final_path, &manifest, uid),
            Err(BackupAdapterError::MastersBundleMismatch)
        ));
    }

    fn manifest(path: &str, bytes: &[u8]) -> RimgBackupManifestV1 {
        RimgBackupManifestV1 {
            schema_version: 1,
            created_at: 1,
            application_schema: 4,
            database: RimgBackupFileV1 {
                path: "database.sqlite".to_owned(),
                size: 1,
                sha256: EvidenceDigest::sha256("database").to_string(),
            },
            masters: vec![RimgBackupFileV1 {
                path: path.to_owned(),
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                sha256: EvidenceDigest::sha256(bytes).to_string(),
            }],
            expected_master_count: 1,
            unexpected_master_paths: Vec::new(),
        }
    }
}
