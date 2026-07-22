use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OpenFlags, backup::Backup};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{BackupAdapterError, CapturedBackupEvidenceV1, OnlineSqliteBackupCaptureRuntimeV1};
use crate::{
    adapter_identity::AdapterOperationIdentityV1,
    backup::{
        BackupCheckEvidenceV1, BackupCheckKindV1, BackupCheckOutcomeV1,
        BackupConsistencyMechanismV1, BackupObjectKindV1, BackupObjectV1,
    },
    domain::{EvidenceDigest, ProjectId},
    phase6::AuthorizedPhaseSpecV1,
    rimg_adapter::runtime::{read_stable_private_file, validate_private_directory},
};

const PROJECT_CONFIG_ROOT: &str = "/etc/rdashboard/projects";
const BACKUP_ROOT: &str = "/var/lib/rdashboard-executor/backups";
const DOCKER_VOLUME_ROOT: &str = "/var/lib/docker/volumes";
const MANAGED_PROJECT_ROOT: &str = "/var/lib/rdashboard/projects";
const MAX_RUNTIME_CONFIG_BYTES: u64 = 32 * 1024;
const MAX_CAPTURE_STATE_BYTES: u64 = 16 * 1024;
const MAX_REQUIRED_TABLES: usize = 256;
const MAX_TABLE_NAME_BYTES: usize = 128;
const BACKUP_PAGES_PER_STEP: i32 = 128;
const BACKUP_STEP_PAUSE: Duration = Duration::from_millis(5);
const CAPTURE_STATE_FILE_NAME: &str = "sqlite-capture-state.jcs";

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSqliteBackupRuntimeV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub source_database_path: String,
    pub required_tables: Vec<String>,
}

impl InstalledSqliteBackupRuntimeV1 {
    fn load(
        config_path: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
        allowed_source_roots: &[PathBuf],
    ) -> Result<Self, BackupAdapterError> {
        let bytes = read_stable_private_file(config_path, required_uid, MAX_RUNTIME_CONFIG_BYTES)?;
        let config: Self = serde_json::from_slice(&bytes)?;
        if serde_jcs::to_vec(&config)? != bytes
            || config.purpose != "rdashboard.installed-sqlite-backup-runtime.v1"
            || config.schema_version != 1
            || config.project_id != spec.project_id
            || config.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
            || config.source_database_path.len() > 4_096
            || !valid_required_tables(&config.required_tables)
            || !valid_source_database_path(
                Path::new(&config.source_database_path),
                allowed_source_roots,
            )
        {
            return Err(BackupAdapterError::RuntimeConfigMismatch);
        }
        validate_source_database(Path::new(&config.source_database_path), required_uid)?;
        Ok(config)
    }
}

#[derive(Debug)]
pub struct InstalledOnlineSqliteBackupRuntimeV1 {
    config: InstalledSqliteBackupRuntimeV1,
    backup_root: PathBuf,
    required_uid: u32,
}

impl InstalledOnlineSqliteBackupRuntimeV1 {
    pub fn new(spec: &AuthorizedPhaseSpecV1) -> Result<Self, BackupAdapterError> {
        let project = spec.project_id.as_str();
        let config_path = Path::new(PROJECT_CONFIG_ROOT)
            .join(project)
            .join("sqlite-backup-runtime.jcs");
        let allowed_source_roots = installed_source_roots(&spec.project_id);
        Self::new_bound(
            &config_path,
            Path::new(BACKUP_ROOT),
            0,
            spec,
            &allowed_source_roots,
        )
    }

    fn new_bound(
        config_path: &Path,
        backup_root: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
        allowed_source_roots: &[PathBuf],
    ) -> Result<Self, BackupAdapterError> {
        validate_private_directory(backup_root, required_uid)?;
        let config = InstalledSqliteBackupRuntimeV1::load(
            config_path,
            required_uid,
            spec,
            allowed_source_roots,
        )?;
        Ok(Self {
            config,
            backup_root: backup_root.to_path_buf(),
            required_uid,
        })
    }
}

impl OnlineSqliteBackupCaptureRuntimeV1 for InstalledOnlineSqliteBackupRuntimeV1 {
    fn capture(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        _identity: &AdapterOperationIdentityV1,
    ) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
        let backup = spec
            .backup
            .as_ref()
            .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
        if backup.unit.consistency != BackupConsistencyMechanismV1::SqliteOnlineBackupV1
            || backup.unit.expected_objects.len() != 1
            || backup.unit.expected_objects[0].kind != BackupObjectKindV1::SqliteDatabase
            || backup.unit.expected_objects[0].path != backup.unit.primary_sqlite_path
            || backup.unit.primary_sqlite_path.as_str() == CAPTURE_STATE_FILE_NAME
        {
            return Err(BackupAdapterError::RuntimeConfigMismatch);
        }
        let output = self.backup_root.join(backup.backup_id.to_string());
        ensure_snapshot_directory(&self.backup_root, &output, self.required_uid)?;
        let database_path = output.join(backup.unit.primary_sqlite_path.as_str());
        let state_path = output.join(CAPTURE_STATE_FILE_NAME);
        ensure_snapshot_parent(&output, &database_path, self.required_uid)?;
        let replay = reconcile_snapshot_pair(
            Path::new(&self.config.source_database_path),
            &database_path,
            &state_path,
            self.required_uid,
        )?;
        let mut captured =
            inspect_sqlite_snapshot(spec, &self.config, &database_path, self.required_uid)?;
        let state = if replay {
            read_capture_state(&state_path, self.required_uid)?
        } else {
            let state = SqliteCaptureStateV1::from_capture(spec, &captured)?;
            publish_capture_state(&state_path, &state, self.required_uid)?;
            state
        };
        state.validate(spec, &captured)?;
        captured.captured_at_ms = state.captured_at_ms;
        validate_snapshot_inventory(
            &output,
            backup.unit.primary_sqlite_path.as_str(),
            CAPTURE_STATE_FILE_NAME,
            self.required_uid,
        )?;
        Ok(captured)
    }
}

fn installed_source_roots(project_id: &ProjectId) -> Vec<PathBuf> {
    let project = project_id.as_str();
    vec![
        Path::new(DOCKER_VOLUME_ROOT)
            .join(format!("{project}-data"))
            .join("_data"),
        Path::new(MANAGED_PROJECT_ROOT).join(project).join("data"),
    ]
}

fn valid_required_tables(tables: &[String]) -> bool {
    !tables.is_empty()
        && tables.len() <= MAX_REQUIRED_TABLES
        && tables.windows(2).all(|pair| pair[0] < pair[1])
        && tables.iter().all(|table| {
            (1..=MAX_TABLE_NAME_BYTES).contains(&table.len())
                && table
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

fn valid_source_database_path(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
        && path.file_name().is_some()
        && allowed_roots.iter().any(|root| path.starts_with(root))
}

fn validate_source_database(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if fs::canonicalize(path)? != path
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != required_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    Ok(())
}

fn ensure_snapshot_directory(
    backup_root: &Path,
    output: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    match fs::create_dir(output) {
        Ok(()) => {
            fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
            File::open(backup_root)?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_private_directory(output, required_uid)?;
    Ok(())
}

fn ensure_snapshot_parent(
    output: &Path,
    database_path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let parent = database_path
        .parent()
        .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?;
    let relative = parent
        .strip_prefix(output)
        .map_err(|_| BackupAdapterError::UnsafeSnapshotFilesystem)?;
    let mut current = output.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_private_directory(&current, required_uid)?;
    }
    Ok(())
}

fn reconcile_snapshot_pair(
    source_path: &Path,
    database_path: &Path,
    state_path: &Path,
    required_uid: u32,
) -> Result<bool, BackupAdapterError> {
    let database_exists = database_path.exists();
    let state_exists = state_path.exists();
    if database_exists != state_exists {
        remove_safe_snapshot_artifact(database_path, required_uid)?;
        remove_safe_snapshot_artifact(state_path, required_uid)?;
        remove_safe_pending(
            &database_path.with_extension("sqlite.pending"),
            required_uid,
        )?;
        remove_safe_pending(&state_pending_path(state_path), required_uid)?;
    }
    let replay = database_path.exists() && state_path.exists();
    reconcile_or_capture(source_path, database_path, required_uid)?;
    if replay {
        reconcile_pending(&state_pending_path(state_path), state_path, required_uid)?;
        validate_private_snapshot_file(state_path, required_uid)?;
    }
    Ok(replay)
}

fn remove_safe_snapshot_artifact(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata)
            if private_snapshot_metadata(&metadata, required_uid) && metadata.nlink() <= 2 =>
        {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(BackupAdapterError::UnsafeSnapshotFilesystem),
    }
}

fn reconcile_or_capture(
    source_path: &Path,
    final_path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let pending_path = final_path.with_extension("sqlite.pending");
    if final_path.exists() {
        reconcile_pending(&pending_path, final_path, required_uid)?;
        validate_private_snapshot_file(final_path, required_uid)?;
        return Ok(());
    }
    remove_safe_pending(&pending_path, required_uid)?;
    create_online_backup(source_path, &pending_path, required_uid)?;
    match fs::hard_link(&pending_path, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&pending_path)?;
    File::open(
        final_path
            .parent()
            .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?,
    )?
    .sync_all()?;
    validate_private_snapshot_file(final_path, required_uid)
}

fn create_online_backup(
    source_path: &Path,
    pending_path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    validate_source_database(source_path, required_uid)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(pending_path)?
        .sync_all()?;
    let source = Connection::open_with_flags(
        source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut destination = Connection::open_with_flags(
        pending_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    {
        let backup = Backup::new(&source, &mut destination)?;
        backup.run_to_completion(BACKUP_PAGES_PER_STEP, BACKUP_STEP_PAUSE, None)?;
    }
    let journal_mode = destination.query_row("PRAGMA journal_mode=DELETE", [], |row| {
        row.get::<_, String>(0)
    })?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    destination.close().map_err(|(_, error)| error)?;
    source.close().map_err(|(_, error)| error)?;
    fs::set_permissions(pending_path, fs::Permissions::from_mode(0o600))?;
    File::open(pending_path)?.sync_all()?;
    validate_private_snapshot_file(pending_path, required_uid)
}

fn reconcile_pending(
    pending_path: &Path,
    final_path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(pending_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(pending) => {
            let final_metadata = fs::symlink_metadata(final_path)?;
            if !private_snapshot_metadata(&pending, required_uid)
                || !private_snapshot_metadata(&final_metadata, required_uid)
                || pending.nlink() != 2
                || final_metadata.nlink() != 2
                || pending.dev() != final_metadata.dev()
                || pending.ino() != final_metadata.ino()
            {
                return Err(BackupAdapterError::InvalidSnapshot);
            }
            fs::remove_file(pending_path)?;
            Ok(())
        }
    }
}

fn remove_safe_pending(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if private_snapshot_metadata(&metadata, required_uid) => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(BackupAdapterError::UnsafeSnapshotFilesystem),
    }
}

fn private_snapshot_metadata(metadata: &fs::Metadata, required_uid: u32) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == required_uid
        && metadata.mode().trailing_zeros() >= 6
}

fn validate_private_snapshot_file(
    path: &Path,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if !private_snapshot_metadata(&metadata, required_uid)
        || metadata.nlink() != 1
        || metadata.len() == 0
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    Ok(())
}

fn validate_snapshot_inventory(
    output: &Path,
    expected_path: &str,
    expected_state_path: &str,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let expected = Path::new(expected_path);
    let mut directories = vec![output.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = path
                .strip_prefix(output)
                .map_err(|_| BackupAdapterError::UnsafeSnapshotFilesystem)?;
            if metadata.is_dir() {
                validate_private_directory(&path, required_uid)?;
                if !expected.starts_with(relative) {
                    return Err(BackupAdapterError::InvalidSnapshot);
                }
                directories.push(path);
            } else if private_snapshot_metadata(&metadata, required_uid) && metadata.nlink() == 1 {
                files.insert(
                    relative
                        .to_str()
                        .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?
                        .to_owned(),
                );
            } else {
                return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
            }
        }
    }
    if files != BTreeSet::from([expected_path.to_owned(), expected_state_path.to_owned()]) {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SqliteCaptureStateV1 {
    purpose: String,
    schema_version: u16,
    authorized_backup_spec_digest: EvidenceDigest,
    database_sha256: EvidenceDigest,
    application_schema_version: String,
    captured_at_ms: i64,
}

impl SqliteCaptureStateV1 {
    fn from_capture(
        spec: &AuthorizedPhaseSpecV1,
        captured: &CapturedBackupEvidenceV1,
    ) -> Result<Self, BackupAdapterError> {
        let backup = spec
            .backup
            .as_ref()
            .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
        let database = captured
            .objects
            .first()
            .ok_or(BackupAdapterError::InvalidSnapshot)?;
        let state = Self {
            purpose: "rdashboard.sqlite-capture-state.v1".to_owned(),
            schema_version: 1,
            authorized_backup_spec_digest: backup.spec_digest.clone(),
            database_sha256: database.sha256.clone(),
            application_schema_version: captured.application_schema_version.clone(),
            captured_at_ms: captured.captured_at_ms,
        };
        state.validate(spec, captured)?;
        Ok(state)
    }

    fn validate(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        captured: &CapturedBackupEvidenceV1,
    ) -> Result<(), BackupAdapterError> {
        let backup = spec
            .backup
            .as_ref()
            .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
        let database = captured
            .objects
            .first()
            .ok_or(BackupAdapterError::InvalidSnapshot)?;
        if self.purpose != "rdashboard.sqlite-capture-state.v1"
            || self.schema_version != 1
            || self.authorized_backup_spec_digest != backup.spec_digest
            || self.database_sha256 != database.sha256
            || self.application_schema_version != captured.application_schema_version
            || self.captured_at_ms < 0
            || self.captured_at_ms > backup.capture_deadline_ms
        {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
        Ok(())
    }
}

fn state_pending_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("jcs.pending")
}

fn publish_capture_state(
    state_path: &Path,
    state: &SqliteCaptureStateV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let pending_path = state_pending_path(state_path);
    remove_safe_pending(&pending_path, required_uid)?;
    let bytes = serde_jcs::to_vec(state)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::hard_link(&pending_path, state_path)?;
    fs::remove_file(&pending_path)?;
    File::open(
        state_path
            .parent()
            .ok_or(BackupAdapterError::UnsafeSnapshotFilesystem)?,
    )?
    .sync_all()?;
    validate_private_snapshot_file(state_path, required_uid)
}

fn read_capture_state(
    state_path: &Path,
    required_uid: u32,
) -> Result<SqliteCaptureStateV1, BackupAdapterError> {
    let bytes = read_stable_private_file(state_path, required_uid, MAX_CAPTURE_STATE_BYTES)?;
    let state: SqliteCaptureStateV1 = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&state)? != bytes {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(state)
}

#[derive(Serialize)]
struct SqliteSchemaEntryV1 {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Serialize)]
struct SqliteCheckObservationV1<'a> {
    purpose: &'static str,
    kind: BackupCheckKindV1,
    database_sha256: &'a EvidenceDigest,
    schema_digest: &'a EvidenceDigest,
    application_schema_version: &'a str,
    required_tables: &'a [String],
}

fn inspect_sqlite_snapshot(
    spec: &AuthorizedPhaseSpecV1,
    config: &InstalledSqliteBackupRuntimeV1,
    database_path: &Path,
    required_uid: u32,
) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
    validate_private_snapshot_file(database_path, required_uid)?;
    let material = hash_private_file(database_path, required_uid)?;
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
    if integrity != "ok" || foreign_key_violations != 0 {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    for table in &config.required_tables {
        let present = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0),
        )?;
        if present != 1 {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
        let query = format!("SELECT 1 FROM \"{table}\" LIMIT 1");
        let mut statement = connection.prepare(&query)?;
        let mut rows = statement.query([])?;
        let _ = rows.next()?;
    }
    let schema_digest = sqlite_schema_digest(&connection)?;
    let application_schema_version = format!("sqlite-schema-{schema_digest}");
    let backup = spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let contract = backup
        .unit
        .expected_objects
        .first()
        .ok_or(BackupAdapterError::InvalidSnapshot)?;
    let database = BackupObjectV1 {
        path: contract.path.clone(),
        kind: BackupObjectKindV1::SqliteDatabase,
        size_bytes: material.size_bytes,
        sha256: material.sha256,
        uid: material.uid,
        gid: material.gid,
        mode: material.mode,
        hard_link_count: material.hard_link_count,
    };
    let checks = backup
        .unit
        .required_checks
        .iter()
        .map(|check| {
            let observation_digest =
                EvidenceDigest::sha256(serde_jcs::to_vec(&SqliteCheckObservationV1 {
                    purpose: "rdashboard.sqlite-backup-check-observation.v1",
                    kind: check.kind,
                    database_sha256: &database.sha256,
                    schema_digest: &schema_digest,
                    application_schema_version: &application_schema_version,
                    required_tables: &config.required_tables,
                })?);
            Ok(BackupCheckEvidenceV1 {
                name: check.name.clone(),
                kind: check.kind,
                definition_digest: check.definition_digest.clone(),
                checked_object_digest: database.sha256.clone(),
                outcome: BackupCheckOutcomeV1::Passed,
                observation_digest,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    Ok(CapturedBackupEvidenceV1 {
        captured_at_ms: now_ms()?,
        application_schema_version,
        objects: vec![database],
        checks,
    })
}

fn sqlite_schema_digest(connection: &Connection) -> Result<EvidenceDigest, BackupAdapterError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema \
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name, sql",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SqliteSchemaEntryV1 {
            object_type: row.get(0)?,
            name: row.get(1)?,
            table_name: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    let schema = rows.collect::<Result<Vec<_>, _>>()?;
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(&schema)?))
}

#[derive(Debug)]
struct BackupObjectMaterialV1 {
    size_bytes: u64,
    sha256: EvidenceDigest,
    uid: u32,
    gid: u32,
    mode: u32,
    hard_link_count: u64,
}

fn hash_private_file(
    path: &Path,
    required_uid: u32,
) -> Result<BackupObjectMaterialV1, BackupAdapterError> {
    validate_private_snapshot_file(path, required_uid)?;
    let path_metadata = fs::symlink_metadata(path)?;
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
    let sha256 = EvidenceDigest::from_str(&format!("{:x}", hasher.finalize()))
        .map_err(|_| BackupAdapterError::InvalidSnapshot)?;
    Ok(BackupObjectMaterialV1 {
        size_bytes: opened.len(),
        sha256,
        uid: opened.uid(),
        gid: opened.gid(),
        mode: opened.mode() & 0o777,
        hard_link_count: opened.nlink(),
    })
}

fn now_ms() -> Result<i64, BackupAdapterError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackupAdapterError::RuntimeConfigMismatch)?
        .as_millis();
    i64::try_from(millis).map_err(|_| BackupAdapterError::RuntimeConfigMismatch)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_identity::AdapterOperationIdentityKindV1,
        backup::{
            AuthorizedBackupSpecInputV1, AuthorizedBackupSpecV1, BackupUnitSpecInputV1,
            BackupUnitSpecV1, ExpectedBackupObjectV1,
        },
        domain::RelativePolicyPath,
        phase6::{FixedAdapterProfileV1, tests::test_base_backup_phase_spec},
    };

    #[test]
    fn installed_source_roots_are_project_scoped() {
        let project = ProjectId::from_str("telegram-gateway")
            .unwrap_or_else(|error| panic!("project id: {error}"));
        let roots = installed_source_roots(&project);
        assert_eq!(
            roots,
            [
                PathBuf::from("/var/lib/docker/volumes/telegram-gateway-data/_data"),
                PathBuf::from("/var/lib/rdashboard/projects/telegram-gateway/data"),
            ]
        );
        assert!(valid_source_database_path(
            Path::new("/var/lib/docker/volumes/telegram-gateway-data/_data/gateway.db"),
            &roots,
        ));
        assert!(!valid_source_database_path(
            Path::new("/etc/shadow"),
            &roots,
        ));
        assert!(!valid_source_database_path(
            Path::new("/var/lib/docker/volumes/telegram-gateway-data/_data/../secret"),
            &roots,
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn online_backup_captures_wal_and_replays_the_published_snapshot() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let source_root = directory.path().join("source");
        let backup_root = directory.path().join("backups");
        fs::create_dir(&source_root).unwrap_or_else(|error| panic!("source root: {error}"));
        fs::create_dir(&backup_root).unwrap_or_else(|error| panic!("backup root: {error}"));
        fs::set_permissions(&source_root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("source permissions: {error}"));
        fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("backup permissions: {error}"));
        let source_path = source_root.join("gateway.db");
        let source = Connection::open(&source_path)
            .unwrap_or_else(|error| panic!("source database: {error}"));
        source
            .execute_batch(
                "PRAGMA journal_mode=WAL; \
                 CREATE TABLE projects (id TEXT PRIMARY KEY); \
                 CREATE TABLE messages (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id)); \
                 INSERT INTO projects VALUES ('sartuli'); \
                 INSERT INTO messages VALUES ('one', 'sartuli');",
            )
            .unwrap_or_else(|error| panic!("source schema: {error}"));
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("source database permissions: {error}"));
        let metadata =
            fs::metadata(&source_path).unwrap_or_else(|error| panic!("source metadata: {error}"));
        let required_uid = metadata.uid();
        let mut spec = test_base_backup_phase_spec();
        let original = spec
            .backup
            .take()
            .unwrap_or_else(|| panic!("original backup authorization"));
        let unit = BackupUnitSpecV1::new(BackupUnitSpecInputV1 {
            unit_id: "telegram-gateway-primary".to_owned(),
            consistency: BackupConsistencyMechanismV1::SqliteOnlineBackupV1,
            expected_objects: vec![ExpectedBackupObjectV1 {
                path: RelativePolicyPath::from_str("gateway.db")
                    .unwrap_or_else(|error| panic!("database path: {error}")),
                kind: BackupObjectKindV1::SqliteDatabase,
                uid: required_uid,
                gid: metadata.gid(),
                mode: 0o600,
            }],
            primary_sqlite_path: RelativePolicyPath::from_str("gateway.db")
                .unwrap_or_else(|error| panic!("primary path: {error}")),
            required_checks: original.unit.required_checks.clone(),
        })
        .unwrap_or_else(|error| panic!("backup unit: {error}"));
        let backup = AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
            attempt_id: original.attempt_id,
            project_id: original.project_id,
            installed_policy: original.installed_policy,
            installed_rimg_policy_digest: original.installed_rimg_policy_digest,
            phase_intent_digest: original.phase_intent_digest,
            backup_set_id: original.backup_set_id,
            backup_id: original.backup_id,
            snapshot_kind: original.snapshot_kind,
            capture_purpose: original.capture_purpose,
            unit,
            recipient_fingerprint: original.recipient_fingerprint,
            provider: original.provider,
            provider_credential_version: original.provider_credential_version,
            capture_deadline_ms: now_ms()
                .unwrap_or_else(|error| panic!("current time: {error}"))
                .saturating_add(60_000),
            fencing_epoch: original.fencing_epoch,
            fence_receipt_digest: original.fence_receipt_digest,
        })
        .unwrap_or_else(|error| panic!("backup authorization: {error}"));
        let backup_id = backup.backup_id;
        spec.backup = Some(backup);
        let config = InstalledSqliteBackupRuntimeV1 {
            purpose: "rdashboard.installed-sqlite-backup-runtime.v1".to_owned(),
            schema_version: 1,
            project_id: spec.project_id.clone(),
            installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
            source_database_path: source_path
                .to_str()
                .unwrap_or_else(|| panic!("source path text"))
                .to_owned(),
            required_tables: vec!["messages".to_owned(), "projects".to_owned()],
        };
        let config_path = directory.path().join("sqlite-backup-runtime.jcs");
        fs::write(
            &config_path,
            serde_jcs::to_vec(&config).unwrap_or_else(|error| panic!("config bytes: {error}")),
        )
        .unwrap_or_else(|error| panic!("config: {error}"));
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("config permissions: {error}"));
        let mut runtime = InstalledOnlineSqliteBackupRuntimeV1::new_bound(
            &config_path,
            &backup_root,
            required_uid,
            &spec,
            std::slice::from_ref(&source_root),
        )
        .unwrap_or_else(|error| panic!("runtime: {error}"));
        let identity = AdapterOperationIdentityV1 {
            purpose: "rdashboard.adapter-operation-identity.v1".to_owned(),
            schema_version: 1,
            kind: AdapterOperationIdentityKindV1::BaseBackup,
            attempt_id: spec.attempt_id,
            project_id: spec.project_id.clone(),
            authorized_phase_spec_digest: spec.spec_digest.clone(),
            sequence: 1,
            profile: FixedAdapterProfileV1::BackupCapture,
            epoch: 1,
            token: uuid::Uuid::new_v4(),
            lease_created_at_ms: 1,
            identity_digest: EvidenceDigest::sha256("test identity"),
        };
        let first = runtime
            .capture(&spec, &identity)
            .unwrap_or_else(|error| panic!("first capture: {error}"));
        source
            .execute("INSERT INTO messages VALUES ('two', 'sartuli')", [])
            .unwrap_or_else(|error| panic!("second source row: {error}"));
        let replay = runtime
            .capture(&spec, &identity)
            .unwrap_or_else(|error| panic!("replay capture: {error}"));
        assert_eq!(first.captured_at_ms, replay.captured_at_ms);
        assert_eq!(first.objects, replay.objects);
        assert_eq!(first.checks, replay.checks);
        assert_eq!(first.objects.len(), 1);
        assert_eq!(first.checks.len(), 5);
        assert!(
            first
                .application_schema_version
                .starts_with("sqlite-schema-")
        );
        let snapshot_path = backup_root.join(backup_id.to_string()).join("gateway.db");
        let snapshot = Connection::open_with_flags(
            snapshot_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
        let count = snapshot
            .query_row("SELECT count(*) FROM messages", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or_else(|error| panic!("snapshot row count: {error}"));
        assert_eq!(count, 1);
        drop(snapshot);

        fs::remove_file(
            backup_root
                .join(backup_id.to_string())
                .join(CAPTURE_STATE_FILE_NAME),
        )
        .unwrap_or_else(|error| panic!("simulate incomplete pair: {error}"));
        let recovered = runtime
            .capture(&spec, &identity)
            .unwrap_or_else(|error| panic!("recover incomplete pair: {error}"));
        assert_ne!(recovered.objects, first.objects);
        let recovered_snapshot = Connection::open_with_flags(
            backup_root.join(backup_id.to_string()).join("gateway.db"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap_or_else(|error| panic!("recovered snapshot: {error}"));
        let recovered_count = recovered_snapshot
            .query_row("SELECT count(*) FROM messages", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or_else(|error| panic!("recovered row count: {error}"));
        assert_eq!(recovered_count, 2);
    }
}
