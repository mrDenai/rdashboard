use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use uuid::Uuid;

use super::{BuildContractError, ReleaseBundleV1};
use crate::domain::{EvidenceDigest, ProjectId};

const MAX_RELEASE_BUNDLE_BYTES: u64 = 64 * 1024;
const TEMPORARY_DIGEST_BYTES: usize = 64;
const TEMPORARY_UUID_BYTES: usize = 36;
const TEMPORARY_NAME_BYTES: usize = 1 + TEMPORARY_DIGEST_BYTES + 1 + TEMPORARY_UUID_BYTES + 4;

#[derive(Clone, Debug)]
pub struct ReleaseBundleStore {
    root: PathBuf,
    expected_owner_uid: u32,
    #[cfg(unix)]
    root_lock: Arc<File>,
    operation_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug)]
pub struct ReleaseBundleReader {
    root: PathBuf,
    expected_owner_uid: u32,
    expected_reader_gid: Option<u32>,
}

impl ReleaseBundleReader {
    #[cfg(unix)]
    pub fn open_root_owned(root: impl AsRef<Path>) -> Result<Self, ReleaseBundleStoreError> {
        Self::open_for_owner(root, 0)
    }

    #[cfg(unix)]
    pub fn open_for_owner(
        root: impl AsRef<Path>,
        expected_owner_uid: u32,
    ) -> Result<Self, ReleaseBundleStoreError> {
        let root = root.as_ref();
        validate_root_directory(root, expected_owner_uid)?;
        Ok(Self {
            root: root.to_path_buf(),
            expected_owner_uid,
            expected_reader_gid: None,
        })
    }

    #[cfg(unix)]
    pub fn open_for_owner_and_group(
        root: impl AsRef<Path>,
        expected_owner_uid: u32,
        expected_reader_gid: u32,
    ) -> Result<Self, ReleaseBundleStoreError> {
        let root = root.as_ref();
        validate_reader_root_directory(root, expected_owner_uid, Some(expected_reader_gid))?;
        Ok(Self {
            root: root.to_path_buf(),
            expected_owner_uid,
            expected_reader_gid: Some(expected_reader_gid),
        })
    }

    #[cfg(unix)]
    pub fn load(
        &self,
        project_id: &ProjectId,
        bundle_digest: &EvidenceDigest,
    ) -> Result<ReleaseBundleV1, ReleaseBundleStoreError> {
        let root = File::open(&self.root)?;
        validate_locked_reader_root_directory(
            &self.root,
            &root,
            self.expected_owner_uid,
            self.expected_reader_gid,
        )?;
        let project_directory = self.root.join(project_id.as_str());
        validate_reader_project_directory(
            &project_directory,
            &self.root,
            self.expected_owner_uid,
            self.expected_reader_gid,
        )?;
        let project = File::open(&project_directory)?;
        validate_locked_reader_project_directory(
            &project_directory,
            &self.root,
            &project,
            self.expected_owner_uid,
            self.expected_reader_gid,
        )?;
        let path = project_directory.join(bundle_digest.as_str());
        let bundle = load_bundle_file(
            &path,
            &project_directory,
            project_id,
            bundle_digest,
            self.expected_owner_uid,
            self.expected_reader_gid,
            true,
        )?;
        validate_locked_reader_root_directory(
            &self.root,
            &root,
            self.expected_owner_uid,
            self.expected_reader_gid,
        )?;
        validate_locked_reader_project_directory(
            &project_directory,
            &self.root,
            &project,
            self.expected_owner_uid,
            self.expected_reader_gid,
        )?;
        Ok(bundle)
    }
}

impl ReleaseBundleStore {
    #[cfg(unix)]
    pub fn open_root_owned(root: impl AsRef<Path>) -> Result<Self, ReleaseBundleStoreError> {
        Self::open_for_owner(root, 0)
    }

    #[cfg(unix)]
    pub fn open_for_owner(
        root: impl AsRef<Path>,
        expected_owner_uid: u32,
    ) -> Result<Self, ReleaseBundleStoreError> {
        use fs2::FileExt as _;

        let root = root.as_ref();
        validate_root_directory(root, expected_owner_uid)?;
        let root_lock = File::open(root)?;
        match root_lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(ReleaseBundleStoreError::StoreAlreadyOpen);
            }
            Err(error) => return Err(error.into()),
        }
        validate_locked_root_directory(root, &root_lock, expected_owner_uid)?;
        sweep_orphan_temporary_files(root, expected_owner_uid)?;
        Ok(Self {
            root: root.to_path_buf(),
            expected_owner_uid,
            root_lock: Arc::new(root_lock),
            operation_lock: Arc::new(Mutex::new(())),
        })
    }

    #[cfg(unix)]
    pub fn persist(
        &self,
        project_id: &ProjectId,
        bundle: &ReleaseBundleV1,
    ) -> Result<PathBuf, ReleaseBundleStoreError> {
        use std::os::unix::fs::DirBuilderExt as _;

        let _guard = self.lock_operations()?;
        validate_locked_root_directory(
            &self.root,
            self.root_lock.as_ref(),
            self.expected_owner_uid,
        )?;
        bundle.verify()?;
        if bundle.project_id() != project_id {
            return Err(ReleaseBundleStoreError::BundleProjectMismatch);
        }
        let encoded = bundle.encode_canonical_json()?;
        if encoded.len() as u64 > MAX_RELEASE_BUNDLE_BYTES {
            return Err(ReleaseBundleStoreError::BundleTooLarge);
        }
        let project_directory = self.project_directory(project_id);
        match DirBuilder::new().mode(0o700).create(&project_directory) {
            Ok(()) => sync_directory(&self.root)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_project_directory(&project_directory, &self.root, self.expected_owner_uid)?;

        let final_path = project_directory.join(bundle.digest().as_str());
        reconcile_temporary_files(
            &project_directory,
            &final_path,
            project_id,
            bundle.digest(),
            self.expected_owner_uid,
        )?;
        if final_path.try_exists()? {
            let existing = load_bundle_file(
                &final_path,
                &project_directory,
                project_id,
                bundle.digest(),
                self.expected_owner_uid,
                None,
                true,
            )?;
            return if existing == *bundle {
                Ok(final_path)
            } else {
                Err(ReleaseBundleStoreError::ExistingBundleConflict)
            };
        }

        if let Err(error) =
            publish_bundle_file(&project_directory, &final_path, bundle.digest(), &encoded)
        {
            reconcile_temporary_files(
                &project_directory,
                &final_path,
                project_id,
                bundle.digest(),
                self.expected_owner_uid,
            )?;
            if final_path.try_exists()? {
                let existing = load_bundle_file(
                    &final_path,
                    &project_directory,
                    project_id,
                    bundle.digest(),
                    self.expected_owner_uid,
                    None,
                    true,
                )?;
                return if existing == *bundle {
                    Ok(final_path)
                } else {
                    Err(ReleaseBundleStoreError::ExistingBundleConflict)
                };
            }
            return Err(error.into());
        }
        let persisted = load_bundle_file(
            &final_path,
            &project_directory,
            project_id,
            bundle.digest(),
            self.expected_owner_uid,
            None,
            true,
        )?;
        if persisted != *bundle {
            return Err(ReleaseBundleStoreError::PersistedBundleMismatch);
        }
        Ok(final_path)
    }

    #[cfg(unix)]
    pub fn load(
        &self,
        project_id: &ProjectId,
        bundle_digest: &EvidenceDigest,
    ) -> Result<ReleaseBundleV1, ReleaseBundleStoreError> {
        let _guard = self.lock_operations()?;
        validate_locked_root_directory(
            &self.root,
            self.root_lock.as_ref(),
            self.expected_owner_uid,
        )?;
        let project_directory = self.project_directory(project_id);
        validate_project_directory(&project_directory, &self.root, self.expected_owner_uid)?;
        let path = project_directory.join(bundle_digest.as_str());
        reconcile_temporary_files(
            &project_directory,
            &path,
            project_id,
            bundle_digest,
            self.expected_owner_uid,
        )?;
        load_bundle_file(
            &path,
            &project_directory,
            project_id,
            bundle_digest,
            self.expected_owner_uid,
            None,
            true,
        )
    }

    fn project_directory(&self, project_id: &ProjectId) -> PathBuf {
        self.root.join(project_id.as_str())
    }

    fn lock_operations(&self) -> Result<MutexGuard<'_, ()>, ReleaseBundleStoreError> {
        self.operation_lock
            .lock()
            .map_err(|_| ReleaseBundleStoreError::OperationLockPoisoned)
    }
}

#[cfg(unix)]
fn publish_bundle_file(
    project_directory: &Path,
    final_path: &Path,
    bundle_digest: &EvidenceDigest,
    encoded: &[u8],
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let temporary_path = project_directory.join(format!(
        ".{}.{}.tmp",
        bundle_digest.as_str(),
        Uuid::new_v4()
    ));
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary_path)?;
    temporary.write_all(encoded)?;
    temporary.flush()?;
    temporary.set_permissions(fs::Permissions::from_mode(0o400))?;
    temporary.sync_all()?;
    fs::hard_link(&temporary_path, final_path)?;
    sync_directory(project_directory)?;
    drop(temporary);
    fs::remove_file(&temporary_path)?;
    sync_directory(project_directory)
}

#[cfg(unix)]
fn validate_root_directory(path: &Path, expected_uid: u32) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_locked_root_directory(
    path: &Path,
    root_lock: &File,
    expected_uid: u32,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    validate_root_directory(path, expected_uid)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let locked_metadata = root_lock.metadata()?;
    if !locked_metadata.is_dir()
        || locked_metadata.uid() != expected_uid
        || locked_metadata.permissions().mode() & 0o022 != 0
        || FileIdentity::from_metadata(&path_metadata)
            != FileIdentity::from_metadata(&locked_metadata)
    {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_reader_root_directory(
    path: &Path,
    owner_uid: u32,
    reader_group_gid: Option<u32>,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Some(reader_gid) = reader_group_gid else {
        return validate_root_directory(path, owner_uid);
    };
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o777 != 0o750
    {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_locked_reader_root_directory(
    path: &Path,
    root: &File,
    expected_uid: u32,
    expected_reader_gid: Option<u32>,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    validate_reader_root_directory(path, expected_uid, expected_reader_gid)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let opened = root.metadata()?;
    let expected_mode = if expected_reader_gid.is_some() {
        0o750
    } else {
        opened.permissions().mode() & 0o777
    };
    if !opened.is_dir()
        || opened.uid() != expected_uid
        || opened.permissions().mode() & 0o777 != expected_mode
        || expected_reader_gid.is_some_and(|gid| opened.gid() != gid)
        || FileIdentity::from_metadata(&path_metadata) != FileIdentity::from_metadata(&opened)
    {
        return Err(ReleaseBundleStoreError::UntrustedRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn sweep_orphan_temporary_files(
    root: &Path,
    expected_uid: u32,
) -> Result<(), ReleaseBundleStoreError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let project_name = entry
            .file_name()
            .into_string()
            .map_err(|_| ReleaseBundleStoreError::UntrustedStoreEntry)?;
        let project_id = ProjectId::from_str(&project_name)
            .map_err(|_| ReleaseBundleStoreError::UntrustedStoreEntry)?;
        let project_directory = entry.path();
        validate_project_directory(&project_directory, root, expected_uid)?;

        let mut bundle_digests = std::collections::BTreeSet::new();
        for bundle_entry in fs::read_dir(&project_directory)? {
            let bundle_entry = bundle_entry?;
            if let Some(bundle_digest) = temporary_bundle_digest(&bundle_entry.file_name())? {
                bundle_digests.insert(bundle_digest);
            }
        }
        for bundle_digest in bundle_digests {
            let final_path = project_directory.join(bundle_digest.as_str());
            reconcile_temporary_files(
                &project_directory,
                &final_path,
                &project_id,
                &bundle_digest,
                expected_uid,
            )?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_project_directory(
    path: &Path,
    root: &Path,
    expected_uid: u32,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if path.parent() != Some(root) || fs::canonicalize(path)? != path {
        return Err(ReleaseBundleStoreError::UntrustedProjectDirectory);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ReleaseBundleStoreError::UntrustedProjectDirectory);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_reader_project_directory(
    path: &Path,
    root: &Path,
    owner_uid: u32,
    reader_group_gid: Option<u32>,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Some(reader_gid) = reader_group_gid else {
        return validate_project_directory(path, root, owner_uid);
    };
    if path.parent() != Some(root) || fs::canonicalize(path)? != path {
        return Err(ReleaseBundleStoreError::UntrustedProjectDirectory);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o777 != 0o750
    {
        return Err(ReleaseBundleStoreError::UntrustedProjectDirectory);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_locked_reader_project_directory(
    path: &Path,
    root: &Path,
    directory: &File,
    expected_uid: u32,
    expected_reader_gid: Option<u32>,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    validate_reader_project_directory(path, root, expected_uid, expected_reader_gid)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    let expected_mode = if expected_reader_gid.is_some() {
        0o750
    } else {
        0o700
    };
    if !opened.is_dir()
        || opened.uid() != expected_uid
        || opened.permissions().mode() & 0o777 != expected_mode
        || expected_reader_gid.is_some_and(|gid| opened.gid() != gid)
        || FileIdentity::from_metadata(&path_metadata) != FileIdentity::from_metadata(&opened)
    {
        return Err(ReleaseBundleStoreError::UntrustedProjectDirectory);
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(unix)]
fn load_bundle_file(
    path: &Path,
    project_directory: &Path,
    project_id: &ProjectId,
    bundle_digest: &EvidenceDigest,
    expected_uid: u32,
    expected_reader_gid: Option<u32>,
    require_single_link: bool,
) -> Result<ReleaseBundleV1, ReleaseBundleStoreError> {
    load_bundle_file_with_identity(
        path,
        project_directory,
        project_id,
        bundle_digest,
        expected_uid,
        expected_reader_gid,
        require_single_link,
    )
    .map(|(bundle, _identity)| bundle)
}

#[cfg(unix)]
fn load_bundle_file_with_identity(
    path: &Path,
    project_directory: &Path,
    project_id: &ProjectId,
    bundle_digest: &EvidenceDigest,
    expected_uid: u32,
    expected_reader_gid: Option<u32>,
    require_single_link: bool,
) -> Result<(ReleaseBundleV1, FileIdentity), ReleaseBundleStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let before = validate_bundle_file(
        path,
        project_directory,
        expected_uid,
        expected_reader_gid,
        require_single_link,
    )?;
    let before_identity = FileIdentity::from_metadata(&before);
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if FileIdentity::from_metadata(&opened) != before_identity
        || opened.len() != before.len()
        || opened.uid() != expected_uid
        || expected_reader_gid.is_some_and(|gid| opened.gid() != gid)
    {
        return Err(ReleaseBundleStoreError::ConcurrentFilesystemChange);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| ReleaseBundleStoreError::BundleTooLarge)?,
    );
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RELEASE_BUNDLE_BYTES {
        return Err(ReleaseBundleStoreError::BundleTooLarge);
    }
    let after = validate_bundle_file(
        path,
        project_directory,
        expected_uid,
        expected_reader_gid,
        require_single_link,
    )?;
    let after_identity = FileIdentity::from_metadata(&after);
    if before_identity != after_identity || before.len() != after.len() {
        return Err(ReleaseBundleStoreError::ConcurrentFilesystemChange);
    }
    let bundle = ReleaseBundleV1::decode_canonical_json(&bytes)?;
    if bundle.project_id() != project_id {
        return Err(ReleaseBundleStoreError::BundleProjectMismatch);
    }
    if bundle.digest() != bundle_digest {
        return Err(ReleaseBundleStoreError::PersistedBundleMismatch);
    }
    Ok((bundle, after_identity))
}

#[cfg(unix)]
fn validate_bundle_file(
    path: &Path,
    project_directory: &Path,
    expected_uid: u32,
    expected_reader_gid: Option<u32>,
    require_single_link: bool,
) -> Result<fs::Metadata, ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let expected_mode = if expected_reader_gid.is_some() {
        0o440
    } else {
        0o400
    };
    if path.parent() != Some(project_directory) {
        return Err(ReleaseBundleStoreError::UntrustedBundleFile);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != expected_mode
        || expected_reader_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.nlink() == 0
        || require_single_link && metadata.nlink() != 1
        || metadata.len() > MAX_RELEASE_BUNDLE_BYTES
    {
        return Err(ReleaseBundleStoreError::UntrustedBundleFile);
    }
    Ok(metadata)
}

#[cfg(unix)]
fn reconcile_temporary_files(
    project_directory: &Path,
    final_path: &Path,
    project_id: &ProjectId,
    bundle_digest: &EvidenceDigest,
    expected_uid: u32,
) -> Result<(), ReleaseBundleStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let temporary_paths = matching_temporary_paths(project_directory, bundle_digest)?;
    let final_metadata = match fs::symlink_metadata(final_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut changed = false;
    if final_metadata.is_some() {
        let (_bundle, final_identity) = load_bundle_file_with_identity(
            final_path,
            project_directory,
            project_id,
            bundle_digest,
            expected_uid,
            None,
            false,
        )?;
        for temporary_path in temporary_paths {
            let temporary_metadata =
                validate_temporary_file(&temporary_path, project_directory, expected_uid)?;
            let temporary_identity = FileIdentity::from_metadata(&temporary_metadata);
            if temporary_identity != final_identity && temporary_metadata.nlink() != 1 {
                return Err(ReleaseBundleStoreError::UntrustedTemporaryFile);
            }
            changed |= remove_file_with_identity(&temporary_path, temporary_identity)?;
        }
        if changed {
            sync_directory(project_directory)?;
        }
        let reconciled =
            validate_bundle_file(final_path, project_directory, expected_uid, None, true)?;
        if FileIdentity::from_metadata(&reconciled) != final_identity {
            return Err(ReleaseBundleStoreError::ConcurrentFilesystemChange);
        }
    } else {
        for temporary_path in temporary_paths {
            let temporary_metadata =
                validate_temporary_file(&temporary_path, project_directory, expected_uid)?;
            if temporary_metadata.nlink() != 1 {
                return Err(ReleaseBundleStoreError::UntrustedTemporaryFile);
            }
            changed |= remove_file_with_identity(
                &temporary_path,
                FileIdentity::from_metadata(&temporary_metadata),
            )?;
        }
        if changed {
            sync_directory(project_directory)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn matching_temporary_paths(
    project_directory: &Path,
    bundle_digest: &EvidenceDigest,
) -> Result<Vec<PathBuf>, ReleaseBundleStoreError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(project_directory)? {
        let entry = entry?;
        if is_temporary_bundle_name(&entry.file_name(), bundle_digest)? {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

#[cfg(unix)]
fn is_temporary_bundle_name(
    name: &OsStr,
    bundle_digest: &EvidenceDigest,
) -> Result<bool, ReleaseBundleStoreError> {
    Ok(temporary_bundle_digest(name)?.as_ref() == Some(bundle_digest))
}

#[cfg(unix)]
fn temporary_bundle_digest(
    name: &OsStr,
) -> Result<Option<EvidenceDigest>, ReleaseBundleStoreError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = name.as_bytes();
    if !bytes.starts_with(b".") && !bytes.ends_with(b".tmp") {
        return Ok(None);
    }
    if bytes.len() != TEMPORARY_NAME_BYTES
        || bytes.first() != Some(&b'.')
        || bytes.get(1 + TEMPORARY_DIGEST_BYTES) != Some(&b'.')
        || !bytes.ends_with(b".tmp")
    {
        return Err(ReleaseBundleStoreError::UntrustedTemporaryFile);
    }
    let digest = std::str::from_utf8(&bytes[1..=TEMPORARY_DIGEST_BYTES])
        .map_err(|_| ReleaseBundleStoreError::UntrustedTemporaryFile)?;
    let digest = EvidenceDigest::from_str(digest)
        .map_err(|_| ReleaseBundleStoreError::UntrustedTemporaryFile)?;
    let uuid_bytes = &bytes[1 + TEMPORARY_DIGEST_BYTES + 1..bytes.len() - b".tmp".len()];
    let uuid = std::str::from_utf8(uuid_bytes)
        .map_err(|_| ReleaseBundleStoreError::UntrustedTemporaryFile)?;
    Uuid::parse_str(uuid).map_err(|_| ReleaseBundleStoreError::UntrustedTemporaryFile)?;
    Ok(Some(digest))
}

#[cfg(unix)]
fn validate_temporary_file(
    path: &Path,
    project_directory: &Path,
    expected_uid: u32,
) -> Result<fs::Metadata, ReleaseBundleStoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if path.parent() != Some(project_directory) {
        return Err(ReleaseBundleStoreError::UntrustedTemporaryFile);
    }
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_uid
        || mode & 0o177 != 0
        || metadata.nlink() == 0
        || metadata.len() > MAX_RELEASE_BUNDLE_BYTES
    {
        return Err(ReleaseBundleStoreError::UntrustedTemporaryFile);
    }
    Ok(metadata)
}

#[cfg(unix)]
fn remove_file_with_identity(
    path: &Path,
    expected_identity: FileIdentity,
) -> Result<bool, ReleaseBundleStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if FileIdentity::from_metadata(&metadata) != expected_identity {
        return Err(ReleaseBundleStoreError::ConcurrentFilesystemChange);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseBundleStoreError {
    #[error("release bundle filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Contract(#[from] BuildContractError),
    #[error("release bundle root is not canonical, owner-trusted, or write-protected")]
    UntrustedRoot,
    #[error("another release bundle store instance already owns the root lock")]
    StoreAlreadyOpen,
    #[error("release bundle root contains an untrusted namespace entry")]
    UntrustedStoreEntry,
    #[error("release bundle project directory is not canonical and owner-only")]
    UntrustedProjectDirectory,
    #[error("release bundle file is not a single-link owner-read-only regular file")]
    UntrustedBundleFile,
    #[error("release bundle temporary file is not an owner-only regular publish artifact")]
    UntrustedTemporaryFile,
    #[error("release bundle exceeds its durable size cap")]
    BundleTooLarge,
    #[error("release bundle project does not match the requested project namespace")]
    BundleProjectMismatch,
    #[error("an immutable release bundle path already contains different evidence")]
    ExistingBundleConflict,
    #[error("persisted release bundle does not match its requested digest or bytes")]
    PersistedBundleMismatch,
    #[error("release bundle filesystem identity changed during validation")]
    ConcurrentFilesystemChange,
    #[error("release bundle operation lock is poisoned")]
    OperationLockPoisoned,
}
