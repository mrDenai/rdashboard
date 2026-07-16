use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    build::{OciDigest, ReleaseBundleV1},
    domain::{EvidenceDigest, GitCommitId, ProjectId},
};

pub const BUILD_OCI_ARCHIVE_ROOT: &str = "/var/lib/rdashboard-build/oci-archives";
pub const ROOT_OCI_ARCHIVE_ROOT: &str = "/var/lib/rdashboard-executor/oci-archives";

const OCI_ARCHIVE_MANIFEST_SCHEMA_VERSION: u16 = 1;
const MAX_OCI_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OciArchiveManifestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub source_head: GitCommitId,
    pub release_bundle_digest: EvidenceDigest,
    pub image_registry_digest: OciDigest,
    pub local_image_id: OciDigest,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    pub published_at_ms: i64,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct OciArchiveManifestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    source_head: &'a GitCommitId,
    release_bundle_digest: &'a EvidenceDigest,
    image_registry_digest: &'a OciDigest,
    local_image_id: &'a OciDigest,
    archive_digest: &'a EvidenceDigest,
    archive_bytes: u64,
    published_at_ms: i64,
}

impl OciArchiveManifestV1 {
    fn new(
        bundle: &ReleaseBundleV1,
        archive_digest: EvidenceDigest,
        archive_bytes: u64,
        published_at_ms: i64,
    ) -> Result<Self, OciArchiveError> {
        let mut manifest = Self {
            purpose: "rdashboard.oci-archive-manifest.v1".to_owned(),
            schema_version: OCI_ARCHIVE_MANIFEST_SCHEMA_VERSION,
            project_id: bundle.project_id().clone(),
            source_head: bundle.deployment_plan().source_head().clone(),
            release_bundle_digest: bundle.digest().clone(),
            image_registry_digest: bundle.image_registry_digest().clone(),
            local_image_id: bundle.local_image_id().clone(),
            archive_digest,
            archive_bytes,
            published_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        manifest.document_digest = manifest.calculate_digest()?;
        manifest.validate(bundle)?;
        Ok(manifest)
    }

    fn validate(&self, bundle: &ReleaseBundleV1) -> Result<(), OciArchiveError> {
        bundle.verify()?;
        if self.purpose != "rdashboard.oci-archive-manifest.v1"
            || self.schema_version != OCI_ARCHIVE_MANIFEST_SCHEMA_VERSION
            || self.project_id != *bundle.project_id()
            || self.source_head != *bundle.deployment_plan().source_head()
            || self.release_bundle_digest != *bundle.digest()
            || self.image_registry_digest != *bundle.image_registry_digest()
            || self.local_image_id != *bundle.local_image_id()
            || self.archive_digest != *bundle.image_archive_digest()
            || self.archive_bytes == 0
            || self.archive_bytes > MAX_OCI_ARCHIVE_BYTES
            || self.published_at_ms < 0
            || self.document_digest != self.calculate_digest()?
        {
            return Err(OciArchiveError::ManifestBinding);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, OciArchiveError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &OciArchiveManifestPayload {
                purpose: "rdashboard.oci-archive-manifest.v1",
                schema_version: OCI_ARCHIVE_MANIFEST_SCHEMA_VERSION,
                project_id: &self.project_id,
                source_head: &self.source_head,
                release_bundle_digest: &self.release_bundle_digest,
                image_registry_digest: &self.image_registry_digest,
                local_image_id: &self.local_image_id,
                archive_digest: &self.archive_digest,
                archive_bytes: self.archive_bytes,
                published_at_ms: self.published_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct OciArchivePublisherV1 {
    root: PathBuf,
    owner_uid: u32,
    reader_gid: u32,
    root_lock: Arc<File>,
    operation_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug)]
pub struct OciArchiveReaderV1 {
    root: PathBuf,
    owner_uid: u32,
    reader_gid: u32,
}

#[derive(Debug)]
pub struct OpenedOciArchiveV1 {
    pub manifest: OciArchiveManifestV1,
    pub archive: File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPromotedOciArchiveV1 {
    pub path: PathBuf,
    device: u64,
    inode: u64,
    bytes: u64,
}

impl OciArchivePublisherV1 {
    pub fn open(
        root: impl AsRef<Path>,
        owner_uid: u32,
        reader_gid: u32,
    ) -> Result<Self, OciArchiveError> {
        use fs2::FileExt as _;

        let root = root.as_ref();
        validate_shared_directory(root, owner_uid, reader_gid)?;
        let root_lock = File::open(root)?;
        match root_lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(OciArchiveError::StoreAlreadyOpen);
            }
            Err(error) => return Err(error.into()),
        }
        revalidate_shared_directory(root, &root_lock, owner_uid, reader_gid)?;
        Ok(Self {
            root: root.to_path_buf(),
            owner_uid,
            reader_gid,
            root_lock: Arc::new(root_lock),
            operation_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn publish(
        &self,
        bundle: &ReleaseBundleV1,
        archive: &File,
        published_at_ms: i64,
    ) -> Result<PathBuf, OciArchiveError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| OciArchiveError::OperationLockPoisoned)?;
        bundle.verify()?;
        let project_root = self.root.join(bundle.project_id().as_str());
        revalidate_shared_directory(
            &self.root,
            self.root_lock.as_ref(),
            self.owner_uid,
            self.reader_gid,
        )?;
        let project = open_shared_directory(&project_root, self.owner_uid, self.reader_gid)?;
        reconcile_shared_temporaries(
            &project_root,
            &project,
            self.owner_uid,
            self.reader_gid,
            bundle.digest(),
        )?;
        let metadata = archive.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_OCI_ARCHIVE_BYTES {
            return Err(OciArchiveError::ArchiveInvalid);
        }
        let archive_digest = hash_file(archive, metadata.len())?;
        if archive_digest != *bundle.image_archive_digest() {
            return Err(OciArchiveError::ArchiveBinding);
        }
        let manifest =
            OciArchiveManifestV1::new(bundle, archive_digest, metadata.len(), published_at_ms)?;
        let stem = bundle.digest().as_str();
        let archive_path = project_root.join(format!("{stem}.oci.tar"));
        let manifest_path = project_root.join(format!("{stem}.manifest.jcs"));

        publish_shared_archive(
            &project_root,
            &archive_path,
            archive,
            &manifest,
            self.owner_uid,
            self.reader_gid,
        )?;
        publish_shared_manifest(
            &project_root,
            &manifest_path,
            &manifest,
            self.owner_uid,
            self.reader_gid,
        )?;
        revalidate_shared_directory(
            &self.root,
            self.root_lock.as_ref(),
            self.owner_uid,
            self.reader_gid,
        )?;
        revalidate_shared_directory(&project_root, &project, self.owner_uid, self.reader_gid)?;
        Ok(archive_path)
    }
}

impl OciArchiveReaderV1 {
    pub fn open(
        root: impl AsRef<Path>,
        owner_uid: u32,
        reader_gid: u32,
    ) -> Result<Self, OciArchiveError> {
        validate_shared_directory(root.as_ref(), owner_uid, reader_gid)?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            owner_uid,
            reader_gid,
        })
    }

    pub fn load(&self, bundle: &ReleaseBundleV1) -> Result<OpenedOciArchiveV1, OciArchiveError> {
        let project_root = self.root.join(bundle.project_id().as_str());
        let root = open_shared_directory(&self.root, self.owner_uid, self.reader_gid)?;
        let project = open_shared_directory(&project_root, self.owner_uid, self.reader_gid)?;
        let stem = bundle.digest().as_str();
        let manifest_path = project_root.join(format!("{stem}.manifest.jcs"));
        let archive_path = project_root.join(format!("{stem}.oci.tar"));
        let manifest_bytes = read_shared_file(
            &manifest_path,
            self.owner_uid,
            self.reader_gid,
            MAX_MANIFEST_BYTES,
        )?;
        let manifest: OciArchiveManifestV1 = serde_json::from_slice(&manifest_bytes)?;
        if serde_jcs::to_vec(&manifest)? != manifest_bytes {
            return Err(OciArchiveError::ManifestNonCanonical);
        }
        manifest.validate(bundle)?;
        let archive = open_shared_file(
            &archive_path,
            self.owner_uid,
            self.reader_gid,
            manifest.archive_bytes,
        )?;
        if hash_file(&archive, manifest.archive_bytes)? != manifest.archive_digest {
            return Err(OciArchiveError::ArchiveBinding);
        }
        revalidate_shared_directory(&self.root, &root, self.owner_uid, self.reader_gid)?;
        revalidate_shared_directory(&project_root, &project, self.owner_uid, self.reader_gid)?;
        Ok(OpenedOciArchiveV1 { manifest, archive })
    }
}

pub fn promote_oci_archive_private(
    root: impl AsRef<Path>,
    required_uid: u32,
    bundle: &ReleaseBundleV1,
    opened: &OpenedOciArchiveV1,
) -> Result<PathBuf, OciArchiveError> {
    opened.manifest.validate(bundle)?;
    let root = root.as_ref();
    let project_root = root.join(bundle.project_id().as_str());
    let root_handle = open_private_directory(root, required_uid)?;
    let project_handle = open_private_directory(&project_root, required_uid)?;
    reconcile_private_temporaries(&project_root, &project_handle, required_uid)?;
    let final_path = project_root.join(format!("{}.oci.tar", bundle.digest().as_str()));
    if final_path.try_exists()? {
        let existing =
            open_private_archive(&final_path, required_uid, opened.manifest.archive_bytes)?;
        if hash_file(&existing, opened.manifest.archive_bytes)? != opened.manifest.archive_digest {
            return Err(OciArchiveError::ArchiveConflict);
        }
        return Ok(final_path);
    }
    let temporary = project_root.join(format!(".{}.{}.tmp", bundle.digest(), Uuid::new_v4()));
    let result = (|| {
        let mut target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        copy_file_exact(&opened.archive, &mut target, opened.manifest.archive_bytes)?;
        target.set_permissions(fs::Permissions::from_mode(0o400))?;
        target.sync_all()?;
        if hash_file(&target, opened.manifest.archive_bytes)? != opened.manifest.archive_digest {
            return Err(OciArchiveError::ArchiveBinding);
        }
        revalidate_private_directory(root, &root_handle, required_uid)?;
        revalidate_private_directory(&project_root, &project_handle, required_uid)?;
        fs::hard_link(&temporary, &final_path)?;
        fs::remove_file(&temporary)?;
        project_handle.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    let promoted = open_private_archive(&final_path, required_uid, opened.manifest.archive_bytes)?;
    if hash_file(&promoted, opened.manifest.archive_bytes)? != opened.manifest.archive_digest {
        return Err(OciArchiveError::ArchiveBinding);
    }
    Ok(final_path)
}

pub fn verify_promoted_oci_archive(
    root: impl AsRef<Path>,
    required_uid: u32,
    bundle: &ReleaseBundleV1,
) -> Result<VerifiedPromotedOciArchiveV1, OciArchiveError> {
    bundle.verify()?;
    let root = root.as_ref();
    let project_root = root.join(bundle.project_id().as_str());
    let root_handle = open_private_directory(root, required_uid)?;
    let project_handle = open_private_directory(&project_root, required_uid)?;
    let path = project_root.join(format!("{}.oci.tar", bundle.digest().as_str()));
    let named = fs::symlink_metadata(&path)?;
    let archive = open_private_archive(&path, required_uid, named.len())?;
    let metadata = archive.metadata()?;
    if hash_file(&archive, metadata.len())? != *bundle.image_archive_digest() {
        return Err(OciArchiveError::ArchiveBinding);
    }
    revalidate_private_directory(root, &root_handle, required_uid)?;
    revalidate_private_directory(&project_root, &project_handle, required_uid)?;
    Ok(VerifiedPromotedOciArchiveV1 {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
    })
}

fn publish_shared_archive(
    project_root: &Path,
    final_path: &Path,
    source: &File,
    manifest: &OciArchiveManifestV1,
    owner_uid: u32,
    reader_gid: u32,
) -> Result<(), OciArchiveError> {
    if final_path.try_exists()? {
        let existing = open_shared_file(final_path, owner_uid, reader_gid, manifest.archive_bytes)?;
        return if hash_file(&existing, manifest.archive_bytes)? == manifest.archive_digest {
            Ok(())
        } else {
            Err(OciArchiveError::ArchiveConflict)
        };
    }
    let temporary = project_root.join(format!(
        ".{}.{}.oci.tmp",
        manifest.release_bundle_digest,
        Uuid::new_v4()
    ));
    let result = (|| {
        let mut target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&temporary)?;
        copy_file_exact(source, &mut target, manifest.archive_bytes)?;
        target.set_permissions(fs::Permissions::from_mode(0o440))?;
        target.sync_all()?;
        validate_created_shared_file(&target, owner_uid, reader_gid, manifest.archive_bytes)?;
        fs::hard_link(&temporary, final_path)?;
        fs::remove_file(&temporary)?;
        File::open(project_root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn publish_shared_manifest(
    project_root: &Path,
    final_path: &Path,
    manifest: &OciArchiveManifestV1,
    owner_uid: u32,
    reader_gid: u32,
) -> Result<(), OciArchiveError> {
    let bytes = serde_jcs::to_vec(manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(OciArchiveError::ManifestOversized);
    }
    if final_path.try_exists()? {
        return if read_shared_file(final_path, owner_uid, reader_gid, MAX_MANIFEST_BYTES)? == bytes
        {
            Ok(())
        } else {
            Err(OciArchiveError::ManifestConflict)
        };
    }
    let temporary = project_root.join(format!(
        ".{}.{}.manifest.tmp",
        manifest.release_bundle_digest,
        Uuid::new_v4()
    ));
    let result = (|| {
        let mut target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&temporary)?;
        target.write_all(&bytes)?;
        target.set_permissions(fs::Permissions::from_mode(0o440))?;
        target.sync_all()?;
        validate_created_shared_file(&target, owner_uid, reader_gid, bytes.len() as u64)?;
        fs::hard_link(&temporary, final_path)?;
        fs::remove_file(&temporary)?;
        File::open(project_root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_file_exact(source: &File, target: &mut File, length: u64) -> Result<(), OciArchiveError> {
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    while offset < length {
        let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
            .map_err(|_| OciArchiveError::ArchiveInvalid)?;
        let read = source.read_at(&mut buffer[..remaining], offset)?;
        if read == 0 {
            return Err(OciArchiveError::ArchiveChanged);
        }
        target.write_all(&buffer[..read])?;
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| OciArchiveError::ArchiveInvalid)?)
            .ok_or(OciArchiveError::ArchiveInvalid)?;
    }
    Ok(())
}

fn hash_file(file: &File, length: u64) -> Result<EvidenceDigest, OciArchiveError> {
    let before = file.metadata()?;
    if before.len() != length || length == 0 || length > MAX_OCI_ARCHIVE_BYTES {
        return Err(OciArchiveError::ArchiveChanged);
    }
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    while offset < length {
        let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
            .map_err(|_| OciArchiveError::ArchiveInvalid)?;
        let read = file.read_at(&mut buffer[..remaining], offset)?;
        if read == 0 {
            return Err(OciArchiveError::ArchiveChanged);
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| OciArchiveError::ArchiveInvalid)?)
            .ok_or(OciArchiveError::ArchiveInvalid)?;
    }
    let after = file.metadata()?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err(OciArchiveError::ArchiveChanged);
    }
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").map_err(|_| OciArchiveError::ArchiveInvalid)?;
    }
    encoded.parse().map_err(|_| OciArchiveError::ArchiveInvalid)
}

fn validate_shared_directory(path: &Path, uid: u32, gid: u32) -> Result<(), OciArchiveError> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(OciArchiveError::UnsafeStore);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o2750
    {
        return Err(OciArchiveError::UnsafeStore);
    }
    Ok(())
}

fn open_shared_directory(path: &Path, uid: u32, gid: u32) -> Result<File, OciArchiveError> {
    validate_shared_directory(path, uid, gid)?;
    let file = File::open(path)?;
    revalidate_shared_directory(path, &file, uid, gid)?;
    Ok(file)
}

fn revalidate_shared_directory(
    path: &Path,
    opened: &File,
    uid: u32,
    gid: u32,
) -> Result<(), OciArchiveError> {
    validate_shared_directory(path, uid, gid)?;
    let named = fs::symlink_metadata(path)?;
    let metadata = opened.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o2750
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
    {
        return Err(OciArchiveError::UnsafeStore);
    }
    Ok(())
}

fn open_shared_file(path: &Path, uid: u32, gid: u32, length: u64) -> Result<File, OciArchiveError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != uid
        || before.gid() != gid
        || before.mode() & 0o777 != 0o440
        || before.nlink() != 1
        || before.len() != length
    {
        return Err(OciArchiveError::UnsafeStore);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != uid
        || opened.gid() != gid
        || opened.mode() & 0o777 != 0o440
        || opened.nlink() != 1
        || opened.len() != length
    {
        return Err(OciArchiveError::UnsafeStore);
    }
    Ok(file)
}

fn read_shared_file(
    path: &Path,
    uid: u32,
    gid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, OciArchiveError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(OciArchiveError::UnsafeStore);
    }
    let mut file = open_shared_file(path, uid, gid, metadata.len())?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| OciArchiveError::UnsafeStore)?,
    );
    file.read_to_end(&mut bytes)?;
    if file.metadata()?.len() != metadata.len() {
        return Err(OciArchiveError::ArchiveChanged);
    }
    Ok(bytes)
}

fn validate_created_shared_file(
    file: &File,
    uid: u32,
    gid: u32,
    length: u64,
) -> Result<(), OciArchiveError> {
    let metadata = file.metadata()?;
    if metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o440
        || metadata.nlink() != 1
        || metadata.len() != length
    {
        return Err(OciArchiveError::UnsafeStore);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SharedTemporaryKind {
    Archive,
    Manifest,
}

fn reconcile_shared_temporaries(
    project_root: &Path,
    project: &File,
    uid: u32,
    gid: u32,
    bundle_digest: &EvidenceDigest,
) -> Result<(), OciArchiveError> {
    let mut changed = false;
    let mut entries = 0_usize;
    for entry in fs::read_dir(project_root)? {
        let entry = entry?;
        entries = entries.checked_add(1).ok_or(OciArchiveError::UnsafeStore)?;
        if entries > 10_000 {
            return Err(OciArchiveError::UnsafeStore);
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some((digest, kind)) = shared_temporary(&name) else {
            continue;
        };
        if digest != bundle_digest.as_str() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != uid
            || metadata.gid() != gid
            || !matches!(metadata.mode() & 0o777, 0o440 | 0o640)
            || !matches!(metadata.nlink(), 1 | 2)
        {
            return Err(OciArchiveError::UnsafeStore);
        }
        if metadata.nlink() == 2 {
            let suffix = match kind {
                SharedTemporaryKind::Archive => "oci.tar",
                SharedTemporaryKind::Manifest => "manifest.jcs",
            };
            let final_path = project_root.join(format!("{digest}.{suffix}"));
            let final_metadata = fs::symlink_metadata(final_path)?;
            if metadata.mode() & 0o777 != 0o440
                || final_metadata.file_type().is_symlink()
                || !final_metadata.is_file()
                || final_metadata.uid() != uid
                || final_metadata.gid() != gid
                || final_metadata.mode() & 0o777 != 0o440
                || final_metadata.nlink() != 2
                || final_metadata.dev() != metadata.dev()
                || final_metadata.ino() != metadata.ino()
                || final_metadata.len() != metadata.len()
            {
                return Err(OciArchiveError::UnsafeStore);
            }
        }
        fs::remove_file(entry.path())?;
        changed = true;
    }
    revalidate_shared_directory(project_root, project, uid, gid)?;
    if changed {
        project.sync_all()?;
    }
    Ok(())
}

fn shared_temporary(name: &str) -> Option<(&str, SharedTemporaryKind)> {
    let body = name.strip_prefix('.')?;
    let (body, kind) = if let Some(body) = body.strip_suffix(".oci.tmp") {
        (body, SharedTemporaryKind::Archive)
    } else {
        (
            body.strip_suffix(".manifest.tmp")?,
            SharedTemporaryKind::Manifest,
        )
    };
    let (digest, identifier) = body.rsplit_once('.')?;
    let parsed = Uuid::parse_str(identifier).ok()?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && identifier == parsed.to_string())
    .then_some((digest, kind))
}

fn open_private_directory(path: &Path, uid: u32) -> Result<File, OciArchiveError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || fs::canonicalize(path)? != path
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(OciArchiveError::UnsafePrivateStore);
    }
    let file = File::open(path)?;
    revalidate_private_directory(path, &file, uid)?;
    Ok(file)
}

fn revalidate_private_directory(
    path: &Path,
    opened: &File,
    uid: u32,
) -> Result<(), OciArchiveError> {
    let named = fs::symlink_metadata(path)?;
    let metadata = opened.metadata()?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !metadata.is_dir()
        || named.uid() != uid
        || metadata.uid() != uid
        || named.mode() & 0o077 != 0
        || metadata.mode() & 0o077 != 0
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
    {
        return Err(OciArchiveError::UnsafePrivateStore);
    }
    Ok(())
}

fn open_private_archive(path: &Path, uid: u32, length: u64) -> Result<File, OciArchiveError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() != length
    {
        return Err(OciArchiveError::UnsafePrivateStore);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != uid
        || opened.mode() & 0o077 != 0
        || opened.nlink() != 1
        || opened.len() != length
    {
        return Err(OciArchiveError::UnsafePrivateStore);
    }
    Ok(file)
}

fn reconcile_private_temporaries(
    project_root: &Path,
    project: &File,
    uid: u32,
) -> Result<(), OciArchiveError> {
    let mut changed = false;
    let mut entries = 0_usize;
    for entry in fs::read_dir(project_root)? {
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or(OciArchiveError::UnsafePrivateStore)?;
        if entries > 10_000 {
            return Err(OciArchiveError::UnsafePrivateStore);
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(digest) = private_temporary_digest(&name) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != uid
            || !matches!(metadata.mode() & 0o777, 0o400 | 0o600)
            || !matches!(metadata.nlink(), 1 | 2)
        {
            return Err(OciArchiveError::UnsafePrivateStore);
        }
        if metadata.nlink() == 2 {
            let final_path = project_root.join(format!("{digest}.oci.tar"));
            let final_metadata = fs::symlink_metadata(final_path)?;
            if metadata.mode() & 0o777 != 0o400
                || final_metadata.file_type().is_symlink()
                || !final_metadata.is_file()
                || final_metadata.uid() != uid
                || final_metadata.mode() & 0o777 != 0o400
                || final_metadata.nlink() != 2
                || final_metadata.dev() != metadata.dev()
                || final_metadata.ino() != metadata.ino()
                || final_metadata.len() != metadata.len()
            {
                return Err(OciArchiveError::UnsafePrivateStore);
            }
        }
        fs::remove_file(entry.path())?;
        changed = true;
    }
    revalidate_private_directory(project_root, project, uid)?;
    if changed {
        project.sync_all()?;
    }
    Ok(())
}

fn private_temporary_digest(name: &str) -> Option<&str> {
    let body = name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (digest, identifier) = body.rsplit_once('.')?;
    let parsed = Uuid::parse_str(identifier).ok()?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && identifier == parsed.to_string())
    .then_some(digest)
}

#[derive(Debug, thiserror::Error)]
pub enum OciArchiveError {
    #[error("OCI archive store is not a stable owner/read-group directory")]
    UnsafeStore,
    #[error("another OCI archive publisher already owns the store lock")]
    StoreAlreadyOpen,
    #[error("OCI archive publisher operation lock is poisoned")]
    OperationLockPoisoned,
    #[error("root OCI archive store is not a stable owner-only directory")]
    UnsafePrivateStore,
    #[error("OCI archive is empty, oversized, or not a regular file")]
    ArchiveInvalid,
    #[error("OCI archive changed while it was being verified")]
    ArchiveChanged,
    #[error("OCI archive digest does not match the signed release bundle")]
    ArchiveBinding,
    #[error("an existing OCI archive conflicts with the signed release bundle")]
    ArchiveConflict,
    #[error("OCI archive manifest is not bound to the signed release bundle")]
    ManifestBinding,
    #[error("OCI archive manifest is not canonical JCS")]
    ManifestNonCanonical,
    #[error("OCI archive manifest exceeds its size limit")]
    ManifestOversized,
    #[error("an existing OCI archive manifest conflicts with this publication")]
    ManifestConflict,
    #[error("OCI archive filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("OCI archive canonical encoding failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error(transparent)]
    Build(#[from] crate::build::BuildContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    use tempfile::tempdir;

    use super::*;

    fn shared_directory(path: &Path, uid: u32, gid: u32) {
        fs::create_dir(path).unwrap_or_else(|error| panic!("create shared directory: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o2750))
            .unwrap_or_else(|error| panic!("protect shared directory: {error}"));
        assert_eq!(
            fs::metadata(path)
                .unwrap_or_else(|error| panic!("metadata: {error}"))
                .uid(),
            uid
        );
        assert_eq!(
            fs::metadata(path)
                .unwrap_or_else(|error| panic!("metadata: {error}"))
                .gid(),
            gid
        );
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap_or_else(|error| panic!("create private directory: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("protect private directory: {error}"));
    }

    #[test]
    fn oci_archive_publication_is_replay_safe_and_promotes_exact_bytes() {
        let fixture = crate::build_attestation::tests::release_bundle();
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let metadata =
            fs::metadata(directory.path()).unwrap_or_else(|error| panic!("metadata: {error}"));
        let uid = metadata.uid();
        let gid = metadata.gid();
        let shared = directory.path().join("shared");
        let project = shared.join(fixture.project_id().as_str());
        shared_directory(&shared, uid, gid);
        shared_directory(&project, uid, gid);
        let private = directory.path().join("private");
        let private_project = private.join(fixture.project_id().as_str());
        private_directory(&private);
        private_directory(&private_project);
        let archive_path = directory.path().join("candidate.oci.tar");
        fs::write(&archive_path, b"fixture OCI archive")
            .unwrap_or_else(|error| panic!("write archive: {error}"));
        let archive =
            File::open(&archive_path).unwrap_or_else(|error| panic!("open archive: {error}"));
        assert_eq!(
            *fixture.image_archive_digest(),
            EvidenceDigest::sha256(b"fixture OCI archive")
        );
        let publisher = OciArchivePublisherV1::open(&shared, uid, gid)
            .unwrap_or_else(|error| panic!("publisher: {error}"));
        let substituted_path = directory.path().join("substituted.oci.tar");
        fs::write(&substituted_path, b"substituted OCI archive")
            .unwrap_or_else(|error| panic!("write substituted archive: {error}"));
        let substituted = File::open(&substituted_path)
            .unwrap_or_else(|error| panic!("open substituted archive: {error}"));
        assert!(matches!(
            publisher.publish(&fixture, &substituted, 100),
            Err(OciArchiveError::ArchiveBinding)
        ));
        let first = publisher
            .publish(&fixture, &archive, 100)
            .unwrap_or_else(|error| panic!("publish archive: {error}"));
        assert!(matches!(
            OciArchivePublisherV1::open(&shared, uid, gid),
            Err(OciArchiveError::StoreAlreadyOpen)
        ));
        assert_eq!(
            publisher
                .publish(&fixture, &archive, 100)
                .unwrap_or_else(|error| panic!("replay archive: {error}")),
            first
        );
        let opened = OciArchiveReaderV1::open(&shared, uid, gid)
            .and_then(|reader| reader.load(&fixture))
            .unwrap_or_else(|error| panic!("read archive: {error}"));
        let promoted = promote_oci_archive_private(&private, uid, &fixture, &opened)
            .unwrap_or_else(|error| panic!("promote archive: {error}"));
        assert_eq!(
            fs::read(&promoted).unwrap_or_else(|error| panic!("read promoted: {error}")),
            b"fixture OCI archive"
        );
        let orphan =
            private_project.join(format!(".{}.{}.tmp", "f".repeat(64), Uuid::from_u128(40)));
        fs::write(&orphan, b"interrupted private copy")
            .unwrap_or_else(|error| panic!("write orphan: {error}"));
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("protect orphan: {error}"));
        let linked_temporary =
            private_project.join(format!(".{}.{}.tmp", fixture.digest(), Uuid::from_u128(41)));
        fs::hard_link(&promoted, &linked_temporary)
            .unwrap_or_else(|error| panic!("link interrupted promotion: {error}"));
        assert_eq!(
            promote_oci_archive_private(&private, uid, &fixture, &opened)
                .unwrap_or_else(|error| panic!("recover promotion: {error}")),
            promoted
        );
        assert!(!orphan.exists());
        assert!(!linked_temporary.exists());
        assert_eq!(
            fs::metadata(&promoted)
                .unwrap_or_else(|error| panic!("promoted metadata: {error}"))
                .nlink(),
            1
        );
        let extra_link = directory.path().join("extra-archive-link");
        fs::hard_link(&first, &extra_link)
            .unwrap_or_else(|error| panic!("link published archive: {error}"));
        assert!(matches!(
            OciArchiveReaderV1::open(&shared, uid, gid).and_then(|reader| reader.load(&fixture)),
            Err(OciArchiveError::UnsafeStore)
        ));
        fs::remove_file(extra_link).unwrap_or_else(|error| panic!("unlink archive: {error}"));
        OciArchiveReaderV1::open(&shared, uid, gid)
            .and_then(|reader| reader.load(&fixture))
            .unwrap_or_else(|error| panic!("read archive after unlink: {error}"));

        fs::set_permissions(&promoted, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("make promoted archive writable: {error}"));
        fs::write(&promoted, b"corrupt promoted bytes")
            .unwrap_or_else(|error| panic!("corrupt promoted archive: {error}"));
        fs::set_permissions(&promoted, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("reprotect promoted archive: {error}"));
        assert!(matches!(
            verify_promoted_oci_archive(&private, uid, &fixture),
            Err(OciArchiveError::ArchiveBinding)
        ));
    }

    #[test]
    fn oci_archive_publication_recovers_interrupted_shared_links() {
        let fixture = crate::build_attestation::tests::release_bundle();
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let metadata =
            fs::metadata(directory.path()).unwrap_or_else(|error| panic!("metadata: {error}"));
        let uid = metadata.uid();
        let gid = metadata.gid();
        let shared = directory.path().join("shared");
        let project = shared.join(fixture.project_id().as_str());
        shared_directory(&shared, uid, gid);
        shared_directory(&project, uid, gid);
        let archive_path = directory.path().join("candidate.oci.tar");
        fs::write(&archive_path, b"fixture OCI archive")
            .unwrap_or_else(|error| panic!("write archive: {error}"));
        let archive =
            File::open(&archive_path).unwrap_or_else(|error| panic!("open archive: {error}"));
        let publisher = OciArchivePublisherV1::open(&shared, uid, gid)
            .unwrap_or_else(|error| panic!("publisher: {error}"));
        let published_path = publisher
            .publish(&fixture, &archive, 100)
            .unwrap_or_else(|error| panic!("publish archive: {error}"));
        let orphan = project.join(format!(
            ".{}.{}.oci.tmp",
            fixture.digest(),
            Uuid::from_u128(38)
        ));
        fs::write(&orphan, b"interrupted shared copy")
            .unwrap_or_else(|error| panic!("write shared orphan: {error}"));
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|error| panic!("protect shared orphan: {error}"));
        let linked_archive = project.join(format!(
            ".{}.{}.oci.tmp",
            fixture.digest(),
            Uuid::from_u128(39)
        ));
        fs::hard_link(&published_path, &linked_archive)
            .unwrap_or_else(|error| panic!("link shared archive publication: {error}"));
        let manifest = project.join(format!("{}.manifest.jcs", fixture.digest()));
        let linked_manifest = project.join(format!(
            ".{}.{}.manifest.tmp",
            fixture.digest(),
            Uuid::from_u128(40)
        ));
        fs::hard_link(&manifest, &linked_manifest)
            .unwrap_or_else(|error| panic!("link shared manifest publication: {error}"));
        assert_eq!(
            publisher
                .publish(&fixture, &archive, 100)
                .unwrap_or_else(|error| panic!("recover shared publication: {error}")),
            published_path
        );
        assert!(!orphan.exists());
        assert!(!linked_archive.exists());
        assert!(!linked_manifest.exists());
        for path in [published_path, manifest] {
            assert_eq!(
                fs::metadata(path)
                    .unwrap_or_else(|error| panic!("publication metadata: {error}"))
                    .nlink(),
                1
            );
        }
    }
}
