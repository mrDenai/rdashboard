use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Read as _},
    os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::domain::{EvidenceDigest, GitCommitId, InstalledPolicyIdentity, ProjectId};

pub const BUILD_SOURCE_EXPORT_ROOT: &str = "/var/lib/rdashboard-build/source-exports";

const SOURCE_ARCHIVE_SCHEMA_VERSION: u16 = 1;
const SOURCE_ARCHIVE_PURPOSE: &str = "rdashboard.source-archive-handoff.v1";
const MAX_SOURCE_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceArchiveInputV1 {
    pub project_id: ProjectId,
    pub head: GitCommitId,
    pub sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub repository_identity: EvidenceDigest,
    pub exported_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArchiveManifestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub head: GitCommitId,
    pub sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub repository_identity: EvidenceDigest,
    pub archive_sha256: EvidenceDigest,
    pub archive_bytes: u64,
    pub exported_at_ms: i64,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SourceArchiveManifestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    head: &'a GitCommitId,
    sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
    repository_identity: &'a EvidenceDigest,
    archive_sha256: &'a EvidenceDigest,
    archive_bytes: u64,
    exported_at_ms: i64,
}

impl SourceArchiveManifestV1 {
    fn new(
        input: SourceArchiveInputV1,
        archive_sha256: EvidenceDigest,
        archive_bytes: u64,
    ) -> Result<Self, SourceArchiveError> {
        let mut manifest = Self {
            purpose: SOURCE_ARCHIVE_PURPOSE.to_owned(),
            schema_version: SOURCE_ARCHIVE_SCHEMA_VERSION,
            project_id: input.project_id,
            head: input.head,
            sequence: input.sequence,
            source_attestation_digest: input.source_attestation_digest,
            installed_policy: input.installed_policy,
            repository_identity: input.repository_identity,
            archive_sha256,
            archive_bytes,
            exported_at_ms: input.exported_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        manifest.document_digest = manifest.calculate_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SourceArchiveError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&manifest)? != bytes {
            return Err(SourceArchiveError::NonCanonicalManifest);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SourceArchiveError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn validate(&self) -> Result<(), SourceArchiveError> {
        if self.purpose != SOURCE_ARCHIVE_PURPOSE
            || self.schema_version != SOURCE_ARCHIVE_SCHEMA_VERSION
            || self.sequence == 0
            || self.installed_policy.version == 0
            || self.archive_bytes == 0
            || self.archive_bytes > MAX_SOURCE_ARCHIVE_BYTES
            || self.exported_at_ms < 0
            || self.document_digest != self.calculate_digest()?
        {
            return Err(SourceArchiveError::InvalidManifest);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SourceArchiveError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SourceArchiveManifestPayload {
                purpose: SOURCE_ARCHIVE_PURPOSE,
                schema_version: SOURCE_ARCHIVE_SCHEMA_VERSION,
                project_id: &self.project_id,
                head: &self.head,
                sequence: self.sequence,
                source_attestation_digest: &self.source_attestation_digest,
                installed_policy: &self.installed_policy,
                repository_identity: &self.repository_identity,
                archive_sha256: &self.archive_sha256,
                archive_bytes: self.archive_bytes,
                exported_at_ms: self.exported_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct SourceArchivePublisherV1 {
    root: PathBuf,
    source_uid: u32,
    build_reader_gid: u32,
}

#[derive(Clone, Debug)]
pub struct SourceArchiveReaderV1 {
    root: PathBuf,
    source_uid: u32,
    build_reader_gid: u32,
}

#[derive(Debug)]
pub struct OpenedSourceArchiveV1 {
    pub manifest: SourceArchiveManifestV1,
    pub archive: File,
}

impl SourceArchiveReaderV1 {
    pub fn open(
        root: impl Into<PathBuf>,
        source_uid: u32,
        build_reader_gid: u32,
    ) -> Result<Self, SourceArchiveError> {
        let reader = Self {
            root: root.into(),
            source_uid,
            build_reader_gid,
        };
        reader.validate_root()?;
        Ok(reader)
    }

    pub fn latest(
        &self,
        project_id: &ProjectId,
    ) -> Result<OpenedSourceArchiveV1, SourceArchiveError> {
        self.validate_root()?;
        let project_root = self.root.join(project_id.as_str());
        validate_shared_directory(&project_root, self.source_uid, self.build_reader_gid, true)?;
        let mut latest: Option<(SourceArchiveManifestV1, PathBuf)> = None;
        let mut entries = 0_usize;
        for entry in fs::read_dir(&project_root)? {
            let entry = entry?;
            entries = entries
                .checked_add(1)
                .ok_or(SourceArchiveError::TooManyPublications)?;
            if entries > 10_000 {
                return Err(SourceArchiveError::TooManyPublications);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SourceArchiveError::UnexpectedPublication)?;
            let extension = Path::new(&name)
                .extension()
                .and_then(|value| value.to_str());
            if name.starts_with('.') || extension == Some("tar") {
                continue;
            }
            if extension != Some("jcs") {
                return Err(SourceArchiveError::UnexpectedPublication);
            }
            let manifest_file = inspect_shared_file(
                &entry.path(),
                self.source_uid,
                self.build_reader_gid,
                MAX_SOURCE_ARCHIVE_MANIFEST_BYTES,
            )?;
            let mut bytes = Vec::new();
            manifest_file
                .file
                .take(manifest_file.length)
                .read_to_end(&mut bytes)?;
            let manifest = SourceArchiveManifestV1::decode_canonical(&bytes)?;
            if manifest.project_id != *project_id
                || name != format!("{}.jcs", archive_stem(&manifest.head, manifest.sequence))
            {
                return Err(SourceArchiveError::UnexpectedPublication);
            }
            match latest.as_ref() {
                Some((current, _)) if current.sequence > manifest.sequence => {}
                Some((current, _)) if current.sequence == manifest.sequence => {
                    return Err(SourceArchiveError::PublicationConflict);
                }
                _ => latest = Some((manifest, entry.path())),
            }
        }
        let (manifest, manifest_path) = latest.ok_or(SourceArchiveError::NoPublication)?;
        self.open_publication(&project_root, &manifest_path, manifest)
    }

    pub fn exact(
        &self,
        project_id: &ProjectId,
        head: &GitCommitId,
        sequence: u64,
    ) -> Result<OpenedSourceArchiveV1, SourceArchiveError> {
        if sequence == 0 {
            return Err(SourceArchiveError::InvalidManifest);
        }
        self.validate_root()?;
        let project_root = self.root.join(project_id.as_str());
        validate_shared_directory(&project_root, self.source_uid, self.build_reader_gid, true)?;
        let manifest_path = project_root.join(format!("{}.jcs", archive_stem(head, sequence)));
        let manifest_file = inspect_shared_file(
            &manifest_path,
            self.source_uid,
            self.build_reader_gid,
            MAX_SOURCE_ARCHIVE_MANIFEST_BYTES,
        )?;
        let mut bytes = Vec::new();
        manifest_file
            .file
            .take(manifest_file.length)
            .read_to_end(&mut bytes)?;
        let manifest = SourceArchiveManifestV1::decode_canonical(&bytes)?;
        if manifest.project_id != *project_id
            || manifest.head != *head
            || manifest.sequence != sequence
        {
            return Err(SourceArchiveError::PublicationConflict);
        }
        self.open_publication(&project_root, &manifest_path, manifest)
    }

    fn open_publication(
        &self,
        project_root: &Path,
        manifest_path: &Path,
        manifest: SourceArchiveManifestV1,
    ) -> Result<OpenedSourceArchiveV1, SourceArchiveError> {
        let archive_path = project_root.join(format!(
            "{}.tar",
            archive_stem(&manifest.head, manifest.sequence)
        ));
        let archive = inspect_shared_file(
            &archive_path,
            self.source_uid,
            self.build_reader_gid,
            MAX_SOURCE_ARCHIVE_BYTES,
        )?;
        if archive.length != manifest.archive_bytes
            || hash_open_file(&archive.file)? != manifest.archive_sha256
        {
            return Err(SourceArchiveError::ArchiveDigestMismatch);
        }
        let manifest_metadata = fs::symlink_metadata(manifest_path)?;
        let archive_metadata = archive.file.metadata()?;
        if manifest_metadata.uid() != archive_metadata.uid()
            || manifest_metadata.gid() != archive_metadata.gid()
        {
            return Err(SourceArchiveError::PublicationConflict);
        }
        Ok(OpenedSourceArchiveV1 {
            manifest,
            archive: archive.file,
        })
    }

    fn validate_root(&self) -> Result<(), SourceArchiveError> {
        if self.source_uid == 0
            || self.source_uid == u32::MAX
            || self.build_reader_gid == 0
            || self.build_reader_gid == u32::MAX
        {
            return Err(SourceArchiveError::InvalidIdentity);
        }
        validate_shared_directory(&self.root, self.source_uid, self.build_reader_gid, true)
    }
}

impl SourceArchivePublisherV1 {
    pub fn open(
        root: impl Into<PathBuf>,
        source_uid: u32,
        build_reader_gid: u32,
    ) -> Result<Self, SourceArchiveError> {
        let publisher = Self {
            root: root.into(),
            source_uid,
            build_reader_gid,
        };
        publisher.validate_root()?;
        Ok(publisher)
    }

    pub fn publish<F>(
        &self,
        input: SourceArchiveInputV1,
        write_archive: F,
    ) -> Result<SourceArchiveManifestV1, SourceArchiveError>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        self.validate_root()?;
        validate_input(&input)?;
        let project_root = self.project_root(&input.project_id)?;
        let stem = archive_stem(&input.head, input.sequence);
        let archive_path = project_root.join(format!("{stem}.tar"));
        let manifest_path = project_root.join(format!("{stem}.jcs"));
        if manifest_path.try_exists()? {
            return self.reopen_exact(&input, &archive_path, &manifest_path);
        }

        let archive_identity = if archive_path.try_exists()? {
            inspect_shared_file(
                &archive_path,
                self.source_uid,
                self.build_reader_gid,
                MAX_SOURCE_ARCHIVE_BYTES,
            )?
        } else {
            self.write_archive(&project_root, &archive_path, &stem, write_archive)?
        };
        let archive_sha256 = hash_open_file(&archive_identity.file)?;
        let manifest =
            SourceArchiveManifestV1::new(input, archive_sha256, archive_identity.length)?;
        Self::write_manifest(&project_root, &manifest_path, &stem, &manifest)?;
        sync_directory(&project_root)?;
        self.reopen_exact_manifest(&archive_path, &manifest_path)
    }

    fn write_archive<F>(
        &self,
        project_root: &Path,
        archive_path: &Path,
        stem: &str,
        write_archive: F,
    ) -> Result<SharedFile, SourceArchiveError>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        let temporary = project_root.join(format!(".{stem}.{}.tar.tmp", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        if let Err(error) = write_archive(&mut file) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(SourceArchiveError::ArchiveWriter(error));
        }
        file.sync_all()?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_SOURCE_ARCHIVE_BYTES {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(SourceArchiveError::InvalidArchiveSize(length));
        }
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o440))?;
        file.sync_all()?;
        fs::rename(&temporary, archive_path)?;
        sync_directory(project_root)?;
        inspect_shared_file(
            archive_path,
            self.source_uid,
            self.build_reader_gid,
            MAX_SOURCE_ARCHIVE_BYTES,
        )
    }

    fn write_manifest(
        project_root: &Path,
        manifest_path: &Path,
        stem: &str,
        manifest: &SourceArchiveManifestV1,
    ) -> Result<(), SourceArchiveError> {
        let temporary = project_root.join(format!(".{stem}.{}.jcs.tmp", Uuid::new_v4()));
        let bytes = manifest.canonical_bytes()?;
        if bytes.len() as u64 > MAX_SOURCE_ARCHIVE_MANIFEST_BYTES {
            return Err(SourceArchiveError::InvalidManifest);
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o440))?;
        file.sync_all()?;
        fs::rename(&temporary, manifest_path)?;
        Ok(())
    }

    fn reopen_exact(
        &self,
        input: &SourceArchiveInputV1,
        archive_path: &Path,
        manifest_path: &Path,
    ) -> Result<SourceArchiveManifestV1, SourceArchiveError> {
        let manifest = self.reopen_exact_manifest(archive_path, manifest_path)?;
        if manifest.project_id != input.project_id
            || manifest.head != input.head
            || manifest.sequence != input.sequence
            || manifest.source_attestation_digest != input.source_attestation_digest
            || manifest.installed_policy != input.installed_policy
            || manifest.repository_identity != input.repository_identity
        {
            return Err(SourceArchiveError::PublicationConflict);
        }
        Ok(manifest)
    }

    fn reopen_exact_manifest(
        &self,
        archive_path: &Path,
        manifest_path: &Path,
    ) -> Result<SourceArchiveManifestV1, SourceArchiveError> {
        let manifest_file = inspect_shared_file(
            manifest_path,
            self.source_uid,
            self.build_reader_gid,
            MAX_SOURCE_ARCHIVE_MANIFEST_BYTES,
        )?;
        let mut bytes = Vec::new();
        manifest_file
            .file
            .take(manifest_file.length)
            .read_to_end(&mut bytes)?;
        let manifest = SourceArchiveManifestV1::decode_canonical(&bytes)?;
        let archive = inspect_shared_file(
            archive_path,
            self.source_uid,
            self.build_reader_gid,
            MAX_SOURCE_ARCHIVE_BYTES,
        )?;
        if archive.length != manifest.archive_bytes
            || hash_open_file(&archive.file)? != manifest.archive_sha256
        {
            return Err(SourceArchiveError::ArchiveDigestMismatch);
        }
        Ok(manifest)
    }

    fn project_root(&self, project_id: &ProjectId) -> Result<PathBuf, SourceArchiveError> {
        let path = self.root.join(project_id.as_str());
        if !path.try_exists()? {
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o2750))?;
            sync_directory(&self.root)?;
        }
        validate_shared_directory(&path, self.source_uid, self.build_reader_gid, true)?;
        Ok(path)
    }

    fn validate_root(&self) -> Result<(), SourceArchiveError> {
        if self.source_uid == 0
            || self.source_uid == u32::MAX
            || self.build_reader_gid == 0
            || self.build_reader_gid == u32::MAX
        {
            return Err(SourceArchiveError::InvalidIdentity);
        }
        validate_shared_directory(&self.root, self.source_uid, self.build_reader_gid, true)
    }
}

#[derive(Debug)]
struct SharedFile {
    file: File,
    length: u64,
}

fn validate_input(input: &SourceArchiveInputV1) -> Result<(), SourceArchiveError> {
    if input.sequence == 0 || input.installed_policy.version == 0 || input.exported_at_ms < 0 {
        Err(SourceArchiveError::InvalidManifest)
    } else {
        Ok(())
    }
}

fn archive_stem(head: &GitCommitId, sequence: u64) -> String {
    format!("{}-{sequence}", head.as_str())
}

fn validate_shared_directory(
    path: &Path,
    owner_uid: u32,
    group_gid: u32,
    require_setgid: bool,
) -> Result<(), SourceArchiveError> {
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let expected_mode = if require_setgid { 0o2750 } else { 0o750 };
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != group_gid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(SourceArchiveError::UntrustedDirectory);
    }
    Ok(())
}

fn inspect_shared_file(
    path: &Path,
    owner_uid: u32,
    group_gid: u32,
    maximum_bytes: u64,
) -> Result<SharedFile, SourceArchiveError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != owner_uid
        || path_metadata.gid() != group_gid
        || path_metadata.mode() & 0o7777 != 0o440
        || path_metadata.nlink() != 1
        || path_metadata.len() == 0
        || path_metadata.len() > maximum_bytes
    {
        return Err(SourceArchiveError::UntrustedFile);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.uid() != path_metadata.uid()
        || opened_metadata.gid() != path_metadata.gid()
        || opened_metadata.mode() & 0o7777 != 0o440
        || opened_metadata.nlink() != 1
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(SourceArchiveError::FileChanged);
    }
    Ok(SharedFile {
        file,
        length: opened_metadata.len(),
    })
}

fn hash_open_file(file: &File) -> Result<EvidenceDigest, SourceArchiveError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut offset = 0_u64;
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(
                u64::try_from(read).map_err(|_| SourceArchiveError::InvalidArchiveSize(offset))?,
            )
            .ok_or(SourceArchiveError::InvalidArchiveSize(offset))?;
    }
    let mut rendered = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut rendered, "{byte:02x}");
    }
    rendered
        .parse()
        .map_err(|_| SourceArchiveError::ArchiveDigestMismatch)
}

fn sync_directory(path: &Path) -> Result<(), SourceArchiveError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SourceArchiveError {
    #[error("source archive handoff identity is invalid")]
    InvalidIdentity,
    #[error("source archive handoff directory is not canonical owner/group setgid 2750")]
    UntrustedDirectory,
    #[error("source archive handoff file is not an exact owner/group 0440 single-link file")]
    UntrustedFile,
    #[error("source archive handoff file changed while it was opened")]
    FileChanged,
    #[error("source archive has invalid size {0}")]
    InvalidArchiveSize(u64),
    #[error("source archive manifest is invalid")]
    InvalidManifest,
    #[error("source archive manifest is not canonical JCS")]
    NonCanonicalManifest,
    #[error("source archive bytes do not match the manifest digest")]
    ArchiveDigestMismatch,
    #[error("source archive publication conflicts with an existing handoff")]
    PublicationConflict,
    #[error("source archive handoff has no published source tree")]
    NoPublication,
    #[error("source archive handoff contains too many publications")]
    TooManyPublications,
    #[error("source archive handoff contains an unexpected publication")]
    UnexpectedPublication,
    #[error("source archive writer failed: {0}")]
    ArchiveWriter(io::Error),
    #[error("source archive handoff I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("source archive handoff JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use tempfile::tempdir;

    use super::*;

    fn input(sequence: u64) -> SourceArchiveInputV1 {
        SourceArchiveInputV1 {
            project_id: ProjectId::from_str("rimg").expect("project"),
            head: GitCommitId::from_str(&"a".repeat(40)).expect("commit"),
            sequence,
            source_attestation_digest: EvidenceDigest::sha256("source attestation"),
            installed_policy: InstalledPolicyIdentity {
                digest: EvidenceDigest::sha256("installed policy"),
                version: 7,
            },
            repository_identity: EvidenceDigest::sha256("repository"),
            exported_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn source_archive_handoff_is_atomic_replayable_and_reader_verified() {
        let directory = tempdir().expect("temp dir");
        let root = directory.path().join("source-exports");
        fs::create_dir(&root).expect("create source export root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o2750))
            .expect("set source export root mode");
        let metadata = fs::metadata(&root).expect("source export root metadata");
        let handoff_writer = SourceArchivePublisherV1::open(&root, metadata.uid(), metadata.gid())
            .expect("open source publisher");
        let expected = input(9);
        let manifest = handoff_writer
            .publish(expected.clone(), |archive| {
                archive.write_all(b"exact tar bytes")
            })
            .expect("publish source archive");
        assert_eq!(
            manifest.archive_sha256,
            EvidenceDigest::sha256("exact tar bytes")
        );

        let replayed = handoff_writer
            .publish(expected.clone(), |_| {
                panic!("exact replay rewrote the archive")
            })
            .expect("replay source publication");
        assert_eq!(replayed, manifest);

        let reader = SourceArchiveReaderV1::open(&root, metadata.uid(), metadata.gid())
            .expect("open source reader");
        let mut opened = reader
            .latest(&expected.project_id)
            .expect("read latest source archive");
        assert_eq!(opened.manifest, manifest);
        let mut bytes = Vec::new();
        opened
            .archive
            .read_to_end(&mut bytes)
            .expect("read source archive bytes");
        assert_eq!(bytes, b"exact tar bytes");

        let manifest_path = root.join("rimg").join(format!(
            "{}.jcs",
            archive_stem(&expected.head, expected.sequence)
        ));
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o640))
            .expect("make manifest permissive");
        assert!(matches!(
            reader.latest(&expected.project_id),
            Err(SourceArchiveError::UntrustedFile)
        ));
    }
}
