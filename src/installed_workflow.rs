use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use crate::domain::{EvidenceDigest, ManifestError, ProjectId, ProjectManifestV2};

pub const INSTALLED_WORKFLOW_CATALOG_PATH: &str = "/etc/rdashboard/project-manifests";

const MAX_MANIFEST_BYTES: u64 = 512 * 1024;
const MAX_PROJECTS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledWorkflowProjectV1 {
    pub manifest: ProjectManifestV2,
    pub workflow_policy_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledWorkflowCatalogV1 {
    projects: BTreeMap<ProjectId, InstalledWorkflowProjectV1>,
}

impl InstalledWorkflowCatalogV1 {
    pub fn from_manifests(
        manifests: impl IntoIterator<Item = ProjectManifestV2>,
    ) -> Result<Self, InstalledWorkflowError> {
        let mut projects = BTreeMap::new();
        for manifest in manifests {
            manifest.validate()?;
            let workflow_policy_digest = manifest.workflow_policy_digest()?;
            let project_id = manifest.project_id.clone();
            if projects
                .insert(
                    project_id.clone(),
                    InstalledWorkflowProjectV1 {
                        manifest,
                        workflow_policy_digest,
                    },
                )
                .is_some()
            {
                return Err(InstalledWorkflowError::DuplicateProject(project_id));
            }
            if projects.len() > MAX_PROJECTS {
                return Err(InstalledWorkflowError::CatalogTooLarge);
            }
        }
        if projects.is_empty() {
            return Err(InstalledWorkflowError::EmptyCatalog);
        }
        Ok(Self { projects })
    }

    pub fn load_root_owned() -> Result<Self, InstalledWorkflowError> {
        Self::load_from_owner(Path::new(INSTALLED_WORKFLOW_CATALOG_PATH), 0)
    }

    pub fn load_root_owned_for_group(reader_gid: u32) -> Result<Self, InstalledWorkflowError> {
        if reader_gid == 0 || reader_gid == u32::MAX {
            return Err(InstalledWorkflowError::InvalidReaderGroup);
        }
        Self::load_from_owner_for_group(Path::new(INSTALLED_WORKFLOW_CATALOG_PATH), 0, reader_gid)
    }

    pub fn project(&self, project_id: &ProjectId) -> Option<&InstalledWorkflowProjectV1> {
        self.projects.get(project_id)
    }

    pub fn projects(&self) -> impl ExactSizeIterator<Item = &InstalledWorkflowProjectV1> {
        self.projects.values()
    }

    fn load_from_owner(path: &Path, owner_uid: u32) -> Result<Self, InstalledWorkflowError> {
        Self::load_from_owner_with_optional_group(path, owner_uid, None)
    }

    fn load_from_owner_for_group(
        path: &Path,
        owner_uid: u32,
        reader_gid: u32,
    ) -> Result<Self, InstalledWorkflowError> {
        if reader_gid == 0 || reader_gid == u32::MAX {
            return Err(InstalledWorkflowError::InvalidReaderGroup);
        }
        Self::load_from_owner_with_optional_group(path, owner_uid, Some(reader_gid))
    }

    fn load_from_owner_with_optional_group(
        path: &Path,
        owner_uid: u32,
        reader_gid: Option<u32>,
    ) -> Result<Self, InstalledWorkflowError> {
        validate_catalog_directory(path, owner_uid, reader_gid)?;
        let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        if entries.is_empty() {
            return Err(InstalledWorkflowError::EmptyCatalog);
        }
        if entries.len() > MAX_PROJECTS {
            return Err(InstalledWorkflowError::CatalogTooLarge);
        }

        let mut manifests = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry_path = entry.path();
            if entry_path.extension().and_then(|value| value.to_str()) != Some("jcs") {
                return Err(InstalledWorkflowError::UnexpectedCatalogEntry(entry_path));
            }
            let bytes = read_stable_manifest(&entry_path, owner_uid, reader_gid)?;
            let manifest = ProjectManifestV2::decode_canonical(&bytes)?;
            let stem = entry_path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    InstalledWorkflowError::UnexpectedCatalogEntry(entry_path.clone())
                })?;
            if stem != manifest.project_id.as_str() {
                return Err(InstalledWorkflowError::FilenameProjectMismatch {
                    path: entry_path,
                    project_id: manifest.project_id,
                });
            }
            manifests.push(manifest);
        }
        Self::from_manifests(manifests)
    }
}

fn validate_catalog_directory(
    path: &Path,
    owner_uid: u32,
    reader_gid: Option<u32>,
) -> Result<(), InstalledWorkflowError> {
    let metadata = fs::symlink_metadata(path)?;
    let access_is_safe = match reader_gid {
        Some(gid) => metadata.gid() == gid && metadata.mode() & 0o7777 == 0o750,
        None => metadata.mode() & 0o7777 == 0o700,
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || !access_is_safe
    {
        return Err(InstalledWorkflowError::UnsafeCatalogPath(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn read_stable_manifest(
    path: &Path,
    owner_uid: u32,
    reader_gid: Option<u32>,
) -> Result<Vec<u8>, InstalledWorkflowError> {
    let path_metadata = fs::symlink_metadata(path)?;
    let access_is_safe = match reader_gid {
        Some(gid) => path_metadata.gid() == gid && path_metadata.mode() & 0o7777 == 0o640,
        None => path_metadata.mode() & 0o7777 == 0o600,
    };
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != owner_uid
        || !access_is_safe
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(InstalledWorkflowError::UnsafeManifest(path.to_path_buf()));
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !same_file(&path_metadata, &opened_metadata) {
        return Err(InstalledWorkflowError::UnsafeManifest(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || !same_file(&opened_metadata, &final_metadata)
        || bytes.len() != usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX)
    {
        return Err(InstalledWorkflowError::UnsafeManifest(path.to_path_buf()));
    }
    Ok(bytes)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledWorkflowError {
    #[error("installed workflow catalog filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("installed workflow manifest is invalid: {0}")]
    Manifest(#[from] ManifestError),
    #[error("installed workflow catalog is empty")]
    EmptyCatalog,
    #[error("installed workflow catalog reader group is invalid")]
    InvalidReaderGroup,
    #[error("installed workflow catalog exceeds its project limit")]
    CatalogTooLarge,
    #[error("installed workflow catalog path is not owner-private: {0}")]
    UnsafeCatalogPath(PathBuf),
    #[error("installed workflow manifest is not a stable owner-private file: {0}")]
    UnsafeManifest(PathBuf),
    #[error("installed workflow catalog contains unexpected entry {0}")]
    UnexpectedCatalogEntry(PathBuf),
    #[error("installed workflow manifest {path} names project {project_id}")]
    FilenameProjectMismatch {
        path: PathBuf,
        project_id: ProjectId,
    },
    #[error("installed workflow catalog contains duplicate project {0}")]
    DuplicateProject(ProjectId),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn installed_loader_requires_private_canonical_files() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("catalog permissions: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("catalog metadata: {error}"))
            .uid();
        assert!(matches!(
            InstalledWorkflowCatalogV1::load_from_owner(directory.path(), uid),
            Err(InstalledWorkflowError::EmptyCatalog)
        ));

        let unexpected = directory.path().join("README.md");
        fs::write(&unexpected, b"not a manifest")
            .unwrap_or_else(|error| panic!("write unexpected entry: {error}"));
        fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("entry permissions: {error}"));
        assert!(matches!(
            InstalledWorkflowCatalogV1::load_from_owner(directory.path(), uid),
            Err(InstalledWorkflowError::UnexpectedCatalogEntry(_))
        ));
    }

    #[test]
    fn installed_loader_accepts_only_exact_read_only_group_access() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
            .unwrap_or_else(|error| panic!("catalog permissions: {error}"));
        let metadata = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("catalog metadata: {error}"));
        assert_ne!(
            metadata.gid(),
            0,
            "group-readable contract requires non-root GID"
        );
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .unwrap_or_else(|error| panic!("manifest fixture: {error}"));
        let path = directory.path().join("ralert.jcs");
        fs::write(
            &path,
            serde_jcs::to_vec(&manifest)
                .unwrap_or_else(|error| panic!("canonical manifest: {error}")),
        )
        .unwrap_or_else(|error| panic!("write manifest: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|error| panic!("manifest permissions: {error}"));
        let loaded = InstalledWorkflowCatalogV1::load_from_owner_for_group(
            directory.path(),
            metadata.uid(),
            metadata.gid(),
        )
        .unwrap_or_else(|error| panic!("load group-readable catalog: {error}"));
        assert!(loaded.project(&manifest.project_id).is_some());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("weaken manifest permissions: {error}"));
        assert!(matches!(
            InstalledWorkflowCatalogV1::load_from_owner_for_group(
                directory.path(),
                metadata.uid(),
                metadata.gid(),
            ),
            Err(InstalledWorkflowError::UnsafeManifest(_))
        ));
    }
}
