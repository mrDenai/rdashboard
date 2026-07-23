use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Cursor, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tar::{Archive, EntryType};

use crate::domain::EvidenceDigest;

pub const CARGO_LOCK_MAX_BYTES: usize = 8 * 1024 * 1024;
pub const CRATE_ARCHIVE_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const CARGO_DEPENDENCY_MANIFEST_FILE: &str = ".rdashboard-cargo-dependency.jcs";
pub const CARGO_VENDOR_DIRECTORY: &str = "vendor";
const CARGO_LOCK_VERSION: i64 = 4;
const MAX_REGISTRY_PACKAGES: usize = 4_096;
const MAX_CRATE_NAME_BYTES: usize = 64;
const MAX_CRATE_VERSION_BYTES: usize = 128;
const MAX_CRATE_PATH_BYTES: usize = 4_096;
const CRATES_IO_GIT_INDEX: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CRATES_IO_SPARSE_INDEX: &str = "registry+https://index.crates.io/";
const DEPENDENCY_MANIFEST_PURPOSE: &str = "rdashboard.cargo-crates-io-dependency.v2";
const DEPENDENCY_MANIFEST_SCHEMA_VERSION: u16 = 2;
const PACKAGE_PLAN_PURPOSE: &str = "rdashboard.cargo-crates-io-package-plan.v1";
const CARGO_VENDOR_LAYOUT_ID: &str = "rdashboard.cargo-crates-io-vendor-layout.v1";
const CHECKSUM_FILE: &str = ".cargo-checksum.json";
const COPY_BUFFER_BYTES: usize = 128 * 1024;
const TAR_STREAM_FIXED_OVERHEAD_BYTES: u64 = 64 * 1024;
const TAR_STREAM_PER_INODE_OVERHEAD_BYTES: u64 = MAX_CRATE_PATH_BYTES as u64 + 2 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoRegistryPackageV1 {
    pub name: String,
    pub version: String,
    pub checksum: EvidenceDigest,
}

impl CargoRegistryPackageV1 {
    pub fn validate(&self) -> Result<(), CargoPrefetchError> {
        if !valid_crate_name(&self.name) || !valid_crate_version(&self.version) {
            return Err(CargoPrefetchError::InvalidRegistryPackage);
        }
        Ok(())
    }

    pub fn archive_file_name(&self) -> String {
        format!("{}-{}.crate", self.name, self.version)
    }

    fn vendor_directory_name(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoLockPlanV1 {
    lockfile_digest: EvidenceDigest,
    package_plan_digest: EvidenceDigest,
    packages: Vec<CargoRegistryPackageV1>,
}

impl CargoLockPlanV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, CargoPrefetchError> {
        if bytes.is_empty() || bytes.len() > CARGO_LOCK_MAX_BYTES {
            return Err(CargoPrefetchError::InvalidLockfile);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| CargoPrefetchError::InvalidLockfile)?;
        let lockfile: RawCargoLock = toml::from_str(text)?;
        if lockfile.version != CARGO_LOCK_VERSION || lockfile.package.is_empty() {
            return Err(CargoPrefetchError::InvalidLockfile);
        }
        let mut packages = Vec::new();
        let mut identities = BTreeSet::new();
        for package in lockfile.package {
            match (package.source.as_deref(), package.checksum.as_deref()) {
                (None, None) => {}
                (Some(CRATES_IO_GIT_INDEX | CRATES_IO_SPARSE_INDEX), Some(checksum)) => {
                    let package = CargoRegistryPackageV1 {
                        name: package.name,
                        version: package.version,
                        checksum: EvidenceDigest::from_str(checksum)
                            .map_err(|_| CargoPrefetchError::InvalidRegistryPackage)?,
                    };
                    package.validate()?;
                    if !identities.insert((package.name.clone(), package.version.clone())) {
                        return Err(CargoPrefetchError::DuplicateRegistryPackage);
                    }
                    packages.push(package);
                }
                _ => return Err(CargoPrefetchError::UnsupportedPackageSource),
            }
            if packages.len() > MAX_REGISTRY_PACKAGES {
                return Err(CargoPrefetchError::TooManyRegistryPackages);
            }
        }
        if packages.is_empty() {
            return Err(CargoPrefetchError::NoRegistryPackages);
        }
        packages.sort();
        let package_plan_digest = package_plan_digest(&packages)?;
        Ok(Self {
            lockfile_digest: EvidenceDigest::sha256(bytes),
            package_plan_digest,
            packages,
        })
    }

    pub const fn lockfile_digest(&self) -> &EvidenceDigest {
        &self.lockfile_digest
    }

    pub const fn package_plan_digest(&self) -> &EvidenceDigest {
        &self.package_plan_digest
    }

    pub fn packages(&self) -> &[CargoRegistryPackageV1] {
        &self.packages
    }
}

#[derive(Deserialize)]
struct RawCargoLock {
    version: i64,
    package: Vec<RawCargoPackage>,
}

#[derive(Deserialize)]
struct RawCargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

#[derive(Serialize)]
struct PackagePlanPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    packages: &'a [CargoRegistryPackageV1],
}

fn package_plan_digest(
    packages: &[CargoRegistryPackageV1],
) -> Result<EvidenceDigest, CargoPrefetchError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &PackagePlanPayload {
            purpose: PACKAGE_PLAN_PURPOSE,
            schema_version: DEPENDENCY_MANIFEST_SCHEMA_VERSION,
            packages,
        },
    )?))
}

pub fn cargo_vendor_layout_digest() -> EvidenceDigest {
    EvidenceDigest::sha256(CARGO_VENDOR_LAYOUT_ID)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoDependencyManifestV1 {
    purpose: String,
    schema_version: u16,
    pub lockfile_digest: EvidenceDigest,
    pub package_plan_digest: EvidenceDigest,
    pub vendor_layout_digest: EvidenceDigest,
    pub package_count: u32,
    document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct CargoDependencyManifestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lockfile_digest: &'a EvidenceDigest,
    package_plan_digest: &'a EvidenceDigest,
    vendor_layout_digest: &'a EvidenceDigest,
    package_count: u32,
}

impl CargoDependencyManifestV1 {
    pub fn new(plan: &CargoLockPlanV1) -> Result<Self, CargoPrefetchError> {
        let package_count = u32::try_from(plan.packages.len())
            .map_err(|_| CargoPrefetchError::TooManyRegistryPackages)?;
        let mut manifest = Self {
            purpose: DEPENDENCY_MANIFEST_PURPOSE.to_owned(),
            schema_version: DEPENDENCY_MANIFEST_SCHEMA_VERSION,
            lockfile_digest: plan.lockfile_digest.clone(),
            package_plan_digest: plan.package_plan_digest.clone(),
            vendor_layout_digest: cargo_vendor_layout_digest(),
            package_count,
            document_digest: EvidenceDigest::sha256([]),
        };
        manifest.document_digest = manifest.calculate_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CargoPrefetchError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CargoPrefetchError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&manifest)? != bytes {
            return Err(CargoPrefetchError::InvalidDependencyManifest);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, CargoPrefetchError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &CargoDependencyManifestPayload {
                purpose: DEPENDENCY_MANIFEST_PURPOSE,
                schema_version: DEPENDENCY_MANIFEST_SCHEMA_VERSION,
                lockfile_digest: &self.lockfile_digest,
                package_plan_digest: &self.package_plan_digest,
                vendor_layout_digest: &self.vendor_layout_digest,
                package_count: self.package_count,
            },
        )?))
    }

    fn validate(&self) -> Result<(), CargoPrefetchError> {
        if self.purpose != DEPENDENCY_MANIFEST_PURPOSE
            || self.schema_version != DEPENDENCY_MANIFEST_SCHEMA_VERSION
            || self.package_count == 0
            || self.vendor_layout_digest != cargo_vendor_layout_digest()
            || usize::try_from(self.package_count)
                .ok()
                .is_none_or(|count| count > MAX_REGISTRY_PACKAGES)
            || self.document_digest != self.calculate_digest()?
        {
            return Err(CargoPrefetchError::InvalidDependencyManifest);
        }
        Ok(())
    }
}

pub fn materialize_cargo_dependency<F, E>(
    payload_root: &Path,
    plan: &CargoLockPlanV1,
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
    fetch: F,
) -> Result<(), CargoPrefetchError>
where
    F: FnMut(&CargoRegistryPackageV1) -> Result<Vec<u8>, E>,
    E: std::fmt::Display,
{
    materialize_cargo_dependency_cancellable(
        payload_root,
        plan,
        maximum_payload_bytes,
        maximum_payload_inodes,
        fetch,
        || false,
    )
}

pub fn materialize_cargo_dependency_cancellable<F, E, C>(
    payload_root: &Path,
    plan: &CargoLockPlanV1,
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
    mut fetch: F,
    mut cancelled: C,
) -> Result<(), CargoPrefetchError>
where
    F: FnMut(&CargoRegistryPackageV1) -> Result<Vec<u8>, E>,
    E: std::fmt::Display,
    C: FnMut() -> bool,
{
    if maximum_payload_bytes == 0 || maximum_payload_inodes < 3 {
        return Err(CargoPrefetchError::DependencyPayloadTooLarge);
    }
    ensure_not_cancelled(&mut cancelled)?;
    let manifest = CargoDependencyManifestV1::new(plan)?;
    let manifest_bytes = manifest.canonical_bytes()?;
    let mut budget = PayloadBudget::new(maximum_payload_bytes, maximum_payload_inodes);
    budget.consume(
        u64::try_from(manifest_bytes.len())
            .map_err(|_| CargoPrefetchError::DependencyPayloadTooLarge)?,
        2,
    )?;
    let vendor_root = payload_root.join(CARGO_VENDOR_DIRECTORY);
    create_directory(&vendor_root)?;
    let mut fetched_archive_bytes = 0_u64;
    for package in plan.packages() {
        ensure_not_cancelled(&mut cancelled)?;
        let archive =
            fetch(package).map_err(|error| CargoPrefetchError::FetchFailed(error.to_string()))?;
        ensure_not_cancelled(&mut cancelled)?;
        if archive.is_empty()
            || archive.len() > CRATE_ARCHIVE_MAX_BYTES
            || EvidenceDigest::sha256(&archive) != package.checksum
        {
            return Err(CargoPrefetchError::ArchiveIntegrityMismatch);
        }
        fetched_archive_bytes = fetched_archive_bytes
            .checked_add(
                u64::try_from(archive.len())
                    .map_err(|_| CargoPrefetchError::DependencyPayloadTooLarge)?,
            )
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?;
        if fetched_archive_bytes > maximum_payload_bytes {
            return Err(CargoPrefetchError::DependencyPayloadTooLarge);
        }
        materialize_crate(package, &archive, &vendor_root, &mut budget, &mut cancelled)?;
    }
    ensure_not_cancelled(&mut cancelled)?;
    write_new_file(
        &payload_root.join(CARGO_DEPENDENCY_MANIFEST_FILE),
        &manifest_bytes,
        false,
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PayloadBudget {
    maximum_bytes: u64,
    maximum_inodes: u64,
    used_bytes: u64,
    used_inodes: u64,
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> BoundedReader<R> {
    const fn new(inner: R, maximum_bytes: u64) -> Self {
        Self {
            inner,
            remaining: maximum_bytes,
        }
    }
}

impl<R: io::Read> io::Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decompressed crate archive exceeds its bounded tar stream",
                )),
            };
        }
        let allowed = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining = self
            .remaining
            .saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
        Ok(read)
    }
}

impl PayloadBudget {
    const fn new(maximum_bytes: u64, maximum_inodes: u64) -> Self {
        Self {
            maximum_bytes,
            maximum_inodes,
            used_bytes: 0,
            used_inodes: 0,
        }
    }

    fn consume(&mut self, bytes: u64, inodes: u64) -> Result<(), CargoPrefetchError> {
        let used_bytes = self
            .used_bytes
            .checked_add(bytes)
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?;
        let used_inodes = self
            .used_inodes
            .checked_add(inodes)
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?;
        if used_bytes > self.maximum_bytes || used_inodes > self.maximum_inodes {
            return Err(CargoPrefetchError::DependencyPayloadTooLarge);
        }
        self.used_bytes = used_bytes;
        self.used_inodes = used_inodes;
        Ok(())
    }

    const fn remaining_bytes(self) -> u64 {
        self.maximum_bytes.saturating_sub(self.used_bytes)
    }

    const fn remaining_inodes(self) -> u64 {
        self.maximum_inodes.saturating_sub(self.used_inodes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CrateArchiveInventory {
    directories: Vec<PathBuf>,
    files: BTreeMap<PathBuf, CrateArchiveFile>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CrateArchiveFile {
    bytes: u64,
    executable: bool,
}

fn materialize_crate<C>(
    package: &CargoRegistryPackageV1,
    archive_bytes: &[u8],
    vendor_root: &Path,
    budget: &mut PayloadBudget,
    cancelled: &mut C,
) -> Result<(), CargoPrefetchError>
where
    C: FnMut() -> bool,
{
    let inventory = inspect_crate_archive(
        package,
        archive_bytes,
        budget.remaining_bytes(),
        budget.remaining_inodes(),
        cancelled,
    )?;
    let checksum_estimate = checksum_file_bytes(package, &inventory, None)?;
    let file_bytes = inventory.files.values().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)
    })?;
    let inodes = u64::try_from(
        inventory
            .directories
            .len()
            .checked_add(inventory.files.len())
            .and_then(|count| count.checked_add(2))
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?,
    )
    .map_err(|_| CargoPrefetchError::DependencyPayloadTooLarge)?;
    budget.consume(
        file_bytes
            .checked_add(
                u64::try_from(checksum_estimate.len())
                    .map_err(|_| CargoPrefetchError::DependencyPayloadTooLarge)?,
            )
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?,
        inodes,
    )?;

    let crate_root = vendor_root.join(package.vendor_directory_name());
    create_directory(&crate_root)?;
    for relative in &inventory.directories {
        ensure_not_cancelled(cancelled)?;
        create_directory(&crate_root.join(relative))?;
    }
    let checksums =
        extract_crate_archive(package, archive_bytes, &crate_root, &inventory, cancelled)?;
    let checksum_bytes = checksum_file_bytes(package, &inventory, Some(&checksums))?;
    if checksum_bytes.len() != checksum_estimate.len() {
        return Err(CargoPrefetchError::InvalidCrateArchive);
    }
    write_new_file(&crate_root.join(CHECKSUM_FILE), &checksum_bytes, false)?;
    Ok(())
}

fn inspect_crate_archive<C>(
    package: &CargoRegistryPackageV1,
    archive_bytes: &[u8],
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
    cancelled: &mut C,
) -> Result<CrateArchiveInventory, CargoPrefetchError>
where
    C: FnMut() -> bool,
{
    if maximum_payload_bytes == 0 || maximum_payload_inodes < 2 {
        return Err(CargoPrefetchError::DependencyPayloadTooLarge);
    }
    let expected_root = package.vendor_directory_name();
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let maximum_tar_bytes =
        maximum_tar_stream_bytes(maximum_payload_bytes, maximum_payload_inodes)?;
    let mut archive = Archive::new(BoundedReader::new(decoder, maximum_tar_bytes));
    let mut directories = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut file_bytes = 0_u64;
    for entry in archive.entries()? {
        ensure_not_cancelled(cancelled)?;
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        let Some(relative) = decode_crate_path(
            entry.path_bytes().as_ref(),
            &expected_root,
            entry_type == EntryType::Directory,
        )?
        else {
            if entry_type != EntryType::Directory || entry.header().size()? != 0 {
                return Err(CargoPrefetchError::InvalidCrateArchive);
            }
            continue;
        };
        if relative == Path::new(CHECKSUM_FILE) {
            return Err(CargoPrefetchError::InvalidCrateArchive);
        }
        if entry_type == EntryType::Directory {
            if entry.header().size()? != 0
                || files.contains_key(&relative)
                || !directories.insert(relative.clone())
            {
                return Err(CargoPrefetchError::InvalidCrateArchive);
            }
            insert_parent_directories(&relative, &mut directories, &files)?;
        } else if entry_type.is_file() {
            let file = CrateArchiveFile {
                bytes: entry.header().size()?,
                executable: entry.header().mode()? & 0o111 != 0,
            };
            file_bytes = file_bytes
                .checked_add(file.bytes)
                .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?;
            if directories.contains(&relative) || files.insert(relative.clone(), file).is_some() {
                return Err(CargoPrefetchError::InvalidCrateArchive);
            }
            insert_parent_directories(&relative, &mut directories, &files)?;
            drain_entry(&mut entry, file.bytes, cancelled)?;
        } else {
            return Err(CargoPrefetchError::UnsupportedCrateEntry);
        }
        let entry_count = directories
            .len()
            .checked_add(files.len())
            .and_then(|count| count.checked_add(2))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?;
        if file_bytes > maximum_payload_bytes
            || entry_count > maximum_payload_inodes
            || directories.len().saturating_add(files.len()) > 100_000
        {
            return Err(CargoPrefetchError::DependencyPayloadTooLarge);
        }
    }
    drain_archive(archive, cancelled)?;
    if files.is_empty()
        || files.keys().any(|file| {
            file.ancestors()
                .skip(1)
                .any(|parent| files.contains_key(parent))
        })
    {
        return Err(CargoPrefetchError::InvalidCrateArchive);
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| {
                left.as_os_str()
                    .as_encoded_bytes()
                    .cmp(right.as_os_str().as_encoded_bytes())
            })
    });
    Ok(CrateArchiveInventory { directories, files })
}

fn extract_crate_archive<C>(
    package: &CargoRegistryPackageV1,
    archive_bytes: &[u8],
    crate_root: &Path,
    inventory: &CrateArchiveInventory,
    cancelled: &mut C,
) -> Result<BTreeMap<String, String>, CargoPrefetchError>
where
    C: FnMut() -> bool,
{
    let expected_root = package.vendor_directory_name();
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let maximum_payload_bytes = inventory.files.values().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)
    })?;
    let maximum_payload_inodes = u64::try_from(
        inventory
            .directories
            .len()
            .checked_add(inventory.files.len())
            .and_then(|count| count.checked_add(2))
            .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)?,
    )
    .map_err(|_| CargoPrefetchError::DependencyPayloadTooLarge)?;
    let maximum_tar_bytes =
        maximum_tar_stream_bytes(maximum_payload_bytes, maximum_payload_inodes)?;
    let mut archive = Archive::new(BoundedReader::new(decoder, maximum_tar_bytes));
    let mut seen = BTreeSet::new();
    let mut checksums = BTreeMap::new();
    for entry in archive.entries()? {
        ensure_not_cancelled(cancelled)?;
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        let Some(relative) = decode_crate_path(
            entry.path_bytes().as_ref(),
            &expected_root,
            entry_type == EntryType::Directory,
        )?
        else {
            continue;
        };
        if entry_type == EntryType::Directory {
            if !inventory.directories.contains(&relative) {
                return Err(CargoPrefetchError::CrateArchiveChanged);
            }
            continue;
        }
        let expected = inventory
            .files
            .get(&relative)
            .ok_or(CargoPrefetchError::CrateArchiveChanged)?;
        if !entry_type.is_file()
            || entry.header().size()? != expected.bytes
            || (entry.header().mode()? & 0o111 != 0) != expected.executable
            || !seen.insert(relative.clone())
        {
            return Err(CargoPrefetchError::CrateArchiveChanged);
        }
        let path = crate_root.join(&relative);
        let digest = copy_archive_file(&mut entry, &path, *expected, cancelled)?;
        let key = relative
            .to_str()
            .ok_or(CargoPrefetchError::InvalidCratePath)?
            .to_owned();
        if checksums.insert(key, digest.to_string()).is_some() {
            return Err(CargoPrefetchError::InvalidCrateArchive);
        }
    }
    drain_archive(archive, cancelled)?;
    if seen.len() != inventory.files.len() || checksums.len() != inventory.files.len() {
        return Err(CargoPrefetchError::CrateArchiveChanged);
    }
    Ok(checksums)
}

fn drain_archive<R, C>(archive: Archive<R>, cancelled: &mut C) -> Result<(), CargoPrefetchError>
where
    R: io::Read,
    C: FnMut() -> bool,
{
    let mut reader = archive.into_inner();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        ensure_not_cancelled(cancelled)?;
        if reader.read(&mut buffer)? == 0 {
            break;
        }
    }
    Ok(())
}

fn drain_entry<R, C>(
    input: &mut R,
    expected_bytes: u64,
    cancelled: &mut C,
) -> Result<(), CargoPrefetchError>
where
    R: io::Read,
    C: FnMut() -> bool,
{
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        ensure_not_cancelled(cancelled)?;
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| CargoPrefetchError::InvalidCrateArchive)?)
            .ok_or(CargoPrefetchError::InvalidCrateArchive)?;
        if copied > expected_bytes {
            return Err(CargoPrefetchError::InvalidCrateArchive);
        }
    }
    if copied != expected_bytes {
        return Err(CargoPrefetchError::InvalidCrateArchive);
    }
    Ok(())
}

fn copy_archive_file<R, C>(
    input: &mut R,
    path: &Path,
    expected: CrateArchiveFile,
    cancelled: &mut C,
) -> Result<EvidenceDigest, CargoPrefetchError>
where
    R: io::Read,
    C: FnMut() -> bool,
{
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(path)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        ensure_not_cancelled(cancelled)?;
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| CargoPrefetchError::CrateArchiveChanged)?)
            .ok_or(CargoPrefetchError::CrateArchiveChanged)?;
        if copied > expected.bytes {
            return Err(CargoPrefetchError::CrateArchiveChanged);
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    if copied != expected.bytes {
        return Err(CargoPrefetchError::CrateArchiveChanged);
    }
    output.flush()?;
    output.set_permissions(fs::Permissions::from_mode(if expected.executable {
        0o700
    } else {
        0o600
    }))?;
    output.sync_all()?;
    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(EvidenceDigest::from_str(&hex_digest(&bytes))
        .expect("a SHA-256 byte array always has a valid lowercase digest encoding"))
}

#[derive(Serialize)]
struct CargoChecksumFileV1<'a> {
    files: &'a BTreeMap<String, String>,
    package: &'a str,
}

fn checksum_file_bytes(
    package: &CargoRegistryPackageV1,
    inventory: &CrateArchiveInventory,
    checksums: Option<&BTreeMap<String, String>>,
) -> Result<Vec<u8>, CargoPrefetchError> {
    let placeholder;
    let files = if let Some(checksums) = checksums {
        checksums
    } else {
        placeholder = inventory
            .files
            .keys()
            .map(|path| {
                path.to_str()
                    .ok_or(CargoPrefetchError::InvalidCratePath)
                    .map(|path| (path.to_owned(), "0".repeat(64)))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        &placeholder
    };
    Ok(serde_jcs::to_vec(&CargoChecksumFileV1 {
        files,
        package: package.checksum.as_str(),
    })?)
}

fn decode_crate_path(
    bytes: &[u8],
    expected_root: &str,
    directory_entry: bool,
) -> Result<Option<PathBuf>, CargoPrefetchError> {
    if bytes.is_empty()
        || bytes.len() > MAX_CRATE_PATH_BYTES
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
    {
        return Err(CargoPrefetchError::InvalidCratePath);
    }
    let normalized = if directory_entry {
        bytes.strip_suffix(b"/").unwrap_or(bytes)
    } else {
        if bytes.ends_with(b"/") {
            return Err(CargoPrefetchError::InvalidCratePath);
        }
        bytes
    };
    let text = std::str::from_utf8(normalized).map_err(|_| CargoPrefetchError::InvalidCratePath)?;
    let path = Path::new(text);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CargoPrefetchError::InvalidCratePath);
    }
    let mut components = path.components();
    let Some(Component::Normal(root)) = components.next() else {
        return Err(CargoPrefetchError::InvalidCratePath);
    };
    if root != expected_root {
        return Err(CargoPrefetchError::InvalidCrateRoot);
    }
    let relative = components.collect::<PathBuf>();
    if relative.as_os_str().is_empty() {
        Ok(None)
    } else {
        Ok(Some(relative))
    }
}

fn insert_parent_directories(
    path: &Path,
    directories: &mut BTreeSet<PathBuf>,
    files: &BTreeMap<PathBuf, CrateArchiveFile>,
) -> Result<(), CargoPrefetchError> {
    let mut parent = path.parent();
    while let Some(value) = parent {
        if value.as_os_str().is_empty() {
            break;
        }
        if files.contains_key(value) {
            return Err(CargoPrefetchError::InvalidCrateArchive);
        }
        directories.insert(value.to_owned());
        parent = value.parent();
    }
    Ok(())
}

fn create_directory(path: &Path) -> Result<(), CargoPrefetchError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], executable: bool) -> Result<(), CargoPrefetchError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.set_permissions(fs::Permissions::from_mode(if executable {
        0o700
    } else {
        0o600
    }))?;
    file.sync_all()?;
    Ok(())
}

fn maximum_tar_stream_bytes(
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
) -> Result<u64, CargoPrefetchError> {
    maximum_payload_inodes
        .checked_mul(TAR_STREAM_PER_INODE_OVERHEAD_BYTES)
        .and_then(|overhead| overhead.checked_add(TAR_STREAM_FIXED_OVERHEAD_BYTES))
        .and_then(|overhead| overhead.checked_add(maximum_payload_bytes))
        .ok_or(CargoPrefetchError::DependencyPayloadTooLarge)
}

fn ensure_not_cancelled<C>(cancelled: &mut C) -> Result<(), CargoPrefetchError>
where
    C: FnMut() -> bool,
{
    if cancelled() {
        Err(CargoPrefetchError::Cancelled)
    } else {
        Ok(())
    }
}

fn valid_crate_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CRATE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_crate_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CRATE_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Debug, thiserror::Error)]
pub enum CargoPrefetchError {
    #[error("Cargo.lock is not a bounded version-4 lockfile")]
    InvalidLockfile,
    #[error("Cargo.lock contains an invalid crates.io package")]
    InvalidRegistryPackage,
    #[error("Cargo.lock contains the same crates.io name and version more than once")]
    DuplicateRegistryPackage,
    #[error("Cargo.lock contains a git, alternate-registry, or unpinned package source")]
    UnsupportedPackageSource,
    #[error("Cargo.lock contains too many crates.io packages")]
    TooManyRegistryPackages,
    #[error("Cargo dependency preparation requires at least one crates.io package")]
    NoRegistryPackages,
    #[error("Cargo dependency manifest is invalid")]
    InvalidDependencyManifest,
    #[error("crate fetch failed: {0}")]
    FetchFailed(String),
    #[error("fetched crate archive does not match its Cargo.lock checksum")]
    ArchiveIntegrityMismatch,
    #[error("crate archive path is invalid")]
    InvalidCratePath,
    #[error("crate archive does not have its exact name-version root")]
    InvalidCrateRoot,
    #[error("crate archive structure is invalid")]
    InvalidCrateArchive,
    #[error("crate archive contains a link or unsupported entry")]
    UnsupportedCrateEntry,
    #[error("crate archive changed between validation and extraction")]
    CrateArchiveChanged,
    #[error("Cargo dependency payload exceeds its byte or inode boundary")]
    DependencyPayloadTooLarge,
    #[error("Cargo dependency preparation was cancelled")]
    Cancelled,
    #[error("Cargo.lock TOML failed: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Cargo dependency JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Cargo dependency filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::process::Command;
    use tempfile::TempDir;

    fn crate_archive(package: &CargoRegistryPackageV1, files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        crate_archive_with_trailing_bytes(package, files, 0)
    }

    fn crate_archive_with_trailing_bytes(
        package: &CargoRegistryPackageV1,
        files: &[(&str, &[u8], u32)],
        trailing_bytes: usize,
    ) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let root = package.vendor_directory_name();
        let mut root_header = tar::Header::new_gnu();
        root_header.set_entry_type(EntryType::Directory);
        root_header.set_mode(0o755);
        root_header.set_size(0);
        root_header.set_cksum();
        archive
            .append_data(&mut root_header, format!("{root}/"), io::empty())
            .expect("append crate root");
        for (path, bytes, mode) in files {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_mode(*mode);
            header.set_size(u64::try_from(bytes.len()).expect("file length"));
            header.set_cksum();
            archive
                .append_data(&mut header, format!("{root}/{path}"), *bytes)
                .expect("append crate file");
        }
        let mut encoder = archive.into_inner().expect("finish tar");
        encoder
            .write_all(&vec![0_u8; trailing_bytes])
            .expect("append trailing decompressed bytes");
        encoder.finish().expect("finish gzip")
    }

    fn package_for_archive(name: &str, version: &str, archive: &[u8]) -> CargoRegistryPackageV1 {
        CargoRegistryPackageV1 {
            name: name.to_owned(),
            version: version.to_owned(),
            checksum: EvidenceDigest::sha256(archive),
        }
    }

    #[test]
    fn cargo_lock_plan_accepts_only_sorted_checksummed_crates_io_packages() {
        let lock = br#"version = 4

[[package]]
name = "workspace"
version = "0.1.0"

[[package]]
name = "z-last"
version = "2.0.0"
source = "registry+https://index.crates.io/"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "a-first"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        let plan = CargoLockPlanV1::parse(lock).expect("valid lock plan");
        assert_eq!(
            plan.packages()
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a-first", "z-last"]
        );
        assert_eq!(plan.lockfile_digest(), &EvidenceDigest::sha256(lock));
    }

    #[test]
    fn repository_lockfile_is_supported_without_git_or_alternate_registry_inputs() {
        let bytes = include_bytes!("../Cargo.lock");
        let plan = CargoLockPlanV1::parse(bytes).expect("repository lockfile plan");
        assert!(plan.packages().len() > 200);
        assert_eq!(plan.lockfile_digest(), &EvidenceDigest::sha256(bytes));
    }

    #[test]
    fn cargo_lock_plan_rejects_git_alternate_and_missing_checksums() {
        for (source, checksum) in [
            ("git+https://example.invalid/repo", Some("a".repeat(64))),
            (
                "registry+https://registry.example.invalid",
                Some("a".repeat(64)),
            ),
            (CRATES_IO_GIT_INDEX, None),
        ] {
            let checksum =
                checksum.map_or_else(String::new, |value| format!("checksum = \"{value}\""));
            let lock = format!(
                "version = 4\n[[package]]\nname = \"crate\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n{checksum}\n"
            );
            assert!(matches!(
                CargoLockPlanV1::parse(lock.as_bytes()),
                Err(CargoPrefetchError::UnsupportedPackageSource)
            ));
        }
    }

    #[test]
    fn exact_archive_is_materialized_as_cargo_vendor_source() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo-crate".to_owned(),
            version: "1.2.3".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive(
            &provisional,
            &[
                ("Cargo.toml", b"[package]\nname='demo-crate'\n", 0o644),
                ("src/lib.rs", b"pub fn value() {}\n", 0o644),
            ],
        );
        let package = package_for_archive("demo-crate", "1.2.3", &archive);
        let lock = format!(
            "version = 4\n[[package]]\nname = \"{}\"\nversion = \"{}\"\nsource = \"{}\"\nchecksum = \"{}\"\n",
            package.name, package.version, CRATES_IO_GIT_INDEX, package.checksum
        );
        let plan = CargoLockPlanV1::parse(lock.as_bytes()).expect("lock plan");
        let directory = TempDir::new().expect("temporary directory");
        materialize_cargo_dependency(directory.path(), &plan, 1024 * 1024, 100, |_| {
            Ok::<_, io::Error>(archive.clone())
        })
        .expect("materialize dependency");
        let crate_root = directory.path().join("vendor/demo-crate-1.2.3");
        assert_eq!(
            fs::read(crate_root.join("src/lib.rs")).expect("vendored source"),
            b"pub fn value() {}\n"
        );
        let checksum: serde_json::Value = serde_json::from_slice(
            &fs::read(crate_root.join(CHECKSUM_FILE)).expect("checksum file"),
        )
        .expect("checksum JSON");
        assert_eq!(checksum["package"], package.checksum.as_str());
        assert_eq!(
            checksum["files"]["src/lib.rs"],
            EvidenceDigest::sha256(b"pub fn value() {}\n").as_str()
        );
    }

    #[test]
    fn generated_directory_source_is_accepted_by_cargo_offline_and_locked() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo-crate".to_owned(),
            version: "1.2.3".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive(
            &provisional,
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname = \"demo-crate\"\nversion = \"1.2.3\"\nedition = \"2024\"\n[lib]\npath = \"src/lib.rs\"\n",
                    0o644,
                ),
                ("src/lib.rs", b"pub fn value() {}\n", 0o644),
            ],
        );
        let package = package_for_archive("demo-crate", "1.2.3", &archive);
        let lock = format!(
            "version = 4\n[[package]]\nname = \"demo-crate\"\nversion = \"1.2.3\"\nsource = \"{}\"\nchecksum = \"{}\"\n",
            CRATES_IO_GIT_INDEX, package.checksum
        );
        let plan = CargoLockPlanV1::parse(lock.as_bytes()).expect("lock plan");
        let directory = TempDir::new().expect("temporary directory");
        let dependency = directory.path().join("dependency");
        fs::create_dir(&dependency).expect("create dependency root");
        materialize_cargo_dependency(&dependency, &plan, 1024 * 1024, 100, |_| {
            Ok::<_, io::Error>(archive.clone())
        })
        .expect("materialize dependency");

        let workspace = directory.path().join("workspace");
        let cargo_home = directory.path().join("cargo-home");
        fs::create_dir_all(workspace.join("src")).expect("create workspace source");
        fs::create_dir(&cargo_home).expect("create Cargo home");
        fs::write(
            workspace.join("Cargo.toml"),
            b"[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\ndemo-crate = \"=1.2.3\"\n",
        )
        .expect("write consumer manifest");
        fs::write(
            workspace.join("src/lib.rs"),
            b"pub use demo_crate::value;\n",
        )
        .expect("write consumer source");
        fs::write(
            workspace.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"consumer\"\nversion = \"0.1.0\"\ndependencies = [\n \"demo-crate\",\n]\n\n[[package]]\nname = \"demo-crate\"\nversion = \"1.2.3\"\nsource = \"{}\"\nchecksum = \"{}\"\n",
                CRATES_IO_GIT_INDEX, package.checksum
            ),
        )
        .expect("write consumer lockfile");
        let config = format!(
            "[source.crates-io]\nreplace-with = \"rdashboard_vendor\"\n[source.rdashboard_vendor]\ndirectory = \"{}\"\n[net]\noffline = true\n",
            dependency.join(CARGO_VENDOR_DIRECTORY).display()
        );
        fs::write(cargo_home.join("config.toml"), config).expect("write Cargo config");

        let output = Command::new(env!("CARGO"))
            .args(["metadata", "--offline", "--locked", "--format-version=1"])
            .current_dir(&workspace)
            .env("CARGO_HOME", &cargo_home)
            .output()
            .expect("run Cargo metadata");
        assert!(
            output.status.success(),
            "Cargo rejected generated vendor snapshot: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn materialization_rejects_checksum_escape_and_budget_overflow() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive(&provisional, &[("Cargo.toml", b"contents", 0o644)]);
        let package = CargoRegistryPackageV1 {
            checksum: EvidenceDigest::sha256("wrong"),
            ..provisional.clone()
        };
        let plan = CargoLockPlanV1 {
            lockfile_digest: EvidenceDigest::sha256("lock"),
            package_plan_digest: package_plan_digest(std::slice::from_ref(&package)).expect("plan"),
            packages: vec![package],
        };
        let directory = TempDir::new().expect("temporary directory");
        assert!(matches!(
            materialize_cargo_dependency(
                directory.path(),
                &plan,
                1024,
                100,
                |_| Ok::<_, io::Error>(archive.clone())
            ),
            Err(CargoPrefetchError::ArchiveIntegrityMismatch)
        ));

        let package = package_for_archive("demo", "1.0.0", &archive);
        let plan = CargoLockPlanV1 {
            lockfile_digest: EvidenceDigest::sha256("lock"),
            package_plan_digest: package_plan_digest(std::slice::from_ref(&package)).expect("plan"),
            packages: vec![package],
        };
        let directory = TempDir::new().expect("temporary directory");
        assert!(matches!(
            materialize_cargo_dependency(directory.path(), &plan, 4, 100, |_| Ok::<_, io::Error>(
                archive.clone()
            )),
            Err(CargoPrefetchError::DependencyPayloadTooLarge)
        ));
    }

    #[test]
    fn materialization_rejects_checksum_path_aliases() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive(
            &provisional,
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname='demo'\nversion='1.0.0'\n",
                    0o644,
                ),
                ("src\\lib.rs", b"backslash", 0o644),
                ("src/lib.rs", b"slash", 0o644),
            ],
        );
        let package = package_for_archive("demo", "1.0.0", &archive);
        let plan = CargoLockPlanV1 {
            lockfile_digest: EvidenceDigest::sha256("lock"),
            package_plan_digest: package_plan_digest(std::slice::from_ref(&package)).expect("plan"),
            packages: vec![package],
        };
        let directory = TempDir::new().expect("temporary directory");
        assert!(matches!(
            materialize_cargo_dependency(directory.path(), &plan, 1024 * 1024, 100, |_| Ok::<
                _,
                io::Error,
            >(
                archive.clone()
            )),
            Err(CargoPrefetchError::InvalidCratePath)
        ));
    }

    #[test]
    fn decompressed_tar_stream_and_inventory_are_bounded_before_publication() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive_with_trailing_bytes(
            &provisional,
            &[("Cargo.toml", b"contents", 0o644)],
            2 * 1024 * 1024,
        );
        let package = package_for_archive("demo", "1.0.0", &archive);
        let plan = CargoLockPlanV1 {
            lockfile_digest: EvidenceDigest::sha256("lock"),
            package_plan_digest: package_plan_digest(std::slice::from_ref(&package)).expect("plan"),
            packages: vec![package],
        };
        let directory = TempDir::new().expect("temporary directory");
        assert!(matches!(
            materialize_cargo_dependency(
                directory.path(),
                &plan,
                64 * 1024,
                16,
                |_| Ok::<_, io::Error>(archive.clone())
            ),
            Err(CargoPrefetchError::Io(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn cancellation_interrupts_archive_processing() {
        let provisional = CargoRegistryPackageV1 {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: EvidenceDigest::sha256([]),
        };
        let archive = crate_archive(
            &provisional,
            &[
                ("Cargo.toml", b"contents", 0o644),
                ("src/lib.rs", b"code", 0o644),
            ],
        );
        let package = package_for_archive("demo", "1.0.0", &archive);
        let plan = CargoLockPlanV1 {
            lockfile_digest: EvidenceDigest::sha256("lock"),
            package_plan_digest: package_plan_digest(std::slice::from_ref(&package)).expect("plan"),
            packages: vec![package],
        };
        let directory = TempDir::new().expect("temporary directory");
        let mut cancellation_checks = 0_u8;
        assert!(matches!(
            materialize_cargo_dependency_cancellable(
                directory.path(),
                &plan,
                1024 * 1024,
                100,
                |_| Ok::<_, io::Error>(archive.clone()),
                || {
                    cancellation_checks = cancellation_checks.saturating_add(1);
                    cancellation_checks >= 4
                }
            ),
            Err(CargoPrefetchError::Cancelled)
        ));
        assert!(
            !directory
                .path()
                .join(CARGO_DEPENDENCY_MANIFEST_FILE)
                .exists()
        );
    }
}
