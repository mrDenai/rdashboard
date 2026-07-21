use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use crate::{
    domain::{EvidenceDigest, GitCommitId},
    self_update::{InstalledSelfUpdatePolicyV1, SignedSelfReleaseV1},
};

pub const SELF_RELEASE_HANDOFF_ROOT: &str = "/var/lib/rdashboard-build/self-releases";

const MAX_HANDOFF_FILES: usize = 128;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ValidatedSelfReleaseHandoffV1 {
    pub descriptor: SignedSelfReleaseV1,
    pub descriptor_path: PathBuf,
    pub archive_path: PathBuf,
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub fn discover_newest_self_release_handoff(
    root: &Path,
    policy: &InstalledSelfUpdatePolicyV1,
    owner_uid: u32,
    owner_gid: u32,
    reader_gid: u32,
    current_sequence: u64,
    terminal_candidates: &BTreeSet<EvidenceDigest>,
    now_ms: i64,
) -> Result<Option<ValidatedSelfReleaseHandoffV1>, SelfReleaseHandoffError> {
    let mut candidates = scan_handoffs(root, policy, owner_uid, owner_gid, reader_gid, now_ms)?
        .into_iter()
        .filter(|candidate| {
            now_ms <= candidate.descriptor.expires_at_ms
                && candidate.descriptor.manifest.source_sequence > current_sequence
                && !terminal_candidates.contains(&candidate.descriptor.manifest.manifest_digest)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.descriptor
            .manifest
            .source_sequence
            .cmp(&right.descriptor.manifest.source_sequence)
            .then_with(|| {
                left.descriptor
                    .manifest
                    .manifest_digest
                    .cmp(&right.descriptor.manifest.manifest_digest)
            })
    });
    if candidates.windows(2).any(|pair| {
        pair[0].descriptor.manifest.source_sequence == pair[1].descriptor.manifest.source_sequence
            && pair[0].descriptor.manifest.manifest_digest
                != pair[1].descriptor.manifest.manifest_digest
    }) {
        return Err(SelfReleaseHandoffError::ConflictingSourceSequence);
    }
    Ok(candidates.pop())
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub fn load_exact_self_release_handoff(
    root: &Path,
    source_head: &GitCommitId,
    policy: &InstalledSelfUpdatePolicyV1,
    owner_uid: u32,
    owner_gid: u32,
    reader_gid: u32,
    now_ms: i64,
) -> Result<ValidatedSelfReleaseHandoffV1, SelfReleaseHandoffError> {
    let candidates = scan_handoffs(root, policy, owner_uid, owner_gid, reader_gid, now_ms)?;
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.descriptor.manifest.source_head == *source_head)
        .cloned()
        .ok_or(SelfReleaseHandoffError::CandidateMissing)?;
    if now_ms > candidate.descriptor.expires_at_ms {
        return Err(SelfReleaseHandoffError::CandidateExpired);
    }
    if candidates.iter().any(|other| {
        now_ms <= other.descriptor.expires_at_ms
            && other.descriptor.manifest.source_sequence
                == candidate.descriptor.manifest.source_sequence
            && other.descriptor.manifest.manifest_digest
                != candidate.descriptor.manifest.manifest_digest
    }) {
        return Err(SelfReleaseHandoffError::ConflictingSourceSequence);
    }
    Ok(candidate)
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn scan_handoffs(
    root: &Path,
    policy: &InstalledSelfUpdatePolicyV1,
    owner_uid: u32,
    owner_gid: u32,
    reader_gid: u32,
    now_ms: i64,
) -> Result<Vec<ValidatedSelfReleaseHandoffV1>, SelfReleaseHandoffError> {
    validate_handoff_root(root, owner_uid, owner_gid)?;
    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() > MAX_HANDOFF_FILES {
        return Err(SelfReleaseHandoffError::CapacityExceeded);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut candidates = Vec::new();
    for entry in entries {
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SelfReleaseHandoffError::UnsafeHandoff)?;
        if name.starts_with(".stage-") {
            validate_hidden_staging(&path, &name)?;
            continue;
        }
        let source_head =
            GitCommitId::from_str(&name).map_err(|_| SelfReleaseHandoffError::UnsafeHandoff)?;
        let directory_identity = validate_published_directory(&path, owner_uid, reader_gid)?;
        let descriptor_path = path.join("release.jcs");
        let archive_path = path.join("release.tar");
        let bytes = read_handoff_file(
            &descriptor_path,
            owner_uid,
            reader_gid,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let descriptor = SignedSelfReleaseV1::decode_canonical(&bytes)?;
        if descriptor.manifest.source_head != source_head {
            return Err(SelfReleaseHandoffError::HandoffBinding);
        }
        descriptor.verify(policy, now_ms.min(descriptor.expires_at_ms))?;
        validate_large_handoff_file(&archive_path, owner_uid, reader_gid, MAX_RELEASE_BYTES)?;
        if validate_published_directory(&path, owner_uid, reader_gid)? != directory_identity {
            return Err(SelfReleaseHandoffError::ConcurrentChange);
        }
        candidates.push(ValidatedSelfReleaseHandoffV1 {
            descriptor,
            descriptor_path,
            archive_path,
        });
    }
    Ok(candidates)
}

#[allow(clippy::similar_names)]
fn validate_handoff_root(
    root: &Path,
    root_uid: u32,
    root_gid: u32,
) -> Result<(), SelfReleaseHandoffError> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != root_uid
        || metadata.gid() != root_gid
        || metadata.permissions().mode() & 0o7777 != 0o711
    {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    Ok(())
}

fn validate_hidden_staging(path: &Path, name: &str) -> Result<(), SelfReleaseHandoffError> {
    let suffix = name
        .strip_prefix(".stage-")
        .ok_or(SelfReleaseHandoffError::UnsafeHandoff)?;
    let Some((lease, generation)) = suffix.split_once("-g") else {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    };
    if lease.len() != 32
        || !lease.bytes().all(|byte| byte.is_ascii_hexdigit())
        || generation.is_empty()
        || generation.len() > 10
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation == "0"
    {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    Ok(())
}

fn validate_published_directory(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
) -> Result<(u64, u64), SelfReleaseHandoffError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o7777 != 0o550
    {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    let names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = ["release.jcs", "release.tar"]
        .into_iter()
        .map(Into::into)
        .collect::<BTreeSet<_>>();
    if names != expected {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn read_handoff_file(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfReleaseHandoffError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o7777 != 0o440
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    let bytes = fs::read(path)?;
    let after = fs::symlink_metadata(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len())
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(SelfReleaseHandoffError::ConcurrentChange);
    }
    Ok(bytes)
}

fn validate_large_handoff_file(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    maximum_bytes: u64,
) -> Result<(), SelfReleaseHandoffError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o7777 != 0o440
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfReleaseHandoffError::UnsafeHandoff);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(SelfReleaseHandoffError::ConcurrentChange);
    }
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read).map_err(|_| SelfReleaseHandoffError::ConcurrentChange)?,
            )
            .ok_or(SelfReleaseHandoffError::ConcurrentChange)?;
        if total > metadata.len() {
            return Err(SelfReleaseHandoffError::ConcurrentChange);
        }
    }
    let after = fs::symlink_metadata(path)?;
    if total != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(SelfReleaseHandoffError::ConcurrentChange);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SelfReleaseHandoffError {
    #[error("the self-release handoff is unsafe")]
    UnsafeHandoff,
    #[error("the self-release handoff does not bind its exact source and archive")]
    HandoffBinding,
    #[error("the self-release handoff exceeded its fixed capacity")]
    CapacityExceeded,
    #[error("two self releases claim the same source sequence")]
    ConflictingSourceSequence,
    #[error("the requested exact self-release handoff does not exist")]
    CandidateMissing,
    #[error("the requested exact self-release handoff has expired")]
    CandidateExpired,
    #[error("a self-release handoff file changed while it was read")]
    ConcurrentChange,
    #[error(transparent)]
    SelfUpdate(#[from] crate::self_update::SelfUpdateError),
    #[error("self-release handoff I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
