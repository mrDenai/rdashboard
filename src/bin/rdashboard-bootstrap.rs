use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use rdashboard::{
    domain::{EvidenceDigest, GitCommitId},
    self_update::{
        InstalledSelfUpdatePolicyV1, SelfReleaseStoreV1, SelfUpdateJournalV1, SelfUpdateOutcomeV1,
        SignedSelfReleaseV1, load_installed_self_update_policy_from,
    },
    self_update_runtime::{
        InstalledSelfUpdatePlatformV1, InstalledSelfUpdateServiceRuntimeV1,
        SelfUpdateRuntimePathsV1, read_current_release,
    },
    unix_time_ms,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const POLICY_PATH: &str = "/etc/rdashboard/self-update-policy.jcs";
const HANDOFF_ROOT: &str = "/var/lib/rdashboard-build/self-releases";
const LOOP_INTERVAL: Duration = Duration::from_secs(2);
const MAX_HANDOFF_FILES: usize = 128;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_BYTES: u64 = 512 * 1024 * 1024;

fn main() -> Result<(), BootstrapError> {
    if std::env::args_os().len() != 1 {
        return Err(BootstrapError::InvalidInvocation);
    }
    init_tracing()?;
    let release_reader_gid = required_id("RDASHBOARD_SELF_RELEASE_GID")?;
    loop {
        match run_cycle(release_reader_gid) {
            Ok(CycleResult::Idle) => {}
            Ok(CycleResult::Terminal(outcome)) => {
                info!(
                    ?outcome,
                    "rdashboard self-update cycle reached a terminal state"
                );
            }
            Err(error) => {
                error!(
                    reason_code = error.reason_code(),
                    error = %error,
                    "rdashboard self-update cycle failed"
                );
            }
        }
        std::thread::sleep(LOOP_INTERVAL);
    }
}

fn run_cycle(release_reader_gid: u32) -> Result<CycleResult, BootstrapError> {
    let policy = load_installed_self_update_policy_from(Path::new(POLICY_PATH), 0)?;
    let paths = SelfUpdateRuntimePathsV1::installed();
    let journal =
        SelfUpdateJournalV1::open(rdashboard::self_update_runtime::SELF_UPDATE_JOURNAL_ROOT, 0)?;
    let active = journal.active()?;
    let candidate_digest = if let Some(active) = active {
        active.candidate_release_digest
    } else {
        let records = journal.records()?;
        let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, release_reader_gid)?;
        let current_digest = read_current_release(&paths, 0, &store)?;
        let current = store.verify_staged(&current_digest)?;
        let Some(candidate) = discover_candidate(
            Path::new(HANDOFF_ROOT),
            &policy,
            0,
            0,
            release_reader_gid,
            current.manifest.source_sequence,
            &records
                .iter()
                .map(|record| record.candidate_release_digest.clone())
                .collect(),
            unix_time_ms()?,
        )?
        else {
            return Ok(CycleResult::Idle);
        };
        let staged = store.stage(
            &candidate.descriptor_path,
            &candidate.archive_path,
            &policy,
            unix_time_ms()?,
        )?;
        staged.manifest_digest
    };

    let mut platform = InstalledSelfUpdatePlatformV1::open(
        paths,
        0,
        0,
        release_reader_gid,
        InstalledSelfUpdateServiceRuntimeV1,
    )?;
    let coordinator = rdashboard::self_update::SelfUpdateCoordinatorV1::new(journal);
    let outcome = coordinator.apply(candidate_digest, &mut platform, unix_time_ms()?)?;
    if outcome == SelfUpdateOutcomeV1::NeedsReconcile {
        warn!(
            reason_code = "self_update_needs_reconcile",
            "rdashboard self-update requires the root recovery path"
        );
    }
    Ok(CycleResult::Terminal(outcome))
}

#[derive(Debug)]
struct CandidateHandoff {
    descriptor: SignedSelfReleaseV1,
    descriptor_path: PathBuf,
    archive_path: PathBuf,
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn discover_candidate(
    root: &Path,
    policy: &InstalledSelfUpdatePolicyV1,
    owner_uid: u32,
    owner_gid: u32,
    reader_gid: u32,
    current_sequence: u64,
    terminal_candidates: &BTreeSet<EvidenceDigest>,
    now_ms: i64,
) -> Result<Option<CandidateHandoff>, BootstrapError> {
    validate_handoff_root(root, owner_uid, owner_gid)?;
    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() > MAX_HANDOFF_FILES {
        return Err(BootstrapError::HandoffCapacityExceeded);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut candidates = Vec::new();
    for entry in &entries {
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BootstrapError::UnsafeHandoff)?;
        if name.starts_with(".stage-") {
            validate_hidden_staging(&path, &name)?;
            continue;
        }
        let source_head =
            GitCommitId::from_str(&name).map_err(|_| BootstrapError::UnsafeHandoff)?;
        validate_published_directory(&path, owner_uid, reader_gid)?;
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
            return Err(BootstrapError::HandoffBinding);
        }
        if now_ms > descriptor.expires_at_ms {
            descriptor.verify(policy, descriptor.expires_at_ms)?;
        } else {
            descriptor.verify(policy, now_ms)?;
        }
        validate_large_handoff_file(&archive_path, owner_uid, reader_gid, MAX_RELEASE_BYTES)?;
        if now_ms > descriptor.expires_at_ms
            || descriptor.manifest.source_sequence <= current_sequence
            || terminal_candidates.contains(&descriptor.manifest.manifest_digest)
        {
            continue;
        }
        candidates.push(CandidateHandoff {
            descriptor,
            descriptor_path,
            archive_path,
        });
    }
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
        return Err(BootstrapError::ConflictingSourceSequence);
    }
    Ok(candidates.pop())
}

#[allow(clippy::similar_names)]
fn validate_handoff_root(
    root: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), BootstrapError> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.permissions().mode() & 0o7777 != 0o711
    {
        return Err(BootstrapError::UnsafeHandoff);
    }
    Ok(())
}

fn validate_hidden_staging(path: &Path, name: &str) -> Result<(), BootstrapError> {
    let suffix = name
        .strip_prefix(".stage-")
        .ok_or(BootstrapError::UnsafeHandoff)?;
    let Some((lease, generation)) = suffix.split_once("-g") else {
        return Err(BootstrapError::UnsafeHandoff);
    };
    if lease.len() != 32
        || !lease.bytes().all(|byte| byte.is_ascii_hexdigit())
        || generation.is_empty()
        || generation.len() > 10
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation == "0"
    {
        return Err(BootstrapError::UnsafeHandoff);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BootstrapError::UnsafeHandoff);
    }
    Ok(())
}

fn validate_published_directory(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
) -> Result<(), BootstrapError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_gid
        || metadata.permissions().mode() & 0o7777 != 0o550
    {
        return Err(BootstrapError::UnsafeHandoff);
    }
    let names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = ["release.jcs", "release.tar"]
        .into_iter()
        .map(Into::into)
        .collect::<BTreeSet<_>>();
    if names != expected {
        return Err(BootstrapError::UnsafeHandoff);
    }
    Ok(())
}

fn read_handoff_file(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, BootstrapError> {
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
        return Err(BootstrapError::UnsafeHandoff);
    }
    let bytes = fs::read(path)?;
    let after = fs::symlink_metadata(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len())
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(BootstrapError::ConcurrentChange);
    }
    Ok(bytes)
}

fn validate_large_handoff_file(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    maximum_bytes: u64,
) -> Result<(), BootstrapError> {
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
        return Err(BootstrapError::UnsafeHandoff);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(BootstrapError::ConcurrentChange);
    }
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| BootstrapError::ConcurrentChange)?)
            .ok_or(BootstrapError::ConcurrentChange)?;
        if total > metadata.len() {
            return Err(BootstrapError::ConcurrentChange);
        }
    }
    let after = fs::symlink_metadata(path)?;
    if total != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(BootstrapError::ConcurrentChange);
    }
    Ok(())
}

fn required_id(name: &'static str) -> Result<u32, BootstrapError> {
    let value = std::env::var(name).map_err(|_| BootstrapError::MissingConfiguration(name))?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| BootstrapError::InvalidConfiguration(name))?;
    if parsed == 0 || parsed == u32::MAX {
        return Err(BootstrapError::InvalidConfiguration(name));
    }
    Ok(parsed)
}

fn init_tracing() -> Result<(), BootstrapError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|_| BootstrapError::Tracing)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CycleResult {
    Idle,
    Terminal(SelfUpdateOutcomeV1),
}

#[derive(Debug, thiserror::Error)]
enum BootstrapError {
    #[error("rdashboard-bootstrap accepts no arguments")]
    InvalidInvocation,
    #[error("required self-update setting {0} is absent")]
    MissingConfiguration(&'static str),
    #[error("self-update setting {0} is invalid")]
    InvalidConfiguration(&'static str),
    #[error("the self-release handoff is unsafe")]
    UnsafeHandoff,
    #[error("the self-release handoff does not bind its exact source and archive")]
    HandoffBinding,
    #[error("the self-release handoff exceeded its fixed capacity")]
    HandoffCapacityExceeded,
    #[error("two self releases claim the same source sequence")]
    ConflictingSourceSequence,
    #[error("a self-release handoff file changed while it was read")]
    ConcurrentChange,
    #[error("self-update tracing could not be initialized")]
    Tracing,
    #[error(transparent)]
    SelfUpdate(#[from] rdashboard::self_update::SelfUpdateError),
    #[error(transparent)]
    Runtime(#[from] rdashboard::self_update_runtime::SelfUpdateRuntimeError),
    #[error("self-update time failed: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("self-update I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl BootstrapError {
    const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidInvocation => "self_update_invocation_invalid",
            Self::MissingConfiguration(_) | Self::InvalidConfiguration(_) => {
                "self_update_configuration_invalid"
            }
            Self::UnsafeHandoff | Self::HandoffBinding | Self::ConcurrentChange => {
                "self_update_handoff_invalid"
            }
            Self::HandoffCapacityExceeded => "self_update_handoff_full",
            Self::ConflictingSourceSequence => "self_update_source_conflict",
            Self::Tracing => "self_update_tracing_failed",
            Self::SelfUpdate(_) => "self_update_contract_failed",
            Self::Runtime(_) => "self_update_runtime_failed",
            Self::Time(_) => "self_update_clock_invalid",
            Self::Io(_) => "self_update_io_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use rdashboard::self_update::{
        InstalledSelfUpdatePolicyInputV1, SelfReleaseManifestInputV1, SelfReleaseSignatureInputV1,
        SelfReleaseSourceV1, SelfUpdateFilePolicyV1, build_signed_self_release,
    };
    use tempfile::tempdir;

    use super::*;

    fn digest(label: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    fn published_fixture() -> (
        tempfile::TempDir,
        InstalledSelfUpdatePolicyV1,
        u32,
        u32,
        GitCommitId,
    ) {
        let directory = tempdir().expect("temporary directory");
        let metadata = fs::symlink_metadata(directory.path()).expect("temporary metadata");
        let uid = metadata.uid();
        let gid = metadata.gid();
        let root = directory.path().join("handoff");
        fs::create_dir(&root).expect("create handoff root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o711))
            .expect("protect handoff root");
        let source_head = GitCommitId::from_str(&"a".repeat(40)).expect("source head");
        let published = root.join(source_head.as_str());
        fs::create_dir(&published).expect("create publication");
        fs::set_permissions(&published, fs::Permissions::from_mode(0o2750))
            .expect("prepare publication");
        let source = directory.path().join("rdashboardd");
        fs::write(&source, b"rdashboard binary").expect("write source binary");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755))
            .expect("protect source binary");
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let policy = InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
            key_id: "self-release-2026".to_owned(),
            key_epoch: 1,
            public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            runtime_contract_digest: digest("runtime"),
            minimum_state_schema_version: 1,
            maximum_state_schema_version: 1,
            maximum_release_bytes: 8 * 1024 * 1024,
            files: vec![SelfUpdateFilePolicyV1 {
                path: "bin/rdashboardd".to_owned(),
                mode: 0o555,
            }],
        })
        .expect("self-update policy");
        build_signed_self_release(
            &published,
            "release",
            SelfReleaseManifestInputV1 {
                source_head: source_head.clone(),
                source_sequence: 2,
                source_attestation_digest: digest("source"),
                workflow_policy_digest: digest("workflow"),
                verification_receipt_digest: digest("verification"),
                runtime_contract_digest: digest("runtime"),
                state_schema_version: 1,
            },
            vec![SelfReleaseSourceV1 {
                path: "bin/rdashboardd".to_owned(),
                source,
                executable: true,
            }],
            SelfReleaseSignatureInputV1 {
                key_id: "self-release-2026".to_owned(),
                key_epoch: 1,
                archive_digest: digest("replaced"),
                archive_bytes: 1,
                issued_at_ms: 1_000,
                expires_at_ms: 60_000,
            },
            &signing_key,
            uid,
            gid,
        )
        .expect("build publication");
        fs::set_permissions(&published, fs::Permissions::from_mode(0o550))
            .expect("publish directory");
        (directory, policy, uid, gid, source_head)
    }

    #[test]
    fn installed_paths_and_capacity_are_fixed() {
        assert_eq!(POLICY_PATH, "/etc/rdashboard/self-update-policy.jcs");
        assert_eq!(HANDOFF_ROOT, "/var/lib/rdashboard-build/self-releases");
        assert_eq!(LOOP_INTERVAL, Duration::from_secs(2));
        assert_eq!(MAX_HANDOFF_FILES, 128);
    }

    #[test]
    fn candidate_discovery_observes_only_complete_published_directories() {
        let (directory, policy, uid, gid, source_head) = published_fixture();
        let staging = directory
            .path()
            .join("handoff/.stage-0123456789abcdef0123456789abcdef-g1");
        fs::create_dir(&staging).expect("create hidden staging");
        fs::write(staging.join("partial"), b"partial").expect("write partial staging");
        let candidate = discover_candidate(
            &directory.path().join("handoff"),
            &policy,
            uid,
            gid,
            gid,
            1,
            &BTreeSet::new(),
            2_000,
        )
        .expect("discover candidate")
        .expect("candidate");
        assert_eq!(candidate.descriptor.manifest.source_head, source_head);
        assert_eq!(
            candidate.descriptor_path,
            directory
                .path()
                .join(format!("handoff/{source_head}/release.jcs"))
        );
    }

    #[test]
    fn flat_or_extra_handoff_content_is_rejected() {
        let (directory, policy, uid, gid, _) = published_fixture();
        fs::write(directory.path().join("handoff/orphan.jcs"), b"orphan").expect("write orphan");
        assert!(matches!(
            discover_candidate(
                &directory.path().join("handoff"),
                &policy,
                uid,
                gid,
                gid,
                1,
                &BTreeSet::new(),
                2_000,
            ),
            Err(BootstrapError::UnsafeHandoff)
        ));
    }
}
