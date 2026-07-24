use std::{path::Path, time::Duration};

use rdashboard::{
    self_update::{
        SelfReleaseStoreV1, SelfUpdateJournalV1, SelfUpdateOutcomeV1, SelfUpdatePhaseV1,
        load_installed_self_update_policy_from,
    },
    self_update_handoff::{
        SELF_RELEASE_HANDOFF_ROOT, SelfReleaseHandoffError, discover_newest_self_release_handoff,
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
const LOOP_INTERVAL: Duration = Duration::from_secs(2);

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
        if records
            .iter()
            .any(|record| record.phase == SelfUpdatePhaseV1::NeedsReconcile)
        {
            return Err(BootstrapError::RecoveryRequired);
        }
        let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, release_reader_gid)?;
        let current_digest = read_current_release(&paths, 0, &store)?;
        let current = store.verify_staged(&current_digest)?;
        let Some(candidate) = discover_newest_self_release_handoff(
            Path::new(SELF_RELEASE_HANDOFF_ROOT),
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
    #[error(transparent)]
    Handoff(#[from] SelfReleaseHandoffError),
    #[error("self-update tracing could not be initialized")]
    Tracing,
    #[error("a self-update operation requires root recovery")]
    RecoveryRequired,
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
            Self::Handoff(SelfReleaseHandoffError::CapacityExceeded) => "self_update_handoff_full",
            Self::Handoff(SelfReleaseHandoffError::ConflictingSourceSequence) => {
                "self_update_source_conflict"
            }
            Self::Handoff(_) => "self_update_handoff_invalid",
            Self::Tracing => "self_update_tracing_failed",
            Self::RecoveryRequired => "self_update_recovery_required",
            Self::SelfUpdate(_) => "self_update_contract_failed",
            Self::Runtime(_) => "self_update_runtime_failed",
            Self::Time(_) => "self_update_clock_invalid",
            Self::Io(_) => "self_update_io_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use rdashboard::domain::{EvidenceDigest, GitCommitId};
    use rdashboard::self_update::{
        InstalledSelfUpdatePolicyInputV1, InstalledSelfUpdatePolicyV1, SelfReleaseManifestInputV1,
        SelfReleaseSignatureInputV1, SelfReleaseSourceV1, SelfUpdateFilePolicyV1,
        build_signed_self_release,
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
        let staging = root.join("fixture-staging");
        fs::create_dir(&staging).expect("create publication");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o2750))
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
        let built = build_signed_self_release(
            &staging,
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
        let published = root.join(format!(
            "release-{}",
            built.descriptor.manifest.manifest_digest.as_str()
        ));
        fs::rename(staging, &published).expect("publish manifest-bound directory");
        fs::set_permissions(&published, fs::Permissions::from_mode(0o550))
            .expect("publish directory");
        (directory, policy, uid, gid, source_head)
    }

    #[test]
    fn installed_paths_and_capacity_are_fixed() {
        assert_eq!(POLICY_PATH, "/etc/rdashboard/self-update-policy.jcs");
        assert_eq!(
            SELF_RELEASE_HANDOFF_ROOT,
            "/var/lib/rdashboard-build/self-releases"
        );
        assert_eq!(LOOP_INTERVAL, Duration::from_secs(2));
    }

    #[test]
    fn candidate_discovery_observes_only_complete_published_directories() {
        let (directory, policy, uid, gid, source_head) = published_fixture();
        let staging = directory
            .path()
            .join("handoff/.stage-0123456789abcdef0123456789abcdef-g1");
        fs::create_dir(&staging).expect("create hidden staging");
        fs::write(staging.join("partial"), b"partial").expect("write partial staging");
        let candidate = discover_newest_self_release_handoff(
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
            directory.path().join(format!(
                "handoff/release-{}/release.jcs",
                candidate.descriptor.manifest.manifest_digest.as_str()
            ))
        );
    }

    #[test]
    fn flat_or_extra_handoff_content_is_rejected() {
        let (directory, policy, uid, gid, _) = published_fixture();
        fs::write(directory.path().join("handoff/orphan.jcs"), b"orphan").expect("write orphan");
        assert!(matches!(
            discover_newest_self_release_handoff(
                &directory.path().join("handoff"),
                &policy,
                uid,
                gid,
                gid,
                1,
                &BTreeSet::new(),
                2_000,
            ),
            Err(SelfReleaseHandoffError::UnsafeHandoff)
        ));
    }
}
