use std::{ffi::OsString, path::Path, process::Command, str::FromStr as _};

use rdashboard::{
    domain::{EvidenceDigest, GitCommitId},
    self_update::{
        InstalledSelfUpdatePolicyV1, SelfReleaseStoreV1, SelfUpdateCoordinatorV1,
        SelfUpdateJournalV1, SelfUpdateOutcomeV1, SelfUpdatePhaseV1, SelfUpdateRecordV1,
        load_installed_self_update_policy_from,
    },
    self_update_handoff::{
        SELF_RELEASE_HANDOFF_ROOT, SelfReleaseHandoffError, load_exact_self_release_handoff,
    },
    self_update_recovery::{
        SelfUpdateRecoveryError, restart_exact_current_release, restore_reconciled_operation,
        resume_active_update,
    },
    self_update_runtime::{
        InstalledSelfUpdatePlatformV1, InstalledSelfUpdateServiceRuntimeV1,
        SELF_UPDATE_JOURNAL_ROOT, SYSTEMCTL_EXECUTABLE, SelfUpdateRuntimePathsV1,
        read_current_release, read_last_known_good_release,
    },
    unix_time_ms,
};
use serde::Serialize;
use uuid::Uuid;

const POLICY_PATH: &str = "/etc/rdashboard/self-update-policy.jcs";
const BOOTSTRAP_SERVICE: &str = "rdashboard-bootstrap.service";

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    match run(&arguments) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "error": error.to_string(),
                    "reason_code": error.reason_code(),
                    "status": "failed"
                })
            );
            std::process::exit(1);
        }
    }
}

fn run(arguments: &[OsString]) -> Result<String, RecoveryCliError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(RecoveryCliError::RootRequired);
    }
    let command = parse_command(arguments)?;
    ensure_bootstrap_inactive()?;
    let release_reader_gid = required_id("RDASHBOARD_SELF_RELEASE_GID")?;
    let policy = load_installed_self_update_policy_from(Path::new(POLICY_PATH), 0)?;
    let now_ms = unix_time_ms()?;

    let output = match command {
        RecoveryCommand::Inspect => inspect(release_reader_gid, &policy, now_ms)?,
        RecoveryCommand::Resume => resume(release_reader_gid, now_ms)?,
        RecoveryCommand::RestartCurrent => restart_current(release_reader_gid)?,
        RecoveryCommand::RestoreLastKnownGood(operation_id) => {
            restore_last_known_good(release_reader_gid, operation_id, now_ms)?
        }
        RecoveryCommand::Admit(source_head) => {
            admit_exact_handoff(release_reader_gid, &policy, &source_head, now_ms)?
        }
    };
    Ok(serde_json::to_string(&output)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecoveryCommand {
    Inspect,
    Resume,
    RestartCurrent,
    RestoreLastKnownGood(Uuid),
    Admit(GitCommitId),
}

fn parse_command(arguments: &[OsString]) -> Result<RecoveryCommand, RecoveryCliError> {
    let values = arguments
        .iter()
        .map(|value| value.to_str().ok_or(RecoveryCliError::InvalidInvocation))
        .collect::<Result<Vec<_>, _>>()?;
    match values.as_slice() {
        [_, "inspect"] => Ok(RecoveryCommand::Inspect),
        [_, "resume"] => Ok(RecoveryCommand::Resume),
        [_, "restart-current"] => Ok(RecoveryCommand::RestartCurrent),
        [_, "restore-lkg", operation_id] => Ok(RecoveryCommand::RestoreLastKnownGood(
            Uuid::parse_str(operation_id).map_err(|_| RecoveryCliError::InvalidInvocation)?,
        )),
        [_, "admit", source_head] => Ok(RecoveryCommand::Admit(
            GitCommitId::from_str(source_head).map_err(|_| RecoveryCliError::InvalidInvocation)?,
        )),
        _ => Err(RecoveryCliError::InvalidInvocation),
    }
}

fn ensure_bootstrap_inactive() -> Result<(), RecoveryCliError> {
    let status = Command::new(SYSTEMCTL_EXECUTABLE)
        .args(["is-active", "--quiet", BOOTSTRAP_SERVICE])
        .status()?;
    if status.success() {
        return Err(RecoveryCliError::BootstrapActive);
    }
    if status.code() != Some(3) {
        return Err(RecoveryCliError::BootstrapStateUnknown);
    }
    Ok(())
}

fn inspect(
    release_reader_gid: u32,
    policy: &InstalledSelfUpdatePolicyV1,
    now_ms: i64,
) -> Result<RecoveryOutput, RecoveryCliError> {
    let paths = SelfUpdateRuntimePathsV1::installed();
    let journal = SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    let active_operation = journal.active()?.map(|record| record.operation_id);
    let records = journal.records()?;
    let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, release_reader_gid)?;
    let current = inspect_pointer(
        read_current_release(&paths, 0, &store),
        &store,
        policy,
        now_ms,
    );
    let last_known_good = inspect_pointer(
        read_last_known_good_release(&paths, 0, &store),
        &store,
        policy,
        now_ms,
    );
    Ok(RecoveryOutput::Inspection(Box::new(RecoveryInspectionV1 {
        purpose: "rdashboard.self-update-recovery-inspection.v1",
        status: "inspected",
        policy_digest: policy.document_digest.clone(),
        active_operation,
        current,
        last_known_good,
        records,
    })))
}

fn inspect_pointer(
    digest: Result<EvidenceDigest, rdashboard::self_update_runtime::SelfUpdateRuntimeError>,
    store: &SelfReleaseStoreV1,
    policy: &InstalledSelfUpdatePolicyV1,
    now_ms: i64,
) -> PointerInspectionV1 {
    let inspected = digest.and_then(|digest| {
        let descriptor = store.verify_staged(&digest)?;
        descriptor
            .verify(policy, now_ms.min(descriptor.expires_at_ms))
            .map_err(rdashboard::self_update_runtime::SelfUpdateRuntimeError::from)?;
        Ok((digest, descriptor))
    });
    match inspected {
        Ok((digest, descriptor)) => PointerInspectionV1 {
            status: "valid",
            digest: Some(digest),
            source_head: Some(descriptor.manifest.source_head),
            source_sequence: Some(descriptor.manifest.source_sequence),
            failure: None,
        },
        Err(error) => PointerInspectionV1 {
            status: "invalid",
            digest: None,
            source_head: None,
            source_sequence: None,
            failure: Some(error.to_string()),
        },
    }
}

fn resume(release_reader_gid: u32, now_ms: i64) -> Result<RecoveryOutput, RecoveryCliError> {
    let journal = SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    let candidate = journal
        .active()?
        .ok_or(SelfUpdateRecoveryError::NoActiveOperation)?
        .candidate_release_digest;
    let mut platform = installed_platform(release_reader_gid)?;
    let outcome = resume_active_update(journal, &mut platform, now_ms)?;
    Ok(action_output(
        "resume",
        outcome_name(outcome),
        Some(candidate),
    ))
}

fn restart_current(release_reader_gid: u32) -> Result<RecoveryOutput, RecoveryCliError> {
    let journal = SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    if journal.active()?.is_some()
        || journal
            .records()?
            .iter()
            .any(|record| record.phase == SelfUpdatePhaseV1::NeedsReconcile)
    {
        return Err(RecoveryCliError::OperationRequiresRecovery);
    }
    let mut platform = installed_platform(release_reader_gid)?;
    let current = restart_exact_current_release(&mut platform)?;
    drop(journal);
    Ok(action_output("restart_current", "healthy", Some(current)))
}

fn restore_last_known_good(
    release_reader_gid: u32,
    operation_id: Uuid,
    now_ms: i64,
) -> Result<RecoveryOutput, RecoveryCliError> {
    let paths = SelfUpdateRuntimePathsV1::installed();
    let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, release_reader_gid)?;
    let last_known_good = read_last_known_good_release(&paths, 0, &store)?;
    drop(store);
    let journal = SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    let mut platform = installed_platform(release_reader_gid)?;
    let record = restore_reconciled_operation(
        &journal,
        &mut platform,
        operation_id,
        &last_known_good,
        now_ms,
    )?;
    Ok(action_output(
        "restore_lkg",
        "rolled_back",
        Some(record.previous_release_digest),
    ))
}

fn admit_exact_handoff(
    release_reader_gid: u32,
    policy: &InstalledSelfUpdatePolicyV1,
    source_head: &GitCommitId,
    now_ms: i64,
) -> Result<RecoveryOutput, RecoveryCliError> {
    let paths = SelfUpdateRuntimePathsV1::installed();
    let journal = SelfUpdateJournalV1::open(SELF_UPDATE_JOURNAL_ROOT, 0)?;
    if journal.active()?.is_some() {
        return Err(SelfUpdateRecoveryError::ActiveOperationExists.into());
    }
    let records = journal.records()?;
    if records
        .iter()
        .any(|record| record.phase == SelfUpdatePhaseV1::NeedsReconcile)
    {
        return Err(RecoveryCliError::OperationRequiresRecovery);
    }
    let store = SelfReleaseStoreV1::open(&paths.releases, 0, 0, release_reader_gid)?;
    let current_digest = read_current_release(&paths, 0, &store)?;
    let current = store.verify_staged(&current_digest)?;
    current.verify(policy, now_ms.min(current.expires_at_ms))?;
    let candidate = load_exact_self_release_handoff(
        Path::new(SELF_RELEASE_HANDOFF_ROOT),
        source_head,
        policy,
        0,
        0,
        release_reader_gid,
        now_ms,
    )?;
    if candidate.descriptor.manifest.source_sequence <= current.manifest.source_sequence
        || records.iter().any(|record| {
            record.candidate_release_digest == candidate.descriptor.manifest.manifest_digest
        })
    {
        return Err(RecoveryCliError::CandidateNotAdmissible);
    }
    let staged = store.stage(
        &candidate.descriptor_path,
        &candidate.archive_path,
        policy,
        now_ms,
    )?;
    drop(store);
    let mut platform = installed_platform(release_reader_gid)?;
    let outcome = SelfUpdateCoordinatorV1::new(journal).apply(
        staged.manifest_digest.clone(),
        &mut platform,
        now_ms,
    )?;
    Ok(action_output(
        "admit",
        outcome_name(outcome),
        Some(staged.manifest_digest),
    ))
}

fn installed_platform(
    release_reader_gid: u32,
) -> Result<InstalledSelfUpdatePlatformV1<InstalledSelfUpdateServiceRuntimeV1>, RecoveryCliError> {
    Ok(InstalledSelfUpdatePlatformV1::open(
        SelfUpdateRuntimePathsV1::installed(),
        0,
        0,
        release_reader_gid,
        InstalledSelfUpdateServiceRuntimeV1,
    )?)
}

fn action_output(
    action: &'static str,
    status: &'static str,
    release_digest: Option<EvidenceDigest>,
) -> RecoveryOutput {
    RecoveryOutput::Action(RecoveryActionV1 {
        purpose: "rdashboard.self-update-recovery-result.v1",
        action,
        status,
        release_digest,
    })
}

const fn outcome_name(outcome: SelfUpdateOutcomeV1) -> &'static str {
    match outcome {
        SelfUpdateOutcomeV1::Succeeded => "succeeded",
        SelfUpdateOutcomeV1::RolledBack => "rolled_back",
        SelfUpdateOutcomeV1::NeedsReconcile => "needs_reconcile",
    }
}

fn required_id(name: &'static str) -> Result<u32, RecoveryCliError> {
    let value = std::env::var(name).map_err(|_| RecoveryCliError::MissingConfiguration(name))?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| RecoveryCliError::InvalidConfiguration(name))?;
    if parsed == 0 || parsed == u32::MAX {
        return Err(RecoveryCliError::InvalidConfiguration(name));
    }
    Ok(parsed)
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RecoveryOutput {
    Inspection(Box<RecoveryInspectionV1>),
    Action(RecoveryActionV1),
}

#[derive(Debug, Serialize)]
struct RecoveryInspectionV1 {
    purpose: &'static str,
    status: &'static str,
    policy_digest: EvidenceDigest,
    active_operation: Option<Uuid>,
    current: PointerInspectionV1,
    last_known_good: PointerInspectionV1,
    records: Vec<SelfUpdateRecordV1>,
}

#[derive(Debug, Serialize)]
struct PointerInspectionV1 {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<EvidenceDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_head: Option<GitCommitId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<String>,
}

#[derive(Debug, Serialize)]
struct RecoveryActionV1 {
    purpose: &'static str,
    action: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_digest: Option<EvidenceDigest>,
}

#[derive(Debug, thiserror::Error)]
enum RecoveryCliError {
    #[error(
        "usage: rdashboard-recovery inspect|resume|restart-current|restore-lkg <operation-uuid>|admit <git-sha>"
    )]
    InvalidInvocation,
    #[error("rdashboard-recovery must run as root")]
    RootRequired,
    #[error("stop rdashboard-bootstrap.service before running recovery")]
    BootstrapActive,
    #[error("rdashboard-bootstrap.service state could not be proven inactive")]
    BootstrapStateUnknown,
    #[error("required self-update setting {0} is absent")]
    MissingConfiguration(&'static str),
    #[error("self-update setting {0} is invalid")]
    InvalidConfiguration(&'static str),
    #[error("the exact handoff is stale or has already been attempted")]
    CandidateNotAdmissible,
    #[error("an update record requires exact LKG recovery before current can restart")]
    OperationRequiresRecovery,
    #[error(transparent)]
    Recovery(#[from] SelfUpdateRecoveryError),
    #[error(transparent)]
    Handoff(#[from] SelfReleaseHandoffError),
    #[error(transparent)]
    SelfUpdate(#[from] rdashboard::self_update::SelfUpdateError),
    #[error(transparent)]
    Runtime(#[from] rdashboard::self_update_runtime::SelfUpdateRuntimeError),
    #[error("self-update time failed: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("self-update recovery JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("self-update recovery I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl RecoveryCliError {
    const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidInvocation => "self_update_recovery_invocation_invalid",
            Self::RootRequired => "self_update_recovery_root_required",
            Self::BootstrapActive | Self::BootstrapStateUnknown => {
                "self_update_recovery_bootstrap_not_inactive"
            }
            Self::MissingConfiguration(_) | Self::InvalidConfiguration(_) => {
                "self_update_recovery_configuration_invalid"
            }
            Self::CandidateNotAdmissible => "self_update_recovery_candidate_not_admissible",
            Self::OperationRequiresRecovery => "self_update_recovery_operation_pending",
            Self::Recovery(_) => "self_update_recovery_contract_failed",
            Self::Handoff(_) => "self_update_recovery_handoff_invalid",
            Self::SelfUpdate(_) => "self_update_recovery_self_update_failed",
            Self::Runtime(_) => "self_update_recovery_runtime_failed",
            Self::Time(_) => "self_update_recovery_clock_invalid",
            Self::Json(_) => "self_update_recovery_json_failed",
            Self::Io(_) => "self_update_recovery_io_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdashboard::self_update::VERSIONED_SELF_RELEASE_BINARIES;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn command_parser_accepts_only_fixed_actions_and_exact_identities() {
        assert_eq!(
            parse_command(&args(&["rdashboard-recovery", "inspect"])).expect("inspect command"),
            RecoveryCommand::Inspect
        );
        assert_eq!(
            parse_command(&args(&[
                "rdashboard-recovery",
                "admit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]))
            .expect("admit command"),
            RecoveryCommand::Admit(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .expect("source SHA")
            )
        );
        assert!(parse_command(&args(&["rdashboard-recovery", "admit", "/tmp/release"])).is_err());
        assert!(parse_command(&args(&["rdashboard-recovery", "shell", "id"])).is_err());
        assert!(
            parse_command(&args(&["rdashboard-recovery", "restart-current", "extra"])).is_err()
        );
    }

    #[test]
    fn recovery_kit_paths_stay_outside_the_versioned_slot() {
        assert_eq!(SYSTEMCTL_EXECUTABLE, "/usr/bin/systemctl");
        assert_eq!(POLICY_PATH, "/etc/rdashboard/self-update-policy.jcs");
        assert_eq!(BOOTSTRAP_SERVICE, "rdashboard-bootstrap.service");
        assert!(!VERSIONED_SELF_RELEASE_BINARIES.contains(&"rdashboard-recovery"));
    }
}
