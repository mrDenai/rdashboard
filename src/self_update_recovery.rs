use uuid::Uuid;

use crate::{
    domain::EvidenceDigest,
    self_update::{
        SelfUpdateCoordinatorV1, SelfUpdateError, SelfUpdateJournalV1, SelfUpdateOutcomeV1,
        SelfUpdatePhaseV1, SelfUpdatePlatformFailureV1, SelfUpdatePlatformV1, SelfUpdateRecordV1,
    },
};

pub fn resume_active_update<P: SelfUpdatePlatformV1>(
    journal: SelfUpdateJournalV1,
    platform: &mut P,
    now_ms: i64,
) -> Result<SelfUpdateOutcomeV1, SelfUpdateRecoveryError> {
    let candidate = journal
        .active()?
        .ok_or(SelfUpdateRecoveryError::NoActiveOperation)?
        .candidate_release_digest;
    Ok(SelfUpdateCoordinatorV1::new(journal).apply(candidate, platform, now_ms)?)
}

pub fn restore_reconciled_operation<P: SelfUpdatePlatformV1>(
    journal: &SelfUpdateJournalV1,
    platform: &mut P,
    operation_id: Uuid,
    last_known_good: &EvidenceDigest,
    now_ms: i64,
) -> Result<SelfUpdateRecordV1, SelfUpdateRecoveryError> {
    if journal.active()?.is_some() {
        return Err(SelfUpdateRecoveryError::ActiveOperationExists);
    }
    let record = journal
        .records()?
        .into_iter()
        .find(|record| record.operation_id == operation_id)
        .ok_or(SelfUpdateRecoveryError::OperationMissing)?;
    let backup = record
        .backup_receipt_digest
        .as_ref()
        .ok_or(SelfUpdateRecoveryError::BackupUnavailable)?;
    if record.phase != SelfUpdatePhaseV1::NeedsReconcile
        || record.previous_release_digest != *last_known_good
    {
        return Err(SelfUpdateRecoveryError::OperationNotRecoverable);
    }

    platform.restore_release(last_known_good, backup)?;
    platform.start_release(last_known_good)?;
    if !platform.release_is_healthy(last_known_good)? {
        return Err(SelfUpdateRecoveryError::RestoredReleaseUnhealthy);
    }
    Ok(journal.mark_recovered_rollback(&record, now_ms)?)
}

pub fn restart_exact_current_release<P: SelfUpdatePlatformV1>(
    platform: &mut P,
) -> Result<EvidenceDigest, SelfUpdateRecoveryError> {
    let current = platform.active_release()?;
    platform.activate_release(&current)?;
    platform.start_release(&current)?;
    if !platform.release_is_healthy(&current)? {
        return Err(SelfUpdateRecoveryError::CurrentReleaseUnhealthy);
    }
    Ok(current)
}

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateRecoveryError {
    #[error("there is no active self-update operation to resume")]
    NoActiveOperation,
    #[error("an active self-update operation must be resumed before recovery")]
    ActiveOperationExists,
    #[error("the requested self-update operation does not exist")]
    OperationMissing,
    #[error("the requested self-update operation has no verified state backup")]
    BackupUnavailable,
    #[error("the requested self-update operation cannot be restored to exact last-known-good")]
    OperationNotRecoverable,
    #[error("the restored last-known-good release is unhealthy")]
    RestoredReleaseUnhealthy,
    #[error("the exact current release is unhealthy after restart")]
    CurrentReleaseUnhealthy,
    #[error(transparent)]
    Platform(#[from] SelfUpdatePlatformFailureV1),
    #[error(transparent)]
    SelfUpdate(#[from] SelfUpdateError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;

    fn digest(value: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(value)
    }

    fn journal_fixture(directory: &TempDir) -> SelfUpdateJournalV1 {
        let root = directory.path().join("journal");
        std::fs::create_dir(&root).expect("create journal");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("protect journal");
        let uid = std::fs::symlink_metadata(&root)
            .expect("journal metadata")
            .uid();
        SelfUpdateJournalV1::open(root, uid).expect("open journal")
    }

    struct FakePlatform {
        active: EvidenceDigest,
        healthy: bool,
        actions: Vec<&'static str>,
    }

    impl SelfUpdatePlatformV1 for FakePlatform {
        fn active_release(&mut self) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
            Ok(self.active.clone())
        }

        fn backup_state(
            &mut self,
            _operation_id: Uuid,
            _candidate_release_digest: &EvidenceDigest,
        ) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
            self.actions.push("backup");
            Ok(digest("backup"))
        }

        fn activate_release(
            &mut self,
            candidate_release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            self.actions.push("activate");
            self.active = candidate_release_digest.clone();
            Ok(())
        }

        fn start_release(
            &mut self,
            release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            assert_eq!(&self.active, release_digest);
            self.actions.push("start");
            Ok(())
        }

        fn release_is_healthy(
            &mut self,
            release_digest: &EvidenceDigest,
        ) -> Result<bool, SelfUpdatePlatformFailureV1> {
            assert_eq!(&self.active, release_digest);
            self.actions.push("health");
            Ok(self.healthy)
        }

        fn commit_release(
            &mut self,
            _candidate_release_digest: &EvidenceDigest,
            _previous_release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            self.actions.push("commit");
            Ok(())
        }

        fn restore_release(
            &mut self,
            previous_release_digest: &EvidenceDigest,
            backup_receipt_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            assert_eq!(backup_receipt_digest, &digest("backup"));
            self.actions.push("restore");
            self.active = previous_release_digest.clone();
            Ok(())
        }
    }

    fn reconcile_record(journal: &SelfUpdateJournalV1) -> SelfUpdateRecordV1 {
        let record = journal
            .begin(digest("candidate"), digest("previous"), 1_000)
            .expect("begin update");
        journal
            .transition(
                &record,
                SelfUpdatePhaseV1::NeedsReconcile,
                Some(digest("backup")),
                Some("active_release_changed"),
                1_001,
            )
            .expect("require recovery")
    }

    #[test]
    fn exact_lkg_restore_is_idempotent_and_closes_the_reconcile_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let record = reconcile_record(&journal);
        let mut platform = FakePlatform {
            active: digest("unknown"),
            healthy: true,
            actions: Vec::new(),
        };
        let recovered = restore_reconciled_operation(
            &journal,
            &mut platform,
            record.operation_id,
            &digest("previous"),
            1_002,
        )
        .expect("restore exact LKG");
        assert_eq!(recovered.phase, SelfUpdatePhaseV1::RolledBack);
        assert_eq!(platform.actions, ["restore", "start", "health"]);
        assert!(journal.active().expect("active record").is_none());
    }

    #[test]
    fn recovery_refuses_a_release_other_than_the_records_exact_lkg() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let record = reconcile_record(&journal);
        let mut platform = FakePlatform {
            active: digest("unknown"),
            healthy: true,
            actions: Vec::new(),
        };
        assert!(matches!(
            restore_reconciled_operation(
                &journal,
                &mut platform,
                record.operation_id,
                &digest("different"),
                1_002,
            ),
            Err(SelfUpdateRecoveryError::OperationNotRecoverable)
        ));
        assert!(platform.actions.is_empty());
    }

    #[test]
    fn current_restart_reuses_only_the_verified_active_digest() {
        let mut platform = FakePlatform {
            active: digest("current"),
            healthy: true,
            actions: Vec::new(),
        };
        assert_eq!(
            restart_exact_current_release(&mut platform).expect("restart current"),
            digest("current")
        );
        assert_eq!(platform.actions, ["activate", "start", "health"]);
    }
}
