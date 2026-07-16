use crate::{
    adapter_entrypoint::LoadedAdapterJobV1,
    adapter_identity::{AdapterOperationIdentityKindV1, AdapterOperationIdentityV1},
    adapter_result::{AdapterResultContractError, FixedAdapterEvidenceV1, FixedAdapterResultV1},
    backup::{
        BackupCheckEvidenceV1, BackupContractError, BackupEncryptionAlgorithmV1,
        BackupEncryptionEvidenceV1, BackupManifestInputV1, BackupManifestV1, BackupObjectV1,
        BackupSnapshotKindV1, LocalBackupEvidenceV1, OffsiteVerificationEvidenceV1,
        OffsiteVerificationInputV1, ProviderUploadReceiptInputV1, ProviderUploadReceiptV1,
    },
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1, Phase6ContractError},
    rimg_adapter::{
        RimgAdapterError, RimgObservedDocumentV1, RimgOperationalModeV1, RimgOperationalStatusV1,
    },
};

#[cfg(unix)]
pub mod pipeline_runtime;
#[cfg(unix)]
pub mod runtime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedBackupEvidenceV1 {
    pub captured_at_ms: i64,
    pub application_schema_version: String,
    pub objects: Vec<BackupObjectV1>,
    pub checks: Vec<BackupCheckEvidenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBackupMaterialV1 {
    pub plaintext_archive_digest: crate::domain::EvidenceDigest,
    pub ciphertext_digest: crate::domain::EvidenceDigest,
    pub ciphertext_size_bytes: u64,
    pub encrypted_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedBackupMaterialV1 {
    pub object_id: String,
    pub version_id: String,
    pub uploaded_at_ms: i64,
    pub provider_receipt_digest: crate::domain::EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadbackBackupMaterialV1 {
    pub size_bytes: u64,
    pub ciphertext_digest: crate::domain::EvidenceDigest,
    pub observation_digest: crate::domain::EvidenceDigest,
    pub verified_at_ms: i64,
}

pub trait BackupPipelineRuntimeV1 {
    fn encrypt(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        manifest: &BackupManifestV1,
    ) -> Result<EncryptedBackupMaterialV1, BackupAdapterError>;

    fn upload(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        local: &LocalBackupEvidenceV1,
    ) -> Result<UploadedBackupMaterialV1, BackupAdapterError>;

    fn readback(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        local: &LocalBackupEvidenceV1,
        receipt: &ProviderUploadReceiptV1,
    ) -> Result<ReadbackBackupMaterialV1, BackupAdapterError>;
}

pub trait BackupCaptureRuntimeV1 {
    fn begin_drain(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError>;

    fn operational_status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError>;

    fn capture(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        identity: &AdapterOperationIdentityV1,
        create_if_missing: bool,
    ) -> Result<CapturedBackupEvidenceV1, BackupAdapterError>;

    fn resume(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError>;

    fn wait_before_drain_poll(&mut self) -> Result<(), BackupAdapterError>;
}

pub fn execute_backup_capture_step<R: BackupCaptureRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
) -> Result<FixedAdapterResultV1, BackupAdapterError> {
    if job.request.profile != FixedAdapterProfileV1::BackupCapture {
        return Err(BackupAdapterError::InvalidExecutionBoundary);
    }
    let backup = job
        .spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let identity = job.operation_identity()?;
    let boundary = match backup.snapshot_kind {
        BackupSnapshotKindV1::Base => prepare_base_boundary(job, runtime, &identity)?,
        BackupSnapshotKindV1::Cutover => {
            if identity.kind != AdapterOperationIdentityKindV1::Fence
                || backup.fencing_epoch != Some(identity.epoch)
            {
                return Err(BackupAdapterError::OperationIdentityMismatch);
            }
            let status = runtime.operational_status()?;
            status.document.validate_fenced(&identity)?;
            BaseBoundaryStateV1::Active
        }
    };
    let captured = runtime.capture(
        &job.spec,
        &identity,
        boundary == BaseBoundaryStateV1::Active,
    )?;
    let manifest = BackupManifestV1::new(
        backup,
        BackupManifestInputV1 {
            application_schema_version: captured.application_schema_version,
            started_at_ms: captured.captured_at_ms,
            completed_at_ms: captured.captured_at_ms,
            objects: captured.objects,
            checks: captured.checks,
        },
    )?;
    if backup.snapshot_kind == BackupSnapshotKindV1::Base && boundary == BaseBoundaryStateV1::Active
    {
        runtime
            .resume(&identity)?
            .document
            .validate_resumed(&identity)?;
    }
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::BackupManifest(manifest),
        &job.prior_results,
    )?)
}

pub fn execute_backup_encrypt_step<R: BackupPipelineRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
) -> Result<FixedAdapterResultV1, BackupAdapterError> {
    if job.request.profile != FixedAdapterProfileV1::BackupEncryptAge {
        return Err(BackupAdapterError::InvalidExecutionBoundary);
    }
    let backup = job
        .spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let manifest = prior_manifest(job)?;
    let material = runtime.encrypt(&job.spec, manifest)?;
    let local = LocalBackupEvidenceV1::new(
        backup,
        manifest,
        BackupEncryptionEvidenceV1 {
            algorithm: BackupEncryptionAlgorithmV1::AgeX25519,
            authorized_spec_digest: backup.spec_digest.clone(),
            backup_id: backup.backup_id,
            manifest_digest: manifest.manifest_digest.clone(),
            plaintext_archive_digest: material.plaintext_archive_digest,
            recipient_fingerprint: backup.recipient_fingerprint.clone(),
            ciphertext_digest: material.ciphertext_digest,
            ciphertext_size_bytes: material.ciphertext_size_bytes,
            encrypted_at_ms: material.encrypted_at_ms,
        },
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::LocalBackupEvidence(local),
        &job.prior_results,
    )?)
}

pub fn execute_backup_upload_step<R: BackupPipelineRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
) -> Result<FixedAdapterResultV1, BackupAdapterError> {
    if job.request.profile != FixedAdapterProfileV1::BackupUploadGoogleDrive {
        return Err(BackupAdapterError::InvalidExecutionBoundary);
    }
    let backup = job
        .spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let local = prior_local(job)?;
    let material = runtime.upload(&job.spec, local)?;
    let receipt = ProviderUploadReceiptV1::new(
        backup,
        local,
        ProviderUploadReceiptInputV1 {
            provider: backup.provider,
            provider_credential_version: backup.provider_credential_version,
            object_id: material.object_id,
            version_id: material.version_id,
            uploaded_at_ms: material.uploaded_at_ms,
            provider_receipt_digest: material.provider_receipt_digest,
        },
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::ProviderUploadReceipt(receipt),
        &job.prior_results,
    )?)
}

pub fn execute_backup_readback_step<R: BackupPipelineRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
) -> Result<FixedAdapterResultV1, BackupAdapterError> {
    if job.request.profile != FixedAdapterProfileV1::BackupReadbackVerify {
        return Err(BackupAdapterError::InvalidExecutionBoundary);
    }
    let backup = job
        .spec
        .backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
    let local = prior_local(job)?;
    let receipt = prior_receipt(job)?;
    let material = runtime.readback(&job.spec, local, receipt)?;
    let offsite = OffsiteVerificationEvidenceV1::new(
        backup,
        local,
        receipt,
        OffsiteVerificationInputV1 {
            readback_size_bytes: material.size_bytes,
            readback_ciphertext_digest: material.ciphertext_digest,
            readback_observation_digest: material.observation_digest,
            verified_at_ms: material.verified_at_ms,
        },
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::OffsiteVerificationEvidence(offsite),
        &job.prior_results,
    )?)
}

fn prior_manifest(job: &LoadedAdapterJobV1) -> Result<&BackupManifestV1, BackupAdapterError> {
    job.prior_results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::BackupManifest(manifest) => Some(manifest),
            _ => None,
        })
        .ok_or(BackupAdapterError::MissingPriorBackupEvidence)
}

fn prior_local(job: &LoadedAdapterJobV1) -> Result<&LocalBackupEvidenceV1, BackupAdapterError> {
    job.prior_results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::LocalBackupEvidence(local) => Some(local),
            _ => None,
        })
        .ok_or(BackupAdapterError::MissingPriorBackupEvidence)
}

fn prior_receipt(job: &LoadedAdapterJobV1) -> Result<&ProviderUploadReceiptV1, BackupAdapterError> {
    job.prior_results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::ProviderUploadReceipt(receipt) => Some(receipt),
            _ => None,
        })
        .ok_or(BackupAdapterError::MissingPriorBackupEvidence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaseBoundaryStateV1 {
    Active,
    Resumed,
}

fn prepare_base_boundary<R: BackupCaptureRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    identity: &AdapterOperationIdentityV1,
) -> Result<BaseBoundaryStateV1, BackupAdapterError> {
    if identity.kind != AdapterOperationIdentityKindV1::BaseBackup {
        return Err(BackupAdapterError::OperationIdentityMismatch);
    }
    let status = runtime.operational_status()?;
    if status.document.mode == RimgOperationalModeV1::Normal {
        if status.document.validate_resumed(identity).is_ok() {
            return Ok(BaseBoundaryStateV1::Resumed);
        }
        if !status.document.allows_new_identity(identity) {
            return Err(BackupAdapterError::OperationIdentityMismatch);
        }
        runtime
            .begin_drain(identity)?
            .document
            .validate_active_identity(identity, RimgOperationalModeV1::Draining)?;
    } else {
        status
            .document
            .validate_active_identity(identity, RimgOperationalModeV1::Draining)?;
    }
    wait_until_drained(job, runtime, identity)?;
    Ok(BaseBoundaryStateV1::Active)
}

fn wait_until_drained<R: BackupCaptureRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    identity: &AdapterOperationIdentityV1,
) -> Result<(), BackupAdapterError> {
    let maximum_polls = job.request.timeout_ms.div_ceil(250).clamp(1, 7_200);
    for _ in 0..maximum_polls {
        let observed = runtime.operational_status()?;
        match observed.document.validate_drained(identity) {
            Ok(()) => return Ok(()),
            Err(RimgAdapterError::DrainIncomplete) => runtime.wait_before_drain_poll()?,
            Err(error) => return Err(error.into()),
        }
    }
    Err(BackupAdapterError::DrainDeadlineExceeded)
}

#[derive(Debug, thiserror::Error)]
pub enum BackupAdapterError {
    #[error("the fixed backup capture execution boundary is invalid")]
    InvalidExecutionBoundary,
    #[error("the authorized phase does not contain a backup specification")]
    MissingBackupAuthorization,
    #[error("the required prior backup evidence is missing from the validated result chain")]
    MissingPriorBackupEvidence,
    #[error("the adapter operation identity does not authorize this backup boundary")]
    OperationIdentityMismatch,
    #[error("the base-backup drain did not complete before the authorized deadline")]
    DrainDeadlineExceeded,
    #[error("the coherent backup snapshot is missing after rimg resumed")]
    MissingCompletedSnapshot,
    #[error("the coherent backup snapshot or its inventory is invalid")]
    InvalidSnapshot,
    #[error("the coherent backup snapshot filesystem is not stable and owner-controlled")]
    UnsafeSnapshotFilesystem,
    #[error("the coherent backup manifest exceeded its bounded contract")]
    SnapshotManifestTooLarge,
    #[error("the deterministic masters bundle is invalid or conflicts with the snapshot")]
    MastersBundleMismatch,
    #[error("the fixed backup runtime command failed: {0}")]
    CommandFailed(String),
    #[error(
        "the installed backup runtime configuration or credential does not match authorization"
    )]
    RuntimeConfigMismatch,
    #[error("the encrypted backup artifact is missing, unsafe or conflicts with replay evidence")]
    InvalidEncryptedArtifact,
    #[error("the provider upload metadata does not prove the authorized immutable object")]
    InvalidProviderEvidence,
    #[error("the provider readback did not reproduce the authorized ciphertext")]
    InvalidProviderReadback,
    #[error("the backup adapter filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the backup adapter SQLite verification failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("the rimg backup report or manifest is invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Entrypoint(#[from] crate::adapter_entrypoint::AdapterEntrypointError),
    #[error(transparent)]
    AdapterJob(#[from] crate::adapter::AdapterJobError),
    #[error(transparent)]
    Rimg(#[from] RimgAdapterError),
    #[error(transparent)]
    Phase6(#[from] Phase6ContractError),
    #[error(transparent)]
    Backup(#[from] BackupContractError),
    #[error(transparent)]
    Result(#[from] AdapterResultContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::Path,
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_entrypoint::FixedAdapterInvocationV1,
        adapter_result::PhaseExecutionProjectionV1,
        backup::BackupCheckOutcomeV1,
        domain::EvidenceDigest,
        phase6::tests::{test_base_backup_phase_spec, test_cutover_backup_phase_spec},
        store::{BackupBoundaryLease, FenceJournalState, FenceLease},
    };

    struct FakeBackupRuntime {
        statuses: VecDeque<RimgOperationalStatusV1>,
        begin_status: Option<RimgOperationalStatusV1>,
        resume_status: Option<RimgOperationalStatusV1>,
        captured: Option<CapturedBackupEvidenceV1>,
        begin_calls: usize,
        resume_calls: usize,
        capture_create_flags: Vec<bool>,
    }

    impl BackupCaptureRuntimeV1 for FakeBackupRuntime {
        fn begin_drain(
            &mut self,
            _identity: &AdapterOperationIdentityV1,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
            self.begin_calls += 1;
            observed(
                self.begin_status
                    .take()
                    .ok_or(BackupAdapterError::OperationIdentityMismatch)?,
            )
        }

        fn operational_status(
            &mut self,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
            observed(
                self.statuses
                    .pop_front()
                    .ok_or(BackupAdapterError::OperationIdentityMismatch)?,
            )
        }

        fn capture(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
            _identity: &AdapterOperationIdentityV1,
            create_if_missing: bool,
        ) -> Result<CapturedBackupEvidenceV1, BackupAdapterError> {
            self.capture_create_flags.push(create_if_missing);
            self.captured
                .take()
                .ok_or(BackupAdapterError::InvalidSnapshot)
        }

        fn resume(
            &mut self,
            _identity: &AdapterOperationIdentityV1,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, BackupAdapterError> {
            self.resume_calls += 1;
            observed(
                self.resume_status
                    .take()
                    .ok_or(BackupAdapterError::OperationIdentityMismatch)?,
            )
        }

        fn wait_before_drain_poll(&mut self) -> Result<(), BackupAdapterError> {
            Ok(())
        }
    }

    struct FakePipelineRuntime {
        encrypt_calls: usize,
        upload_calls: usize,
        readback_calls: usize,
        readback_digest: EvidenceDigest,
    }

    impl BackupPipelineRuntimeV1 for FakePipelineRuntime {
        fn encrypt(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
            _manifest: &BackupManifestV1,
        ) -> Result<EncryptedBackupMaterialV1, BackupAdapterError> {
            self.encrypt_calls += 1;
            Ok(EncryptedBackupMaterialV1 {
                plaintext_archive_digest: EvidenceDigest::sha256("plaintext archive"),
                ciphertext_digest: EvidenceDigest::sha256("ciphertext"),
                ciphertext_size_bytes: 8_192,
                encrypted_at_ms: 1_200,
            })
        }

        fn upload(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
            _local: &LocalBackupEvidenceV1,
        ) -> Result<UploadedBackupMaterialV1, BackupAdapterError> {
            self.upload_calls += 1;
            Ok(UploadedBackupMaterialV1 {
                object_id: "drive-object".to_owned(),
                version_id: "gdrive:drive-object:md5:0123456789abcdef0123456789abcdef".to_owned(),
                uploaded_at_ms: 1_300,
                provider_receipt_digest: EvidenceDigest::sha256("upload observation"),
            })
        }

        fn readback(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
            _local: &LocalBackupEvidenceV1,
            _receipt: &ProviderUploadReceiptV1,
        ) -> Result<ReadbackBackupMaterialV1, BackupAdapterError> {
            self.readback_calls += 1;
            Ok(ReadbackBackupMaterialV1 {
                size_bytes: 8_192,
                ciphertext_digest: self.readback_digest.clone(),
                observation_digest: EvidenceDigest::sha256("readback observation"),
                verified_at_ms: 1_400,
            })
        }
    }

    #[test]
    fn base_capture_drains_verifies_and_resumes_the_exact_identity() {
        let fixture = base_capture_fixture();
        let mut runtime = active_capture_runtime(&fixture);
        let result = execute_backup_capture_step(&fixture.job, &mut runtime)
            .unwrap_or_else(|error| panic!("execute base capture: {error}"));

        assert_eq!(runtime.begin_calls, 1);
        assert_eq!(runtime.resume_calls, 1);
        assert_eq!(runtime.capture_create_flags, vec![true]);
        assert!(matches!(
            result.evidence,
            FixedAdapterEvidenceV1::BackupManifest(_)
        ));
    }

    #[test]
    fn resumed_base_capture_requires_the_existing_snapshot_and_never_redrains() {
        let fixture = base_capture_fixture();
        let mut runtime = FakeBackupRuntime {
            statuses: VecDeque::from([status(
                RimgOperationalModeV1::Normal,
                &fixture.identity,
                true,
            )]),
            begin_status: None,
            resume_status: None,
            captured: Some(captured_evidence(&fixture.job.spec)),
            begin_calls: 0,
            resume_calls: 0,
            capture_create_flags: Vec::new(),
        };
        execute_backup_capture_step(&fixture.job, &mut runtime)
            .unwrap_or_else(|error| panic!("replay base capture: {error}"));

        assert_eq!(runtime.begin_calls, 0);
        assert_eq!(runtime.resume_calls, 0);
        assert_eq!(runtime.capture_create_flags, vec![false]);
    }

    #[test]
    fn invalid_snapshot_evidence_keeps_the_base_boundary_drained() {
        let fixture = base_capture_fixture();
        let mut runtime = active_capture_runtime(&fixture);
        runtime
            .captured
            .as_mut()
            .and_then(|captured| captured.objects.first_mut())
            .unwrap_or_else(|| panic!("captured database object"))
            .mode = 0o640;

        assert!(matches!(
            execute_backup_capture_step(&fixture.job, &mut runtime),
            Err(BackupAdapterError::Backup(_))
        ));
        assert_eq!(runtime.resume_calls, 0);
    }

    #[test]
    fn cutover_capture_requires_the_held_fence_and_never_resumes_it() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_cutover_backup_phase_spec();
        let lease = FenceLease {
            journal_id: 2,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: spec.fencing_epoch.unwrap_or(0),
            token: uuid::Uuid::new_v4(),
            created_at_ms: 900,
            state: FenceJournalState::Held,
            release_safe_receipt_digest: None,
        };
        let identity = AdapterOperationIdentityV1::from_fence_lease(&spec, 1, &lease)
            .unwrap_or_else(|error| panic!("fence identity: {error}"));
        let job = materialize_job(directory.path(), &spec, &identity);
        let mut runtime = FakeBackupRuntime {
            statuses: VecDeque::from([status(RimgOperationalModeV1::Fenced, &identity, true)]),
            begin_status: None,
            resume_status: None,
            captured: Some(captured_evidence(&spec)),
            begin_calls: 0,
            resume_calls: 0,
            capture_create_flags: Vec::new(),
        };
        execute_backup_capture_step(&job, &mut runtime)
            .unwrap_or_else(|error| panic!("cutover capture: {error}"));

        assert_eq!(runtime.begin_calls, 0);
        assert_eq!(runtime.resume_calls, 0);
        assert_eq!(runtime.capture_create_flags, vec![true]);
    }

    #[test]
    fn base_pipeline_requires_real_encrypt_upload_and_independent_matching_readback() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_base_backup_phase_spec();
        let backup = spec
            .backup
            .as_ref()
            .unwrap_or_else(|| panic!("backup authorization"));
        let manifest = BackupManifestV1::new(
            backup,
            BackupManifestInputV1 {
                application_schema_version: "4".to_owned(),
                started_at_ms: 1_100,
                completed_at_ms: 1_100,
                objects: captured_evidence(&spec).objects,
                checks: captured_evidence(&spec).checks,
            },
        )
        .unwrap_or_else(|error| panic!("manifest: {error}"));
        let manifest_result = FixedAdapterResultV1::new(
            &spec,
            1,
            FixedAdapterEvidenceV1::BackupManifest(manifest),
            &[],
        )
        .unwrap_or_else(|error| panic!("manifest result: {error}"));
        let mut runtime = FakePipelineRuntime {
            encrypt_calls: 0,
            upload_calls: 0,
            readback_calls: 0,
            readback_digest: EvidenceDigest::sha256("ciphertext"),
        };

        let encrypt_job = materialize_pipeline_job(
            directory.path(),
            &spec,
            2,
            std::slice::from_ref(&manifest_result),
        );
        let local_result = execute_backup_encrypt_step(&encrypt_job, &mut runtime)
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let upload_job = materialize_pipeline_job(
            directory.path(),
            &spec,
            3,
            &[manifest_result.clone(), local_result.clone()],
        );
        let upload_result = execute_backup_upload_step(&upload_job, &mut runtime)
            .unwrap_or_else(|error| panic!("upload: {error}"));
        let readback_job = materialize_pipeline_job(
            directory.path(),
            &spec,
            4,
            &[
                manifest_result.clone(),
                local_result.clone(),
                upload_result.clone(),
            ],
        );
        let readback_result = execute_backup_readback_step(&readback_job, &mut runtime)
            .unwrap_or_else(|error| panic!("readback: {error}"));
        let results = [
            manifest_result,
            local_result,
            upload_result,
            readback_result,
        ];
        PhaseExecutionProjectionV1::from_results(&spec, &results)
            .unwrap_or_else(|error| panic!("complete projection: {error}"));
        assert_eq!(
            (
                runtime.encrypt_calls,
                runtime.upload_calls,
                runtime.readback_calls
            ),
            (1, 1, 1)
        );

        runtime.readback_digest = EvidenceDigest::sha256("substituted ciphertext");
        assert!(matches!(
            execute_backup_readback_step(&readback_job, &mut runtime),
            Err(BackupAdapterError::Backup(_))
        ));
    }

    struct BaseCaptureFixture {
        _directory: tempfile::TempDir,
        job: LoadedAdapterJobV1,
        identity: AdapterOperationIdentityV1,
    }

    fn base_capture_fixture() -> BaseCaptureFixture {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_base_backup_phase_spec();
        let lease = BackupBoundaryLease {
            journal_id: 1,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: 7,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 900,
        };
        let identity = AdapterOperationIdentityV1::from_backup_boundary(&spec, 1, &lease)
            .unwrap_or_else(|error| panic!("backup identity: {error}"));
        let job = materialize_job(directory.path(), &spec, &identity);
        BaseCaptureFixture {
            _directory: directory,
            job,
            identity,
        }
    }

    fn materialize_job(
        root: &Path,
        spec: &AuthorizedPhaseSpecV1,
        identity: &AdapterOperationIdentityV1,
    ) -> LoadedAdapterJobV1 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job permissions: {error}"));
        let inputs = root.join("inputs");
        fs::create_dir(&inputs).unwrap_or_else(|error| panic!("inputs: {error}"));
        let invocation = FixedAdapterInvocationV1 {
            subcommand: "capture-v1".to_owned(),
            spec_path: root.join("spec.jcs"),
            request_path: root.join("request.jcs"),
            result_path: root.join("result.jcs"),
            inputs_path: inputs,
            operation_identity_path: root.join("operation-identity.jcs"),
        };
        write_private(
            &invocation.spec_path,
            &spec
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("spec bytes: {error}")),
        );
        write_private(
            &invocation.request_path,
            &spec
                .fixed_adapter_request(1)
                .and_then(|request| request.canonical_bytes())
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        write_private(
            &invocation.operation_identity_path,
            &identity
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("identity bytes: {error}")),
        );
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| panic!("job metadata: {error}"))
            .uid();
        LoadedAdapterJobV1::load(&invocation, FixedAdapterProfileV1::BackupCapture, uid)
            .unwrap_or_else(|error| panic!("load capture job: {error}"))
    }

    fn materialize_pipeline_job(
        root: &Path,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        prior_results: &[FixedAdapterResultV1],
    ) -> LoadedAdapterJobV1 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job permissions: {error}"));
        let job = root.join(format!("job-{sequence}"));
        fs::create_dir(&job).unwrap_or_else(|error| panic!("job directory: {error}"));
        fs::set_permissions(&job, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job directory permissions: {error}"));
        let inputs = job.join("inputs");
        fs::create_dir(&inputs).unwrap_or_else(|error| panic!("inputs: {error}"));
        fs::set_permissions(&inputs, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("input permissions: {error}"));
        for result in prior_results {
            let step = inputs.join(format!("step-{:05}", result.sequence));
            fs::create_dir(&step).unwrap_or_else(|error| panic!("input step: {error}"));
            fs::set_permissions(&step, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("input step permissions: {error}"));
            write_private(
                &step.join("result.jcs"),
                &result
                    .canonical_bytes()
                    .unwrap_or_else(|error| panic!("prior result bytes: {error}")),
            );
        }
        let profile = spec
            .fixed_adapter_request(sequence)
            .unwrap_or_else(|error| panic!("request: {error}"))
            .profile;
        let invocation = FixedAdapterInvocationV1 {
            subcommand: "pipeline-v1".to_owned(),
            spec_path: job.join("spec.jcs"),
            request_path: job.join("request.jcs"),
            result_path: job.join("result.jcs"),
            inputs_path: inputs,
            operation_identity_path: job.join("operation-identity.jcs"),
        };
        write_private(
            &invocation.spec_path,
            &spec
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("spec bytes: {error}")),
        );
        write_private(
            &invocation.request_path,
            &spec
                .fixed_adapter_request(sequence)
                .and_then(|request| request.canonical_bytes())
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| panic!("job metadata: {error}"))
            .uid();
        LoadedAdapterJobV1::load(&invocation, profile, uid)
            .unwrap_or_else(|error| panic!("load pipeline job: {error}"))
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write fixture: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("fixture permissions: {error}"));
    }

    fn active_capture_runtime(fixture: &BaseCaptureFixture) -> FakeBackupRuntime {
        FakeBackupRuntime {
            statuses: VecDeque::from([
                status(RimgOperationalModeV1::Normal, &fixture.identity, false),
                status(RimgOperationalModeV1::Draining, &fixture.identity, true),
            ]),
            begin_status: Some(status(
                RimgOperationalModeV1::Draining,
                &fixture.identity,
                false,
            )),
            resume_status: Some(status(
                RimgOperationalModeV1::Normal,
                &fixture.identity,
                true,
            )),
            captured: Some(captured_evidence(&fixture.job.spec)),
            begin_calls: 0,
            resume_calls: 0,
            capture_create_flags: Vec::new(),
        }
    }

    fn captured_evidence(spec: &AuthorizedPhaseSpecV1) -> CapturedBackupEvidenceV1 {
        let backup = spec
            .backup
            .as_ref()
            .unwrap_or_else(|| panic!("backup authorization"));
        let database_digest = EvidenceDigest::sha256("database");
        let objects = backup
            .unit
            .expected_objects
            .iter()
            .map(|expected| BackupObjectV1 {
                path: expected.path.clone(),
                kind: expected.kind,
                size_bytes: 100,
                sha256: if expected.kind == crate::backup::BackupObjectKindV1::SqliteDatabase {
                    database_digest.clone()
                } else {
                    EvidenceDigest::sha256("masters")
                },
                uid: expected.uid,
                gid: expected.gid,
                mode: expected.mode,
                hard_link_count: 1,
            })
            .collect();
        let checks = backup
            .unit
            .required_checks
            .iter()
            .map(|check| BackupCheckEvidenceV1 {
                name: check.name.clone(),
                kind: check.kind,
                definition_digest: check.definition_digest.clone(),
                checked_object_digest: database_digest.clone(),
                outcome: BackupCheckOutcomeV1::Passed,
                observation_digest: EvidenceDigest::sha256(check.name.as_bytes()),
            })
            .collect();
        CapturedBackupEvidenceV1 {
            captured_at_ms: 1_100,
            application_schema_version: "4".to_owned(),
            objects,
            checks,
        }
    }

    fn status(
        mode: RimgOperationalModeV1,
        identity: &AdapterOperationIdentityV1,
        completed: bool,
    ) -> RimgOperationalStatusV1 {
        let active = matches!(
            mode,
            RimgOperationalModeV1::Draining | RimgOperationalModeV1::Fenced
        );
        RimgOperationalStatusV1 {
            schema_version: 1,
            mode,
            last_epoch: if completed || active {
                identity.epoch
            } else {
                0
            },
            last_token: (completed || active).then_some(identity.token),
            active_epoch: active.then_some(identity.epoch),
            active_token: active.then_some(identity.token),
            intake_open: !active,
            workers_drained: active && completed,
            active_write_leases: 0,
            processing_jobs: 0,
            delivering_webhooks: 0,
            updated_at: 1,
        }
    }

    fn observed<T: serde::Serialize>(
        document: T,
    ) -> Result<RimgObservedDocumentV1<T>, BackupAdapterError> {
        Ok(RimgObservedDocumentV1::from_document(document)?)
    }
}
