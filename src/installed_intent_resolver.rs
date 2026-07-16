use std::{
    path::{Path, PathBuf},
    str::FromStr as _,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    backup::BackupProviderV1,
    backup_adapter::pipeline_runtime::{
        BACKUP_ADAPTER_CONFIG_PATH, InstalledBackupAdapterRuntimeV1,
    },
    domain::{EvidenceDigest, InstalledPolicyIdentity, OperationKind, ProjectId},
    executor_intent::ExecutorIntentIssueInputV1,
    installed_deploy::{
        DeploySourceSnapshotV1, InstalledDeployError, InstalledDeployIntentResolverV1,
    },
    mutation_admission::{
        ExecutorIntentResolverV1, IntentResolutionFailureV1, PrepareMutationIntentV1,
    },
    phase6::InstalledRimgPolicyV1,
    rimg_adapter::runtime::{
        InstalledRimgAdapterRuntimeV1, RIMG_ADAPTER_CONFIG_PATH, read_stable_private_file,
    },
};

pub const BACKUP_MUTATION_POLICY_PATH: &str =
    "/etc/rdashboard/projects/rimg/backup-mutation-policy.jcs";

const BACKUP_MUTATION_POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 32 * 1024;
const MIN_INTENT_TTL_MS: u64 = 30_000;
const MAX_INTENT_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledBackupMutationPolicyV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub backup_unit_digest: EvidenceDigest,
    pub recipient_fingerprint: EvidenceDigest,
    pub backup_staging_bytes: u64,
    pub projected_hot_store_growth_bytes: u64,
    pub intent_ttl_ms: u64,
    pub document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledBackupMutationPolicyInputV1 {
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub backup_unit_digest: EvidenceDigest,
    pub recipient_fingerprint: EvidenceDigest,
    pub backup_staging_bytes: u64,
    pub projected_hot_store_growth_bytes: u64,
    pub intent_ttl_ms: u64,
}

#[derive(Serialize)]
struct InstalledBackupMutationPolicyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    operation_kind: OperationKind,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    backup_unit_digest: &'a EvidenceDigest,
    recipient_fingerprint: &'a EvidenceDigest,
    backup_staging_bytes: u64,
    projected_hot_store_growth_bytes: u64,
    intent_ttl_ms: u64,
}

impl InstalledBackupMutationPolicyV1 {
    pub fn new(
        input: InstalledBackupMutationPolicyInputV1,
    ) -> Result<Self, InstalledIntentResolverError> {
        let mut policy = Self {
            purpose: "rdashboard.installed-backup-mutation-policy.v1".to_owned(),
            schema_version: BACKUP_MUTATION_POLICY_SCHEMA_VERSION,
            project_id: input.project_id,
            operation_kind: OperationKind::BackupOnly,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            backup_unit_digest: input.backup_unit_digest,
            recipient_fingerprint: input.recipient_fingerprint,
            backup_staging_bytes: input.backup_staging_bytes,
            projected_hot_store_growth_bytes: input.projected_hot_store_growth_bytes,
            intent_ttl_ms: input.intent_ttl_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        policy.document_digest = policy.calculate_digest()?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), InstalledIntentResolverError> {
        let rimg = ProjectId::from_str("rimg")
            .map_err(|_| InstalledIntentResolverError::InvalidInstalledPolicy)?;
        if self.purpose != "rdashboard.installed-backup-mutation-policy.v1"
            || self.schema_version != BACKUP_MUTATION_POLICY_SCHEMA_VERSION
            || self.project_id != rimg
            || self.operation_kind != OperationKind::BackupOnly
            || self.installed_policy.version == 0
            || self.backup_staging_bytes == 0
            || self.projected_hot_store_growth_bytes == 0
            || self
                .backup_staging_bytes
                .checked_add(self.projected_hot_store_growth_bytes)
                .is_none()
            || !(MIN_INTENT_TTL_MS..=MAX_INTENT_TTL_MS).contains(&self.intent_ttl_ms)
            || self.document_digest != self.calculate_digest()?
        {
            return Err(InstalledIntentResolverError::InvalidInstalledPolicy);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, InstalledIntentResolverError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledBackupMutationPolicyPayload {
                purpose: "rdashboard.installed-backup-mutation-policy.v1",
                schema_version: BACKUP_MUTATION_POLICY_SCHEMA_VERSION,
                project_id: &self.project_id,
                operation_kind: self.operation_kind,
                installed_policy: &self.installed_policy,
                installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
                backup_unit_digest: &self.backup_unit_digest,
                recipient_fingerprint: &self.recipient_fingerprint,
                backup_staging_bytes: self.backup_staging_bytes,
                projected_hot_store_growth_bytes: self.projected_hot_store_growth_bytes,
                intent_ttl_ms: self.intent_ttl_ms,
            },
        )?))
    }

    pub fn validate_installed_rimg_policy(
        &self,
        policy: &InstalledRimgPolicyV1,
    ) -> Result<(), InstalledIntentResolverError> {
        if !policy.has_valid_digest()?
            || policy.project_id() != &self.project_id
            || policy.installed_policy() != &self.installed_policy
            || policy.digest() != &self.installed_rimg_policy_digest
            || policy
                .backup_unit_by_digest(&self.backup_unit_digest)
                .is_none()
            || !policy.authorizes_backup_recipient(&self.recipient_fingerprint)
            || policy.backup_provider() != BackupProviderV1::GoogleDrive
        {
            return Err(InstalledIntentResolverError::InstalledRuntimeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct InstalledBackupIntentResolverV1 {
    policy_path: PathBuf,
    rimg_runtime_path: PathBuf,
    backup_runtime_path: PathBuf,
    required_uid: u32,
}

#[derive(Clone, Debug)]
pub struct InstalledMutationIntentResolverV1<S> {
    backup: InstalledBackupIntentResolverV1,
    deploy: InstalledDeployIntentResolverV1<S>,
}

impl InstalledMutationIntentResolverV1<crate::source_socket::SourceBrokerClientV1> {
    pub fn installed() -> Result<Self, InstalledDeployError> {
        Ok(Self {
            backup: InstalledBackupIntentResolverV1::installed(),
            deploy: InstalledDeployIntentResolverV1::installed()?,
        })
    }
}

impl<S: DeploySourceSnapshotV1> ExecutorIntentResolverV1 for InstalledMutationIntentResolverV1<S> {
    fn resolve(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<ExecutorIntentIssueInputV1, IntentResolutionFailureV1> {
        match request.operation_kind {
            OperationKind::BackupOnly => self.backup.resolve(request, now_ms),
            OperationKind::Deploy => self.deploy.resolve(request, now_ms),
            OperationKind::CodeRollback => Err(IntentResolutionFailureV1::Rejected),
        }
    }
}

impl InstalledBackupIntentResolverV1 {
    pub fn installed() -> Self {
        Self {
            policy_path: PathBuf::from(BACKUP_MUTATION_POLICY_PATH),
            rimg_runtime_path: PathBuf::from(RIMG_ADAPTER_CONFIG_PATH),
            backup_runtime_path: PathBuf::from(BACKUP_ADAPTER_CONFIG_PATH),
            required_uid: 0,
        }
    }

    #[cfg(test)]
    fn bound(
        policy_path: PathBuf,
        rimg_runtime_path: PathBuf,
        backup_runtime_path: PathBuf,
        required_uid: u32,
    ) -> Self {
        Self {
            policy_path,
            rimg_runtime_path,
            backup_runtime_path,
            required_uid,
        }
    }

    pub(crate) fn load_policy(
        &self,
    ) -> Result<InstalledBackupMutationPolicyV1, InstalledIntentResolverError> {
        let policy: InstalledBackupMutationPolicyV1 =
            load_canonical_private(&self.policy_path, self.required_uid, MAX_POLICY_BYTES)?;
        policy.validate()?;
        let rimg: InstalledRimgAdapterRuntimeV1 =
            load_canonical_private(&self.rimg_runtime_path, self.required_uid, MAX_POLICY_BYTES)?;
        let backup: InstalledBackupAdapterRuntimeV1 = load_canonical_private(
            &self.backup_runtime_path,
            self.required_uid,
            MAX_POLICY_BYTES,
        )?;
        if rimg.purpose != "rdashboard.installed-rimg-adapter-runtime.v1"
            || rimg.schema_version != 2
            || backup.purpose != "rdashboard.installed-backup-adapter-runtime.v1"
            || backup.schema_version != 1
            || backup.provider != BackupProviderV1::GoogleDrive
            || backup.provider_credential_version == 0
            || rimg.project_id != policy.project_id
            || backup.project_id != policy.project_id
            || rimg.installed_rimg_policy_digest != policy.installed_rimg_policy_digest
            || backup.installed_rimg_policy_digest != policy.installed_rimg_policy_digest
            || backup.age_recipient_fingerprint != policy.recipient_fingerprint
        {
            return Err(InstalledIntentResolverError::InstalledRuntimeMismatch);
        }
        Ok(policy)
    }
}

impl ExecutorIntentResolverV1 for InstalledBackupIntentResolverV1 {
    fn resolve(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<ExecutorIntentIssueInputV1, IntentResolutionFailureV1> {
        if now_ms < 0 {
            return Err(IntentResolutionFailureV1::TemporarilyUnavailable);
        }
        if request.operation_kind != OperationKind::BackupOnly
            || request.target_commit.is_some()
            || request.proposed_release_class.is_some()
        {
            return Err(IntentResolutionFailureV1::Rejected);
        }
        let policy = self
            .load_policy()
            .map_err(|_| IntentResolutionFailureV1::TemporarilyUnavailable)?;
        if request.project_id != policy.project_id {
            return Err(IntentResolutionFailureV1::Rejected);
        }
        let ttl = i64::try_from(policy.intent_ttl_ms)
            .map_err(|_| IntentResolutionFailureV1::TemporarilyUnavailable)?;
        let expires_at_ms = now_ms
            .checked_add(ttl)
            .ok_or(IntentResolutionFailureV1::TemporarilyUnavailable)?;
        Ok(ExecutorIntentIssueInputV1 {
            issued_at_ms: now_ms,
            not_before_ms: now_ms,
            expires_at_ms,
            intent_id: uuid::Uuid::new_v4(),
            request_id: request.idempotency_key,
            project_id: request.project_id.clone(),
            operation_kind: request.operation_kind,
            target_commit: None,
            proposed_release_class: None,
            effective_release_class: None,
            installed_policy_digest: policy.document_digest,
            source_attestation_digest: None,
            source_sequence: None,
            release_bundle_digest: None,
            build_attestation_digest: None,
            migration_id: None,
            previous_release_bundle_digest: None,
        })
    }
}

pub fn load_installed_backup_mutation_policy()
-> Result<InstalledBackupMutationPolicyV1, InstalledIntentResolverError> {
    InstalledBackupIntentResolverV1::installed().load_policy()
}

fn load_canonical_private<T: DeserializeOwned + Serialize>(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<T, InstalledIntentResolverError> {
    let bytes = read_stable_private_file(path, required_uid, maximum_bytes)?;
    let document = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&document)? != bytes {
        return Err(InstalledIntentResolverError::NoncanonicalInstalledDocument);
    }
    Ok(document)
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledIntentResolverError {
    #[error("the installed backup mutation policy is invalid")]
    InvalidInstalledPolicy,
    #[error("the installed adapter runtimes do not match the mutation policy")]
    InstalledRuntimeMismatch,
    #[error("an installed resolver document is not canonical JCS")]
    NoncanonicalInstalledDocument,
    #[error(transparent)]
    Runtime(#[from] crate::rimg_adapter::RimgAdapterError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        backup::age_x25519_recipient_fingerprint,
        backup_adapter::pipeline_runtime::InstalledBackupAdapterRuntimeV1, domain::ReleaseClass,
    };

    fn write_private(path: &Path, value: &impl Serialize) {
        fs::write(
            path,
            serde_jcs::to_vec(value).unwrap_or_else(|error| panic!("canonical document: {error}")),
        )
        .unwrap_or_else(|error| panic!("write private document: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("private permissions: {error}"));
    }

    #[test]
    fn installed_resolver_is_backup_only_policy_bound_and_reloads_each_request() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let project_id =
            ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"));
        let installed_policy = InstalledPolicyIdentity {
            digest: EvidenceDigest::sha256("installed owner policy"),
            version: 7,
        };
        let rimg_policy_digest = EvidenceDigest::sha256("installed rimg policy");
        let policy = InstalledBackupMutationPolicyV1::new(InstalledBackupMutationPolicyInputV1 {
            project_id: project_id.clone(),
            installed_policy: installed_policy.clone(),
            installed_rimg_policy_digest: rimg_policy_digest.clone(),
            backup_unit_digest: EvidenceDigest::sha256("backup unit"),
            recipient_fingerprint: age_x25519_recipient_fingerprint(&format!(
                "age1{}",
                "q".repeat(58)
            )),
            backup_staging_bytes: 4 * 1024 * 1024 * 1024,
            projected_hot_store_growth_bytes: 256 * 1024 * 1024,
            intent_ttl_ms: 60_000,
        })
        .unwrap_or_else(|error| panic!("mutation policy: {error}"));
        let rimg = InstalledRimgAdapterRuntimeV1 {
            purpose: "rdashboard.installed-rimg-adapter-runtime.v1".to_owned(),
            schema_version: 2,
            project_id: project_id.clone(),
            installed_rimg_policy_digest: rimg_policy_digest.clone(),
            rimg_cli_sha256: EvidenceDigest::sha256("rimg cli"),
            docker_cli_sha256: EvidenceDigest::sha256("docker cli"),
        };
        let recipient = format!("age1{}", "q".repeat(58));
        let mut backup = InstalledBackupAdapterRuntimeV1 {
            purpose: "rdashboard.installed-backup-adapter-runtime.v1".to_owned(),
            schema_version: 1,
            project_id: project_id.clone(),
            installed_rimg_policy_digest: rimg_policy_digest.clone(),
            age_sha256: EvidenceDigest::sha256("age"),
            age_recipient_fingerprint: age_x25519_recipient_fingerprint(&recipient),
            age_recipient: recipient,
            rclone_sha256: EvidenceDigest::sha256("rclone"),
            rclone_config_sha256: EvidenceDigest::sha256("rclone config"),
            provider: BackupProviderV1::GoogleDrive,
            provider_credential_version: 2,
            drive_remote: "drive".to_owned(),
            drive_root_folder_id: "root-folder".to_owned(),
            drive_service_account_sha256: EvidenceDigest::sha256("service account"),
        };
        let policy_path = directory.path().join("policy.jcs");
        let rimg_path = directory.path().join("rimg.jcs");
        let backup_path = directory.path().join("backup.jcs");
        write_private(&policy_path, &policy);
        write_private(&rimg_path, &rimg);
        write_private(&backup_path, &backup);
        let resolver = InstalledBackupIntentResolverV1::bound(
            policy_path,
            rimg_path,
            backup_path.clone(),
            uid,
        );
        let request = PrepareMutationIntentV1 {
            project_id,
            operation_kind: OperationKind::BackupOnly,
            target_commit: None,
            proposed_release_class: None,
            idempotency_key: uuid::Uuid::new_v4(),
        };
        let issued = resolver
            .resolve(&request, 1_000)
            .unwrap_or_else(|error| panic!("resolve backup: {error:?}"));
        assert_eq!(issued.request_id, request.idempotency_key);
        assert_eq!(issued.installed_policy_digest, policy.document_digest);
        assert_eq!(issued.expires_at_ms, 61_000);

        let mut deploy = request.clone();
        deploy.operation_kind = OperationKind::Deploy;
        deploy.target_commit = Some(
            "a".repeat(40)
                .parse()
                .unwrap_or_else(|error| panic!("commit: {error}")),
        );
        deploy.proposed_release_class = Some(ReleaseClass::CodeOnlyCompatible);
        assert_eq!(
            resolver.resolve(&deploy, 2_000),
            Err(IntentResolutionFailureV1::Rejected)
        );

        backup.installed_rimg_policy_digest = EvidenceDigest::sha256("substituted policy");
        write_private(&backup_path, &backup);
        assert_eq!(
            resolver.resolve(&request, 3_000),
            Err(IntentResolutionFailureV1::TemporarilyUnavailable)
        );
    }
}
