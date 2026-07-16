use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    build::{ReleaseBundleReader, ReleaseBundleStore, ReleaseBundleV1},
    build_attestation::{BuildReleaseAttestationError, BuildReleaseAttestationV1},
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, OperationKind, ProjectId,
        ReleaseClass,
    },
    executor_intent::ExecutorIntentIssueInputV1,
    installed_policy::{InstalledPolicyLoadError, load_installed_rimg_policy_from},
    installed_source::{InstalledSourceError, load_installed_source_config_from},
    mutation_admission::{
        ExecutorIntentResolverV1, IntentResolutionFailureV1, PrepareMutationIntentV1,
    },
    oci_handoff::{
        BUILD_OCI_ARCHIVE_ROOT, OciArchiveReaderV1, ROOT_OCI_ARCHIVE_ROOT,
        promote_oci_archive_private,
    },
    phase6::{InstalledRimgPolicyV1, InstalledSchemaTransitionV1},
    rimg_adapter::runtime::{read_stable_private_file, validate_private_directory},
    source::{SourceGateError, SourceSnapshot},
    source_socket::{SourceBrokerClientV1, SourceSnapshotReaderV1},
};

pub const DEPLOY_MUTATION_POLICY_PATH: &str =
    "/etc/rdashboard/projects/rimg/deploy-mutation-policy.jcs";
pub const BUILD_RELEASE_BUNDLE_ROOT: &str = "/var/lib/rdashboard-build/release-bundles";
pub const BUILD_RELEASE_ATTESTATION_ROOT: &str = "/var/lib/rdashboard-build/attestations";
pub const ROOT_RELEASE_BUNDLE_ROOT: &str = "/var/lib/rdashboard-executor/release-bundles";
pub const ROOT_RELEASE_STATE_PATH: &str = "/var/lib/rdashboard-executor/releases/rimg.jcs";

const DEPLOY_MUTATION_POLICY_SCHEMA_VERSION: u16 = 2;
const RELEASE_STATE_SCHEMA_VERSION: u16 = 1;
const MAX_DOCUMENT_BYTES: u64 = 256 * 1024;
const MIN_INTENT_TTL_MS: u64 = 30_000;
const MAX_INTENT_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledDeployMutationPolicyV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub build_uid: u32,
    pub build_reader_gid: u32,
    pub build_key_id: String,
    pub build_key_epoch: u64,
    pub build_public_key: String,
    pub chronyc_sha256: EvidenceDigest,
    pub backup_staging_bytes: u64,
    pub build_peak_bytes: u64,
    pub registry_peak_bytes: u64,
    pub last_known_good_bytes: u64,
    pub projected_hot_store_growth_bytes: u64,
    pub intent_ttl_ms: u64,
    pub document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledDeployMutationPolicyInputV1 {
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub build_uid: u32,
    pub build_reader_gid: u32,
    pub build_key_id: String,
    pub build_key_epoch: u64,
    pub build_public_key: String,
    pub chronyc_sha256: EvidenceDigest,
    pub backup_staging_bytes: u64,
    pub build_peak_bytes: u64,
    pub registry_peak_bytes: u64,
    pub last_known_good_bytes: u64,
    pub projected_hot_store_growth_bytes: u64,
    pub intent_ttl_ms: u64,
}

#[derive(Serialize)]
struct InstalledDeployMutationPolicyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    build_uid: u32,
    build_reader_gid: u32,
    build_key_id: &'a str,
    build_key_epoch: u64,
    build_public_key: &'a str,
    chronyc_sha256: &'a EvidenceDigest,
    backup_staging_bytes: u64,
    build_peak_bytes: u64,
    registry_peak_bytes: u64,
    last_known_good_bytes: u64,
    projected_hot_store_growth_bytes: u64,
    intent_ttl_ms: u64,
}

impl InstalledDeployMutationPolicyV1 {
    pub fn new(input: InstalledDeployMutationPolicyInputV1) -> Result<Self, InstalledDeployError> {
        let mut policy = Self {
            purpose: "rdashboard.installed-deploy-mutation-policy.v1".to_owned(),
            schema_version: DEPLOY_MUTATION_POLICY_SCHEMA_VERSION,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            build_uid: input.build_uid,
            build_reader_gid: input.build_reader_gid,
            build_key_id: input.build_key_id,
            build_key_epoch: input.build_key_epoch,
            build_public_key: input.build_public_key,
            chronyc_sha256: input.chronyc_sha256,
            backup_staging_bytes: input.backup_staging_bytes,
            build_peak_bytes: input.build_peak_bytes,
            registry_peak_bytes: input.registry_peak_bytes,
            last_known_good_bytes: input.last_known_good_bytes,
            projected_hot_store_growth_bytes: input.projected_hot_store_growth_bytes,
            intent_ttl_ms: input.intent_ttl_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        policy.document_digest = policy.calculate_digest()?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), InstalledDeployError> {
        let rimg = ProjectId::from_str("rimg").map_err(|_| InstalledDeployError::InvalidPolicy)?;
        if self.purpose != "rdashboard.installed-deploy-mutation-policy.v1"
            || self.schema_version != DEPLOY_MUTATION_POLICY_SCHEMA_VERSION
            || self.project_id != rimg
            || self.installed_policy.version == 0
            || self.build_uid == 0
            || self.build_uid == u32::MAX
            || self.build_reader_gid == 0
            || self.build_reader_gid == u32::MAX
            || !valid_key_id(&self.build_key_id)
            || self.build_key_epoch == 0
            || self.build_key_epoch > i64::MAX.unsigned_abs()
            || self.backup_staging_bytes == 0
            || self.build_peak_bytes == 0
            || self.registry_peak_bytes == 0
            || self.last_known_good_bytes == 0
            || self.projected_hot_store_growth_bytes == 0
            || self
                .backup_staging_bytes
                .checked_add(self.build_peak_bytes)
                .and_then(|value| value.checked_add(self.registry_peak_bytes))
                .and_then(|value| value.checked_add(self.last_known_good_bytes))
                .and_then(|value| value.checked_add(self.projected_hot_store_growth_bytes))
                .is_none()
            || !(MIN_INTENT_TTL_MS..=MAX_INTENT_TTL_MS).contains(&self.intent_ttl_ms)
            || decode_public_key(&self.build_public_key).is_err()
            || self.document_digest != self.calculate_digest()?
        {
            return Err(InstalledDeployError::InvalidPolicy);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, InstalledDeployError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledDeployMutationPolicyPayload {
                purpose: "rdashboard.installed-deploy-mutation-policy.v1",
                schema_version: DEPLOY_MUTATION_POLICY_SCHEMA_VERSION,
                project_id: &self.project_id,
                installed_policy: &self.installed_policy,
                installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
                build_uid: self.build_uid,
                build_reader_gid: self.build_reader_gid,
                build_key_id: &self.build_key_id,
                build_key_epoch: self.build_key_epoch,
                build_public_key: &self.build_public_key,
                chronyc_sha256: &self.chronyc_sha256,
                backup_staging_bytes: self.backup_staging_bytes,
                build_peak_bytes: self.build_peak_bytes,
                registry_peak_bytes: self.registry_peak_bytes,
                last_known_good_bytes: self.last_known_good_bytes,
                projected_hot_store_growth_bytes: self.projected_hot_store_growth_bytes,
                intent_ttl_ms: self.intent_ttl_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledReleaseStateV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub generation: u64,
    pub current_release_bundle_digest: Option<EvidenceDigest>,
    pub last_known_good_release_bundle_digest: Option<EvidenceDigest>,
    pub updated_at_ms: i64,
    pub document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledReleaseStateInputV1 {
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub generation: u64,
    pub current_release_bundle_digest: Option<EvidenceDigest>,
    pub last_known_good_release_bundle_digest: Option<EvidenceDigest>,
    pub updated_at_ms: i64,
}

#[derive(Serialize)]
struct InstalledReleaseStatePayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    generation: u64,
    current_release_bundle_digest: &'a Option<EvidenceDigest>,
    last_known_good_release_bundle_digest: &'a Option<EvidenceDigest>,
    updated_at_ms: i64,
}

impl InstalledReleaseStateV1 {
    pub fn new(input: InstalledReleaseStateInputV1) -> Result<Self, InstalledDeployError> {
        let mut state = Self {
            purpose: "rdashboard.installed-release-state.v1".to_owned(),
            schema_version: RELEASE_STATE_SCHEMA_VERSION,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            generation: input.generation,
            current_release_bundle_digest: input.current_release_bundle_digest,
            last_known_good_release_bundle_digest: input.last_known_good_release_bundle_digest,
            updated_at_ms: input.updated_at_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        state.document_digest = state.calculate_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), InstalledDeployError> {
        if self.purpose != "rdashboard.installed-release-state.v1"
            || self.schema_version != RELEASE_STATE_SCHEMA_VERSION
            || self.installed_policy.version == 0
            || self.generation == 0
            || self.updated_at_ms < 0
            || self.current_release_bundle_digest.is_none()
                && self.last_known_good_release_bundle_digest.is_some()
            || self.current_release_bundle_digest == self.last_known_good_release_bundle_digest
                && self.current_release_bundle_digest.is_some()
            || self.document_digest != self.calculate_digest()?
        {
            return Err(InstalledDeployError::InvalidReleaseState);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, InstalledDeployError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledReleaseStatePayload {
                purpose: "rdashboard.installed-release-state.v1",
                schema_version: RELEASE_STATE_SCHEMA_VERSION,
                project_id: &self.project_id,
                installed_policy: &self.installed_policy,
                installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
                generation: self.generation,
                current_release_bundle_digest: &self.current_release_bundle_digest,
                last_known_good_release_bundle_digest: &self.last_known_good_release_bundle_digest,
                updated_at_ms: self.updated_at_ms,
            },
        )?))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InstalledDeployError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }
}

pub trait DeploySourceSnapshotV1: fmt::Debug + Send + Sync + 'static {
    fn snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError>;
}

impl DeploySourceSnapshotV1 for SourceBrokerClientV1 {
    fn snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError> {
        self.source_snapshot(project_id)
    }
}

#[derive(Clone, Debug)]
pub struct InstalledDeployIntentResolverV1<S> {
    source: S,
    deploy_policy_path: PathBuf,
    installed_rimg_policy_path: PathBuf,
    installed_source_config_path: PathBuf,
    build_release_bundle_root: PathBuf,
    build_release_attestation_root: PathBuf,
    build_oci_archive_root: PathBuf,
    root_release_bundle_root: PathBuf,
    root_oci_archive_root: PathBuf,
    root_release_state_path: PathBuf,
    required_uid: u32,
}

impl InstalledDeployIntentResolverV1<SourceBrokerClientV1> {
    pub fn installed() -> Result<Self, InstalledDeployError> {
        let source = SourceBrokerClientV1::installed(Duration::from_secs(2))?;
        Ok(Self::bound(
            source,
            PathBuf::from(DEPLOY_MUTATION_POLICY_PATH),
            PathBuf::from(crate::installed_policy::INSTALLED_RIMG_POLICY_PATH),
            PathBuf::from(crate::installed_source::SOURCE_CONFIG_PATH),
            PathBuf::from(BUILD_RELEASE_BUNDLE_ROOT),
            PathBuf::from(BUILD_RELEASE_ATTESTATION_ROOT),
            PathBuf::from(BUILD_OCI_ARCHIVE_ROOT),
            PathBuf::from(ROOT_RELEASE_BUNDLE_ROOT),
            PathBuf::from(ROOT_OCI_ARCHIVE_ROOT),
            PathBuf::from(ROOT_RELEASE_STATE_PATH),
            0,
        ))
    }
}

impl<S> InstalledDeployIntentResolverV1<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bound(
        source: S,
        deploy_policy_path: PathBuf,
        installed_rimg_policy_path: PathBuf,
        installed_source_config_path: PathBuf,
        build_release_bundle_root: PathBuf,
        build_release_attestation_root: PathBuf,
        build_oci_archive_root: PathBuf,
        root_release_bundle_root: PathBuf,
        root_oci_archive_root: PathBuf,
        root_release_state_path: PathBuf,
        required_uid: u32,
    ) -> Self {
        Self {
            source,
            deploy_policy_path,
            installed_rimg_policy_path,
            installed_source_config_path,
            build_release_bundle_root,
            build_release_attestation_root,
            build_oci_archive_root,
            root_release_bundle_root,
            root_oci_archive_root,
            root_release_state_path,
            required_uid,
        }
    }

    pub fn load_policy(&self) -> Result<InstalledDeployMutationPolicyV1, InstalledDeployError> {
        let policy: InstalledDeployMutationPolicyV1 = load_canonical_private(
            &self.deploy_policy_path,
            self.required_uid,
            MAX_DOCUMENT_BYTES,
        )?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn load_release_state(&self) -> Result<InstalledReleaseStateV1, InstalledDeployError> {
        let state: InstalledReleaseStateV1 = load_canonical_private(
            &self.root_release_state_path,
            self.required_uid,
            MAX_DOCUMENT_BYTES,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn load_rimg_policy(&self) -> Result<InstalledRimgPolicyV1, InstalledDeployError> {
        load_installed_rimg_policy_from(&self.installed_rimg_policy_path, self.required_uid)
            .map_err(Into::into)
    }

    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    pub fn promote_candidate_bundle(
        &self,
        policy: &InstalledDeployMutationPolicyV1,
        candidate: &ReleaseBundleV1,
    ) -> Result<(), InstalledDeployError> {
        let archive = OciArchiveReaderV1::open(
            &self.build_oci_archive_root,
            policy.build_uid,
            policy.build_reader_gid,
        )?
        .load(candidate)?;
        promote_oci_archive_private(
            &self.root_oci_archive_root,
            self.required_uid,
            candidate,
            &archive,
        )?;
        ReleaseBundleStore::open_for_owner(&self.root_release_bundle_root, self.required_uid)?
            .persist(candidate.project_id(), candidate)?;
        Ok(())
    }

    pub fn commit_bootstrap_release(
        &self,
        expected: &InstalledReleaseStateV1,
        candidate: &ReleaseBundleV1,
        committed_at_ms: i64,
    ) -> Result<InstalledReleaseStateV1, InstalledDeployError> {
        if committed_at_ms < expected.updated_at_ms
            || expected.current_release_bundle_digest.is_some()
            || expected.last_known_good_release_bundle_digest.is_some()
            || candidate.project_id() != &expected.project_id
        {
            return Err(InstalledDeployError::ReleaseStateConflict);
        }
        let next = InstalledReleaseStateV1::new(InstalledReleaseStateInputV1 {
            project_id: expected.project_id.clone(),
            installed_policy: expected.installed_policy.clone(),
            installed_rimg_policy_digest: expected.installed_rimg_policy_digest.clone(),
            generation: expected
                .generation
                .checked_add(1)
                .ok_or(InstalledDeployError::ReleaseStateConflict)?,
            current_release_bundle_digest: Some(candidate.digest().clone()),
            last_known_good_release_bundle_digest: None,
            updated_at_ms: committed_at_ms,
        })?;
        persist_release_state(
            &self.root_release_state_path,
            self.required_uid,
            expected,
            &next,
        )?;
        Ok(next)
    }
}

impl<S: DeploySourceSnapshotV1> InstalledDeployIntentResolverV1<S> {
    fn resolve_deploy(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<ExecutorIntentIssueInputV1, InstalledDeployError> {
        if now_ms < 0
            || request.operation_kind != OperationKind::Deploy
            || request.target_commit.is_none()
            || request.proposed_release_class == Some(ReleaseClass::Rollback)
        {
            return Err(InstalledDeployError::RequestRejected);
        }
        let target = request
            .target_commit
            .as_ref()
            .ok_or(InstalledDeployError::RequestRejected)?;
        let policy = self.load_policy()?;
        if request.project_id != policy.project_id {
            return Err(InstalledDeployError::RequestRejected);
        }
        let rimg =
            load_installed_rimg_policy_from(&self.installed_rimg_policy_path, self.required_uid)?;
        validate_installed_policy_binding(&policy, &rimg)?;
        let source_config = load_installed_source_config_from(&self.installed_source_config_path)?;
        let snapshot = self.source.snapshot(&request.project_id)?;
        let verified_source = source_config.verify_snapshot(&snapshot, target, now_ms)?;
        if verified_source.installed_policy != policy.installed_policy {
            return Err(InstalledDeployError::InstalledBinding);
        }
        let state = self.load_release_state()?;
        validate_release_state_binding(&state, &policy)?;
        if state.current_release_bundle_digest.is_some() {
            return Err(InstalledDeployError::InstalledUpgradeUnavailable);
        }
        let current = self.load_current_bundle(&state, &policy)?;
        let (attestation, candidate) = self.load_candidate(&policy, target, now_ms)?;
        if attestation.source_sequence != verified_source.sequence
            || attestation.source_attestation_digest != verified_source.attestation_digest
            || attestation.installed_policy != policy.installed_policy
            || attestation.installed_rimg_policy_digest != policy.installed_rimg_policy_digest
        {
            return Err(InstalledDeployError::CandidateBinding);
        }
        let (effective_release_class, transition) =
            classify_release(&rimg, current.as_ref(), &candidate)?;
        if effective_release_class == ReleaseClass::CodeOnlyCompatible {
            if attestation.migration_plan_observation_digest.is_some() {
                return Err(InstalledDeployError::CandidateBinding);
            }
        } else if attestation.migration_plan_observation_digest.is_none() {
            return Err(InstalledDeployError::CandidateBinding);
        }
        let expires_at_ms = now_ms
            .checked_add(
                i64::try_from(policy.intent_ttl_ms)
                    .map_err(|_| InstalledDeployError::InvalidPolicy)?,
            )
            .ok_or(InstalledDeployError::InvalidPolicy)?;
        Ok(ExecutorIntentIssueInputV1 {
            issued_at_ms: now_ms,
            not_before_ms: now_ms,
            expires_at_ms: expires_at_ms.min(attestation.expires_at_ms),
            intent_id: uuid::Uuid::new_v4(),
            request_id: request.idempotency_key,
            project_id: request.project_id.clone(),
            operation_kind: OperationKind::Deploy,
            target_commit: Some(target.clone()),
            proposed_release_class: request.proposed_release_class,
            effective_release_class: Some(effective_release_class),
            installed_policy_digest: policy.document_digest,
            source_attestation_digest: Some(verified_source.attestation_digest),
            source_sequence: Some(verified_source.sequence),
            release_bundle_digest: Some(candidate.digest().clone()),
            build_attestation_digest: Some(attestation.payload_digest.clone()),
            migration_id: transition.map(|value| value.migration_id),
            previous_release_bundle_digest: state.current_release_bundle_digest,
        })
    }

    pub(crate) fn load_candidate(
        &self,
        policy: &InstalledDeployMutationPolicyV1,
        target: &GitCommitId,
        now_ms: i64,
    ) -> Result<(BuildReleaseAttestationV1, ReleaseBundleV1), InstalledDeployError> {
        let candidate_root = open_candidate_directory(
            &self.build_release_attestation_root,
            policy.build_uid,
            policy.build_reader_gid,
        )?;
        let project_root = self
            .build_release_attestation_root
            .join(policy.project_id.as_str());
        let project =
            open_candidate_directory(&project_root, policy.build_uid, policy.build_reader_gid)?;
        let bytes = read_stable_candidate_file(
            &project_root.join(format!("{}.jcs", target.as_str())),
            policy.build_uid,
            policy.build_reader_gid,
            MAX_DOCUMENT_BYTES,
        )?;
        revalidate_candidate_directory(
            &self.build_release_attestation_root,
            &candidate_root,
            policy.build_uid,
            policy.build_reader_gid,
        )?;
        revalidate_candidate_directory(
            &project_root,
            &project,
            policy.build_uid,
            policy.build_reader_gid,
        )?;
        let attestation = BuildReleaseAttestationV1::decode_canonical(&bytes)?;
        if attestation.key_id != policy.build_key_id
            || attestation.key_epoch != policy.build_key_epoch
            || attestation.project_id != policy.project_id
            || &attestation.source_head != target
        {
            return Err(InstalledDeployError::CandidateBinding);
        }
        let reader = ReleaseBundleReader::open_for_owner_and_group(
            &self.build_release_bundle_root,
            policy.build_uid,
            policy.build_reader_gid,
        )?;
        let bundle = reader.load(&policy.project_id, &attestation.release_bundle_digest)?;
        attestation.verify(
            &decode_public_key(&policy.build_public_key)?,
            &bundle,
            now_ms,
        )?;
        OciArchiveReaderV1::open(
            &self.build_oci_archive_root,
            policy.build_uid,
            policy.build_reader_gid,
        )?
        .load(&bundle)?;
        Ok((attestation, bundle))
    }

    pub(crate) fn load_current_bundle(
        &self,
        state: &InstalledReleaseStateV1,
        policy: &InstalledDeployMutationPolicyV1,
    ) -> Result<Option<ReleaseBundleV1>, InstalledDeployError> {
        state
            .current_release_bundle_digest
            .as_ref()
            .map(|digest| {
                ReleaseBundleReader::open_for_owner(
                    &self.root_release_bundle_root,
                    self.required_uid,
                )?
                .load(&policy.project_id, digest)
                .map_err(InstalledDeployError::from)
            })
            .transpose()
    }
}

impl<S: DeploySourceSnapshotV1> ExecutorIntentResolverV1 for InstalledDeployIntentResolverV1<S> {
    fn resolve(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<ExecutorIntentIssueInputV1, IntentResolutionFailureV1> {
        match self.resolve_deploy(request, now_ms) {
            Ok(input) => Ok(input),
            Err(
                InstalledDeployError::RequestRejected
                | InstalledDeployError::CandidateBinding
                | InstalledDeployError::InstalledUpgradeUnavailable,
            ) => Err(IntentResolutionFailureV1::Rejected),
            Err(_) => Err(IntentResolutionFailureV1::TemporarilyUnavailable),
        }
    }
}

fn validate_installed_policy_binding(
    policy: &InstalledDeployMutationPolicyV1,
    rimg: &InstalledRimgPolicyV1,
) -> Result<(), InstalledDeployError> {
    if rimg.project_id() != &policy.project_id
        || rimg.installed_policy() != &policy.installed_policy
        || rimg.digest() != &policy.installed_rimg_policy_digest
    {
        return Err(InstalledDeployError::InstalledBinding);
    }
    Ok(())
}

fn validate_release_state_binding(
    state: &InstalledReleaseStateV1,
    policy: &InstalledDeployMutationPolicyV1,
) -> Result<(), InstalledDeployError> {
    if state.project_id != policy.project_id
        || state.installed_policy != policy.installed_policy
        || state.installed_rimg_policy_digest != policy.installed_rimg_policy_digest
    {
        return Err(InstalledDeployError::InstalledBinding);
    }
    Ok(())
}

fn classify_release(
    policy: &InstalledRimgPolicyV1,
    current: Option<&ReleaseBundleV1>,
    candidate: &ReleaseBundleV1,
) -> Result<(ReleaseClass, Option<InstalledSchemaTransitionV1>), InstalledDeployError> {
    if candidate.project_id() != policy.project_id()
        || candidate.deployment_plan().installed_policy() != policy.installed_policy()
    {
        return Err(InstalledDeployError::CandidateBinding);
    }
    match current {
        None => Ok((ReleaseClass::CodeOnlyCompatible, None)),
        Some(current)
            if current.application_schema_version() == candidate.application_schema_version() =>
        {
            Ok((ReleaseClass::CodeOnlyCompatible, None))
        }
        Some(current) => {
            let transition = policy
                .installed_schema_transition(
                    current.application_schema_version(),
                    candidate.application_schema_version(),
                )
                .ok_or(InstalledDeployError::CandidateBinding)?;
            Ok((transition.release_class, Some(transition)))
        }
    }
}

fn load_canonical_private<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<T, InstalledDeployError> {
    let bytes = read_stable_private_file(path, required_uid, maximum_bytes)?;
    let document = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&document)? != bytes {
        return Err(InstalledDeployError::NoncanonicalDocument);
    }
    Ok(document)
}

fn validate_candidate_directory(
    path: &Path,
    owner_uid: u32,
    reader_group_gid: u32,
) -> Result<(), InstalledDeployError> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_group_gid
        || metadata.mode() & 0o7777 != 0o2750
    {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    Ok(())
}

fn open_candidate_directory(
    path: &Path,
    owner_uid: u32,
    reader_group_gid: u32,
) -> Result<File, InstalledDeployError> {
    validate_candidate_directory(path, owner_uid, reader_group_gid)?;
    let directory = File::open(path)?;
    revalidate_candidate_directory(path, &directory, owner_uid, reader_group_gid)?;
    Ok(directory)
}

fn revalidate_candidate_directory(
    path: &Path,
    opened: &File,
    owner_uid: u32,
    reader_group_gid: u32,
) -> Result<(), InstalledDeployError> {
    validate_candidate_directory(path, owner_uid, reader_group_gid)?;
    let named = fs::symlink_metadata(path)?;
    let metadata = opened.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != reader_group_gid
        || metadata.mode() & 0o7777 != 0o2750
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
    {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    Ok(())
}

fn read_stable_candidate_file(
    path: &Path,
    owner_uid: u32,
    reader_group_gid: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, InstalledDeployError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != owner_uid
        || before.gid() != reader_group_gid
        || before.mode() & 0o777 != 0o440
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.uid() != owner_uid
        || opened.gid() != reader_group_gid
        || opened.mode() & 0o777 != 0o440
    {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| InstalledDeployError::UnsafeCandidateStore)?,
    );
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.uid() != owner_uid
        || after.gid() != reader_group_gid
        || after.mode() & 0o777 != 0o440
        || after.nlink() != 1
    {
        return Err(InstalledDeployError::UnsafeCandidateStore);
    }
    Ok(bytes)
}

fn persist_release_state(
    path: &Path,
    required_uid: u32,
    expected: &InstalledReleaseStateV1,
    next: &InstalledReleaseStateV1,
) -> Result<(), InstalledDeployError> {
    let parent = path
        .parent()
        .ok_or(InstalledDeployError::ReleaseStateConflict)?;
    let directory = open_stable_private_directory(parent, required_uid)?;
    sweep_release_state_temporaries(parent, &directory, required_uid)?;
    let current: InstalledReleaseStateV1 =
        load_canonical_private(path, required_uid, MAX_DOCUMENT_BYTES)?;
    if &current != expected {
        return Err(InstalledDeployError::ReleaseStateConflict);
    }
    let temporary_path = parent.join(format!(".rimg.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        revalidate_private_directory(parent, &directory, required_uid)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut temporary = options.open(&temporary_path)?;
        temporary.write_all(&next.canonical_bytes()?)?;
        temporary.sync_all()?;
        let metadata = temporary.metadata()?;
        if metadata.uid() != required_uid || metadata.mode() & 0o077 != 0 {
            return Err(InstalledDeployError::ReleaseStateConflict);
        }
        let still_current: InstalledReleaseStateV1 =
            load_canonical_private(path, required_uid, MAX_DOCUMENT_BYTES)?;
        if &still_current != expected {
            return Err(InstalledDeployError::ReleaseStateConflict);
        }
        revalidate_private_directory(parent, &directory, required_uid)?;
        fs::rename(&temporary_path, path)?;
        revalidate_private_directory(parent, &directory, required_uid)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        match fs::remove_file(&temporary_path) {
            Ok(()) => {
                let _ = directory.sync_all();
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
    result
}

fn open_stable_private_directory(
    path: &Path,
    required_uid: u32,
) -> Result<File, InstalledDeployError> {
    validate_private_directory(path, required_uid)?;
    let directory = File::open(path)?;
    revalidate_private_directory(path, &directory, required_uid)?;
    Ok(directory)
}

fn revalidate_private_directory(
    path: &Path,
    directory: &File,
    required_uid: u32,
) -> Result<(), InstalledDeployError> {
    let path_metadata = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || !opened.is_dir()
        || path_metadata.uid() != required_uid
        || opened.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || opened.mode() & 0o077 != 0
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err(InstalledDeployError::ReleaseStateConflict);
    }
    Ok(())
}

fn sweep_release_state_temporaries(
    parent: &Path,
    directory: &File,
    required_uid: u32,
) -> Result<(), InstalledDeployError> {
    let mut changed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(identifier) = name
            .strip_prefix(".rimg.")
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            continue;
        };
        let Ok(identifier) = uuid::Uuid::parse_str(identifier) else {
            continue;
        };
        if name != format!(".rimg.{identifier}.tmp") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != required_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(InstalledDeployError::ReleaseStateConflict);
        }
        fs::remove_file(entry.path())?;
        changed = true;
    }
    revalidate_private_directory(parent, directory, required_uid)?;
    if changed {
        directory.sync_all()?;
    }
    Ok(())
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, InstalledDeployError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| InstalledDeployError::InvalidPolicy)?;
    let bytes = decoded
        .try_into()
        .map_err(|_| InstalledDeployError::InvalidPolicy)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| InstalledDeployError::InvalidPolicy)?;
    if key.is_weak() {
        return Err(InstalledDeployError::InvalidPolicy);
    }
    Ok(key)
}

fn valid_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, thiserror::Error)]
pub enum InstalledDeployError {
    #[error("the installed deploy mutation policy is invalid")]
    InvalidPolicy,
    #[error("the installed release state is invalid")]
    InvalidReleaseState,
    #[error("the installed release state changed or could not be atomically promoted")]
    ReleaseStateConflict,
    #[error("the deploy request is not supported by the installed resolver")]
    RequestRejected,
    #[error("installed upgrades remain disabled until the stable-routing driver is installed")]
    InstalledUpgradeUnavailable,
    #[error("the installed deploy policy, source policy and rimg policy do not match")]
    InstalledBinding,
    #[error("the prepared candidate release does not match the deploy request")]
    CandidateBinding,
    #[error("the build candidate store is not an exact owner/group read-only handoff")]
    UnsafeCandidateStore,
    #[error("an installed deploy document is not canonical JCS")]
    NoncanonicalDocument,
    #[error(transparent)]
    BuildAttestation(#[from] BuildReleaseAttestationError),
    #[error(transparent)]
    BuildStore(#[from] crate::build::ReleaseBundleStoreError),
    #[error(transparent)]
    OciArchive(#[from] crate::oci_handoff::OciArchiveError),
    #[error(transparent)]
    InstalledPolicy(#[from] InstalledPolicyLoadError),
    #[error(transparent)]
    InstalledSource(#[from] InstalledSourceError),
    #[error(transparent)]
    Source(#[from] SourceGateError),
    #[error(transparent)]
    SourceClient(#[from] crate::source_socket::SourceClientError),
    #[error(transparent)]
    Runtime(#[from] crate::rimg_adapter::RimgAdapterError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
