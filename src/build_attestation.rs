use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    build::ReleaseBundleV1,
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, OperationPhase, PhaseArtifacts,
        ProjectId,
    },
};

pub const BUILD_RELEASE_ATTESTATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_BUILD_RELEASE_ATTESTATION_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

const BUILD_RELEASE_SIGNATURE_DOMAIN: &str = "rdashboard.build-release-attestation.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildReleaseAttestationInputV1 {
    pub key_id: String,
    pub key_epoch: u64,
    pub project_id: ProjectId,
    pub source_head: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub release_bundle_digest: EvidenceDigest,
    pub testing_artifacts: PhaseArtifacts,
    pub building_artifacts: PhaseArtifacts,
    pub preflight_artifacts: PhaseArtifacts,
    pub migration_plan_observation_digest: Option<EvidenceDigest>,
    pub data_compatibility_observation_digest: EvidenceDigest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReleaseAttestationV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub key_id: String,
    pub key_epoch: u64,
    pub project_id: ProjectId,
    pub source_head: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub release_bundle_digest: EvidenceDigest,
    pub testing_artifacts: PhaseArtifacts,
    pub building_artifacts: PhaseArtifacts,
    pub preflight_artifacts: PhaseArtifacts,
    pub migration_plan_observation_digest: Option<EvidenceDigest>,
    pub data_compatibility_observation_digest: EvidenceDigest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub payload_digest: EvidenceDigest,
    pub signature: String,
}

/// Candidate phase evidence after root replaces the builder's point-in-time disk
/// measurement with the reservation authorized for the accepted runtime attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCandidateArtifactsV1 {
    pub testing: PhaseArtifacts,
    pub building: PhaseArtifacts,
    pub preflight: PhaseArtifacts,
}

#[derive(Serialize)]
struct BuildReleaseAttestationPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    key_id: &'a str,
    key_epoch: u64,
    project_id: &'a ProjectId,
    source_head: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    release_bundle_digest: &'a EvidenceDigest,
    testing_artifacts: &'a PhaseArtifacts,
    building_artifacts: &'a PhaseArtifacts,
    preflight_artifacts: &'a PhaseArtifacts,
    migration_plan_observation_digest: &'a Option<EvidenceDigest>,
    data_compatibility_observation_digest: &'a EvidenceDigest,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl BuildReleaseAttestationV1 {
    pub fn issue(
        input: BuildReleaseAttestationInputV1,
        signing_key: &SigningKey,
    ) -> Result<Self, BuildReleaseAttestationError> {
        let mut attestation = Self {
            purpose: BUILD_RELEASE_SIGNATURE_DOMAIN.to_owned(),
            schema_version: BUILD_RELEASE_ATTESTATION_SCHEMA_VERSION,
            key_id: input.key_id,
            key_epoch: input.key_epoch,
            project_id: input.project_id,
            source_head: input.source_head,
            source_sequence: input.source_sequence,
            source_attestation_digest: input.source_attestation_digest,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            release_bundle_digest: input.release_bundle_digest,
            testing_artifacts: input.testing_artifacts,
            building_artifacts: input.building_artifacts,
            preflight_artifacts: input.preflight_artifacts,
            migration_plan_observation_digest: input.migration_plan_observation_digest,
            data_compatibility_observation_digest: input.data_compatibility_observation_digest,
            issued_at_ms: input.issued_at_ms,
            expires_at_ms: input.expires_at_ms,
            payload_digest: EvidenceDigest::sha256([]),
            signature: String::new(),
        };
        let payload = attestation.payload_bytes()?;
        attestation.payload_digest = EvidenceDigest::sha256(&payload);
        attestation.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        attestation.validate_shape()?;
        Ok(attestation)
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        bundle: &ReleaseBundleV1,
        now_ms: i64,
    ) -> Result<(), BuildReleaseAttestationError> {
        self.validate_shape()?;
        if now_ms < self.issued_at_ms || now_ms > self.expires_at_ms {
            return Err(BuildReleaseAttestationError::Expired);
        }
        bundle.verify()?;
        if bundle.project_id() != &self.project_id
            || bundle.digest() != &self.release_bundle_digest
            || bundle.deployment_plan().source_head() != &self.source_head
            || bundle.deployment_plan().installed_policy() != &self.installed_policy
            || Some(bundle.source_export_digest())
                != self.testing_artifacts.source_export_digest.as_ref()
            || Some(bundle.prefetch_evidence_digest())
                != self.testing_artifacts.prefetch_evidence_digest.as_ref()
            || Some(bundle.ci_evidence_digest())
                != self.testing_artifacts.ci_evidence_digest.as_ref()
            || Some(bundle.build_context_digest())
                != self.testing_artifacts.build_context_digest.as_ref()
            || Some(bundle.resource_reservation_digest())
                != self.testing_artifacts.resource_reservation_digest.as_ref()
            || Some(bundle.build_context_digest())
                != self.building_artifacts.build_context_digest.as_ref()
            || Some(bundle.build_plan_digest())
                != self.building_artifacts.build_plan_digest.as_ref()
            || Some(&EvidenceDigest::sha256(
                bundle.image_registry_digest().as_str(),
            )) != self.building_artifacts.image_digest.as_ref()
            || Some(&EvidenceDigest::sha256(bundle.local_image_id().as_str()))
                != self.building_artifacts.image_id_digest.as_ref()
            || Some(bundle.resource_reservation_digest())
                != self
                    .preflight_artifacts
                    .resource_reservation_digest
                    .as_ref()
            || self.testing_artifacts.base_image_digests
                != self.building_artifacts.base_image_digests
        {
            return Err(BuildReleaseAttestationError::ArtifactBinding);
        }
        let payload = self.payload_bytes()?;
        if EvidenceDigest::sha256(&payload) != self.payload_digest {
            return Err(BuildReleaseAttestationError::DigestMismatch);
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| BuildReleaseAttestationError::InvalidSignature)?;
        if URL_SAFE_NO_PAD.encode(&signature_bytes) != self.signature {
            return Err(BuildReleaseAttestationError::InvalidSignature);
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| BuildReleaseAttestationError::InvalidSignature)?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| BuildReleaseAttestationError::InvalidSignature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BuildReleaseAttestationError> {
        self.validate_shape()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn bind_runtime_reservation(
        &self,
        reservation_digest: EvidenceDigest,
    ) -> Result<RuntimeCandidateArtifactsV1, BuildReleaseAttestationError> {
        self.validate_shape()?;
        let mut testing = self.testing_artifacts.clone();
        testing.resource_reservation_digest = Some(reservation_digest.clone());
        let mut preflight = self.preflight_artifacts.clone();
        preflight.resource_reservation_digest = Some(reservation_digest);
        testing.validate_for_phase(OperationPhase::Testing)?;
        self.building_artifacts
            .validate_for_phase(OperationPhase::Building)?;
        preflight.validate_for_phase(OperationPhase::Preflight)?;
        Ok(RuntimeCandidateArtifactsV1 {
            testing,
            building: self.building_artifacts.clone(),
            preflight,
        })
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BuildReleaseAttestationError> {
        let attestation: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&attestation)? != bytes {
            return Err(BuildReleaseAttestationError::NonCanonical);
        }
        attestation.validate_shape()?;
        Ok(attestation)
    }

    fn validate_shape(&self) -> Result<(), BuildReleaseAttestationError> {
        if self.purpose != BUILD_RELEASE_SIGNATURE_DOMAIN
            || self.schema_version != BUILD_RELEASE_ATTESTATION_SCHEMA_VERSION
            || !valid_key_id(&self.key_id)
            || self.key_epoch == 0
            || self.key_epoch > i64::MAX.unsigned_abs()
            || self.source_sequence == 0
            || self.installed_policy.version == 0
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_BUILD_RELEASE_ATTESTATION_TTL_MS
            || self.signature.is_empty()
        {
            return Err(BuildReleaseAttestationError::InvalidDocument);
        }
        self.testing_artifacts
            .validate_for_phase(OperationPhase::Testing)?;
        self.building_artifacts
            .validate_for_phase(OperationPhase::Building)?;
        self.preflight_artifacts
            .validate_for_phase(OperationPhase::Preflight)?;
        Ok(())
    }

    fn payload_bytes(&self) -> Result<Vec<u8>, BuildReleaseAttestationError> {
        Ok(serde_jcs::to_vec(&BuildReleaseAttestationPayload {
            purpose: BUILD_RELEASE_SIGNATURE_DOMAIN,
            schema_version: BUILD_RELEASE_ATTESTATION_SCHEMA_VERSION,
            key_id: &self.key_id,
            key_epoch: self.key_epoch,
            project_id: &self.project_id,
            source_head: &self.source_head,
            source_sequence: self.source_sequence,
            source_attestation_digest: &self.source_attestation_digest,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            release_bundle_digest: &self.release_bundle_digest,
            testing_artifacts: &self.testing_artifacts,
            building_artifacts: &self.building_artifacts,
            preflight_artifacts: &self.preflight_artifacts,
            migration_plan_observation_digest: &self.migration_plan_observation_digest,
            data_compatibility_observation_digest: &self.data_compatibility_observation_digest,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        })?)
    }
}

fn valid_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, thiserror::Error)]
pub enum BuildReleaseAttestationError {
    #[error("the build-release attestation is structurally invalid")]
    InvalidDocument,
    #[error("the build-release attestation is not canonical JCS")]
    NonCanonical,
    #[error("the build-release attestation is outside its validity interval")]
    Expired,
    #[error("the build-release attestation payload digest does not match")]
    DigestMismatch,
    #[error("the build-release attestation signature is invalid")]
    InvalidSignature,
    #[error("the build-release attestation does not match the verified release bundle")]
    ArtifactBinding,
    #[error(transparent)]
    Artifact(#[from] crate::domain::ArtifactContractError),
    #[error(transparent)]
    Build(#[from] crate::build::BuildContractError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::build::ReleaseRollbackContractV1;

    fn digest(label: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    pub(crate) fn project() -> ProjectId {
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"))
    }

    pub(crate) fn installed_policy() -> InstalledPolicyIdentity {
        InstalledPolicyIdentity {
            digest: digest("installed policy"),
            version: 1,
        }
    }

    pub(crate) fn release_bundle() -> ReleaseBundleV1 {
        let evidence = |field: &str| digest(&format!("candidate:{field}"));
        let mut deployment_plan = serde_json::json!({
            "purpose": "rdashboard.kamal-deployment-plan.v1",
            "project_id": project(),
            "source_head": "dddddddddddddddddddddddddddddddddddddddd",
            "release_identity_digest": evidence("release identity"),
            "installed_policy": installed_policy(),
            "context_digest": evidence("build context"),
            "image_registry_digest": format!("sha256:{}", "a".repeat(64)),
            "service": "rimg",
            "image": "mrdenai/rimg",
            "target_host": "45.151.142.168",
            "ssh_user": "deploy",
            "ssh_port": 22,
            "network": "kamal",
            "network_alias": "rimg",
            "run_as": { "uid": 10001, "gid": 10001 },
            "mounts": [],
            "ports": [],
            "clear_environment": [],
            "secret_bindings": [],
            "credential_versions_digest": evidence("credential versions"),
            "logging": { "driver": "local", "max_size_bytes": 1_048_576, "max_files": 2 },
            "runtime_policy_digest": evidence("runtime policy"),
            "template_digest": evidence("template"),
            "sanitized_diff_digest": evidence("sanitized diff"),
            "repository_configuration": "ignored",
            "hooks": "disabled",
            "template_evaluation": "disabled",
            "registry_transport": "loopback_port5555",
        });
        let plan_digest = EvidenceDigest::sha256(
            serde_jcs::to_vec(&deployment_plan)
                .unwrap_or_else(|error| panic!("plan payload: {error}")),
        );
        let plan = deployment_plan
            .as_object_mut()
            .unwrap_or_else(|| panic!("plan object"));
        plan.remove("purpose");
        plan.insert("plan_digest".to_owned(), serde_json::json!(plan_digest));
        let mut payload = serde_json::json!({
            "purpose": "rdashboard.release-bundle.v1",
            "schema_version": 3,
            "project_id": project(),
            "release_identity_digest": evidence("release identity"),
            "source_export_digest": evidence("source export"),
            "prefetch_evidence_digest": evidence("prefetch"),
            "ci_evidence_digest": evidence("ci"),
            "build_context_digest": evidence("build context"),
            "resource_reservation_digest": evidence("reservation"),
            "build_plan_digest": evidence("build plan"),
            "image_registry_digest": format!("sha256:{}", "a".repeat(64)),
            "local_image_id": format!("sha256:{}", "b".repeat(64)),
            "image_archive_digest": EvidenceDigest::sha256(b"fixture OCI archive"),
            "deployment_plan": deployment_plan,
            "runtime_policy_digest": evidence("runtime policy"),
            "credential_versions_digest": evidence("credential versions"),
            "application_schema_version": "1",
            "rollback": ReleaseRollbackContractV1::BootstrapUnavailable,
        });
        let bundle_digest = EvidenceDigest::sha256(
            serde_jcs::to_vec(&payload).unwrap_or_else(|error| panic!("bundle payload: {error}")),
        );
        let document = payload
            .as_object_mut()
            .unwrap_or_else(|| panic!("bundle object"));
        document.remove("purpose");
        document.insert("bundle_digest".to_owned(), serde_json::json!(bundle_digest));
        ReleaseBundleV1::decode_canonical_json(
            &serde_jcs::to_vec(&payload)
                .unwrap_or_else(|error| panic!("canonical bundle: {error}")),
        )
        .unwrap_or_else(|error| panic!("bundle: {error}"))
    }

    pub(crate) fn phase_artifacts(
        bundle: &ReleaseBundleV1,
    ) -> (PhaseArtifacts, PhaseArtifacts, PhaseArtifacts) {
        let bases = vec![digest("base image")];
        let testing = PhaseArtifacts {
            source_export_digest: Some(bundle.source_export_digest().clone()),
            prefetch_evidence_digest: Some(bundle.prefetch_evidence_digest().clone()),
            ci_evidence_digest: Some(bundle.ci_evidence_digest().clone()),
            build_context_digest: Some(bundle.build_context_digest().clone()),
            resource_reservation_digest: Some(bundle.resource_reservation_digest().clone()),
            base_image_digests: bases.clone(),
            ..PhaseArtifacts::default()
        };
        let building = PhaseArtifacts {
            build_context_digest: Some(bundle.build_context_digest().clone()),
            build_plan_digest: Some(bundle.build_plan_digest().clone()),
            image_digest: Some(EvidenceDigest::sha256(
                bundle.image_registry_digest().as_str(),
            )),
            image_id_digest: Some(EvidenceDigest::sha256(bundle.local_image_id().as_str())),
            base_image_digests: bases,
            ..PhaseArtifacts::default()
        };
        let preflight = PhaseArtifacts {
            resource_reservation_digest: Some(bundle.resource_reservation_digest().clone()),
            ..PhaseArtifacts::default()
        };
        (testing, building, preflight)
    }

    fn signed_attestation(
        bundle: &ReleaseBundleV1,
        signing_key: &SigningKey,
    ) -> BuildReleaseAttestationV1 {
        let (testing_artifacts, building_artifacts, preflight_artifacts) = phase_artifacts(bundle);
        BuildReleaseAttestationV1::issue(
            BuildReleaseAttestationInputV1 {
                key_id: "build-v1".to_owned(),
                key_epoch: 1,
                project_id: project(),
                source_head: GitCommitId::from_str("dddddddddddddddddddddddddddddddddddddddd")
                    .unwrap_or_else(|error| panic!("commit: {error}")),
                source_sequence: 7,
                source_attestation_digest: digest("source attestation"),
                installed_policy: installed_policy(),
                installed_rimg_policy_digest: digest("rimg policy"),
                release_bundle_digest: bundle.digest().clone(),
                testing_artifacts,
                building_artifacts,
                preflight_artifacts,
                migration_plan_observation_digest: None,
                data_compatibility_observation_digest: digest("compatibility observation"),
                issued_at_ms: 1_000,
                expires_at_ms: 2_000,
            },
            signing_key,
        )
        .unwrap_or_else(|error| panic!("attestation: {error}"))
    }

    #[test]
    fn signed_build_release_is_canonical_exact_bundle_bound_and_time_bounded() {
        let bundle = release_bundle();
        let signing_key = SigningKey::from_bytes(&[19; 32]);
        let attestation = signed_attestation(&bundle, &signing_key);
        attestation
            .verify(&signing_key.verifying_key(), &bundle, 1_500)
            .unwrap_or_else(|error| panic!("verify: {error}"));
        let canonical = attestation
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("canonical: {error}"));
        assert_eq!(
            BuildReleaseAttestationV1::decode_canonical(&canonical)
                .unwrap_or_else(|error| panic!("decode: {error}")),
            attestation
        );
        assert!(matches!(
            attestation.verify(&signing_key.verifying_key(), &bundle, 2_001),
            Err(BuildReleaseAttestationError::Expired)
        ));
    }

    #[test]
    fn build_release_rejects_signature_and_phase_artifact_substitution() {
        let bundle = release_bundle();
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let mut attestation = signed_attestation(&bundle, &signing_key);
        attestation.testing_artifacts.ci_evidence_digest = Some(digest("substituted ci"));
        assert!(matches!(
            attestation.verify(&signing_key.verifying_key(), &bundle, 1_500),
            Err(BuildReleaseAttestationError::ArtifactBinding)
        ));

        let other_key = SigningKey::from_bytes(&[29; 32]);
        let exact = signed_attestation(&bundle, &signing_key);
        assert!(matches!(
            exact.verify(&other_key.verifying_key(), &bundle, 1_500),
            Err(BuildReleaseAttestationError::InvalidSignature)
        ));
    }

    #[test]
    fn accepted_runtime_attempt_rebinds_only_its_root_disk_reservation() {
        let bundle = release_bundle();
        let attestation = signed_attestation(&bundle, &SigningKey::from_bytes(&[31; 32]));
        let runtime_digest = digest("accepted runtime reservation");
        let runtime = attestation
            .bind_runtime_reservation(runtime_digest.clone())
            .unwrap_or_else(|error| panic!("bind runtime reservation: {error}"));
        assert_eq!(
            runtime.testing.resource_reservation_digest,
            Some(runtime_digest.clone())
        );
        assert_eq!(
            runtime.preflight.resource_reservation_digest,
            Some(runtime_digest)
        );
        assert_eq!(runtime.building, attestation.building_artifacts);
        let mut expected_testing = attestation.testing_artifacts.clone();
        expected_testing.resource_reservation_digest =
            runtime.testing.resource_reservation_digest.clone();
        assert_eq!(runtime.testing, expected_testing);
    }
}
