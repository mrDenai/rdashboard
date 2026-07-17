use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    adapter_entrypoint::LoadedAdapterJobV1,
    adapter_result::{
        AdapterResultContractError, FixedAdapterEvidenceV1, FixedAdapterResultV1,
        PhaseObservationEvidenceV1,
    },
    domain::EvidenceDigest,
    phase6::FixedAdapterProfileV1,
};

#[cfg(unix)]
pub mod runtime;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KamalEffectKindV1 {
    Bootstrap,
    Deploy,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KamalDeploymentObservationV1 {
    pub schema_version: u16,
    pub effect: KamalEffectKindV1,
    pub release_bundle_digest: EvidenceDigest,
    pub deployment_plan_digest: EvidenceDigest,
    pub runtime_policy_digest: EvidenceDigest,
    pub generated_config_digest: EvidenceDigest,
    pub image_registry_digest: String,
    pub deployed_version: String,
}

impl KamalDeploymentObservationV1 {
    fn validate(
        &self,
        effect: KamalEffectKindV1,
        release_bundle_digest: &EvidenceDigest,
        deployment_plan_digest: Option<&EvidenceDigest>,
    ) -> Result<(), KamalAdapterError> {
        if self.schema_version != 1
            || self.effect != effect
            || &self.release_bundle_digest != release_bundle_digest
            || deployment_plan_digest.is_some_and(|digest| self.deployment_plan_digest != *digest)
            || !valid_git_version(&self.deployed_version)
            || !valid_oci_digest(&self.image_registry_digest)
        {
            return Err(KamalAdapterError::DeploymentObservationMismatch);
        }
        Ok(())
    }
}

pub trait KamalRuntimeV1 {
    fn apply_release(
        &mut self,
        spec: &crate::phase6::AuthorizedPhaseSpecV1,
        release_bundle_digest: &EvidenceDigest,
        effect: KamalEffectKindV1,
    ) -> Result<KamalDeploymentObservationV1, KamalAdapterError>;
}

pub fn execute_kamal_step<R: KamalRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    completed_at_ms: i64,
) -> Result<FixedAdapterResultV1, KamalAdapterError> {
    execute_kamal_step_with_clock(job, runtime, || Ok(completed_at_ms))
}

pub fn execute_kamal_step_with_clock<R, C>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    mut clock: C,
) -> Result<FixedAdapterResultV1, KamalAdapterError>
where
    R: KamalRuntimeV1,
    C: FnMut() -> Result<i64, KamalAdapterError>,
{
    let (effect, release_bundle_digest, expected_plan_digest) = match job.request.profile {
        FixedAdapterProfileV1::KamalBootstrapDeploy => (
            KamalEffectKindV1::Bootstrap,
            job.spec
                .release_bundle_digest
                .as_ref()
                .ok_or(KamalAdapterError::MissingReleaseBundle)?,
            job.spec.deployment_plan_digest.as_ref(),
        ),
        FixedAdapterProfileV1::KamalCandidateDeploy => (
            KamalEffectKindV1::Deploy,
            job.spec
                .release_bundle_digest
                .as_ref()
                .ok_or(KamalAdapterError::MissingReleaseBundle)?,
            job.spec.deployment_plan_digest.as_ref(),
        ),
        FixedAdapterProfileV1::KamalCodeRollback => (
            KamalEffectKindV1::Rollback,
            job.spec
                .expected_observation_artifacts
                .previous_release_bundle_digest
                .as_ref()
                .ok_or(KamalAdapterError::MissingReleaseBundle)?,
            None,
        ),
        _ => return Err(KamalAdapterError::UnsupportedProfile),
    };
    let observation = runtime.apply_release(&job.spec, release_bundle_digest, effect)?;
    observation.validate(effect, release_bundle_digest, expected_plan_digest)?;
    let completed_at_ms = clock()?;
    if completed_at_ms < 0 {
        return Err(KamalAdapterError::InvalidClock);
    }
    let observation_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&observation)?);
    let artifacts = job
        .spec
        .bind_artifacts(job.spec.expected_observation_artifacts.clone())?;
    let evidence = PhaseObservationEvidenceV1::new(completed_at_ms, observation_digest, artifacts)?;
    let evidence = match effect {
        KamalEffectKindV1::Bootstrap | KamalEffectKindV1::Deploy => {
            FixedAdapterEvidenceV1::DeploymentEvidence(evidence)
        }
        KamalEffectKindV1::Rollback => FixedAdapterEvidenceV1::RollbackEvidence(evidence),
    };
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        evidence,
        &job.prior_results,
    )?)
}

pub(super) fn valid_git_version(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_oci_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, thiserror::Error)]
pub enum KamalAdapterError {
    #[error("the fixed Kamal adapter profile is not implemented by this executable")]
    UnsupportedProfile,
    #[error("the authorized Kamal phase does not identify the required release bundle")]
    MissingReleaseBundle,
    #[error("the observed Kamal deployment does not match the exact authorized release")]
    DeploymentObservationMismatch,
    #[error("the adapter clock is invalid")]
    InvalidClock,
    #[error("the installed Kamal runtime or its generated configuration is not trusted")]
    RuntimeConfigMismatch,
    #[error("fixed Kamal command failed: {0}")]
    CommandFailed(String),
    #[error("fixed Kamal command output exceeded its bounded contract")]
    CommandOutputTooLarge,
    #[error("the promoted OCI archive, registry digest, or local image ID did not match")]
    ImageImportMismatch,
    #[error("the fixed ephemeral registry lifecycle failed")]
    RegistryLifecycle,
    #[error("the fixed ephemeral registry name is owned by an unexpected container")]
    RegistryOwnershipMismatch,
    #[error("the fixed ephemeral registry could not be removed safely")]
    RegistryCleanupFailed,
    #[error("the stable router name, image, network, or state volume is not owned by rdashboard")]
    StableRouterOwnershipMismatch,
    #[error("the stable router did not persist the exact authorized backend target")]
    StableRouterStateMismatch,
    #[error("the stable backend name or identity is not owned by the authorized release")]
    StableBackendOwnershipMismatch,
    #[error("the exact stable backend did not become Docker-healthy")]
    StableBackendUnhealthy,
    #[error("fixed Kamal adapter filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("canonical Kamal evidence encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
    #[error(transparent)]
    ReleaseBundle(#[from] crate::build::ReleaseBundleStoreError),
    #[error(transparent)]
    OciArchive(#[from] crate::oci_handoff::OciArchiveError),
    #[error(transparent)]
    Entrypoint(#[from] crate::adapter_entrypoint::AdapterEntrypointError),
    #[error(transparent)]
    AdapterJob(#[from] crate::adapter::AdapterJobError),
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error(transparent)]
    Result(#[from] AdapterResultContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::Path,
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_entrypoint::FixedAdapterInvocationV1,
        adapter_result::FixedAdapterEvidenceV1,
        phase6::{
            AuthorizedPhaseSpecV1,
            tests::{test_bootstrap_phase_spec, test_rollback_phase_spec},
        },
    };

    struct FakeRuntime {
        observation: KamalDeploymentObservationV1,
        applied_digest: Option<EvidenceDigest>,
    }

    impl KamalRuntimeV1 for FakeRuntime {
        fn apply_release(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
            release_bundle_digest: &EvidenceDigest,
            _effect: KamalEffectKindV1,
        ) -> Result<KamalDeploymentObservationV1, KamalAdapterError> {
            self.applied_digest = Some(release_bundle_digest.clone());
            Ok(self.observation.clone())
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write fixture: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("protect fixture: {error}"));
    }

    fn loaded_job(
        root: &Path,
        spec: &AuthorizedPhaseSpecV1,
        profile: FixedAdapterProfileV1,
    ) -> LoadedAdapterJobV1 {
        fs::create_dir(root).unwrap_or_else(|error| panic!("create job: {error}"));
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("protect job: {error}"));
        let invocation = FixedAdapterInvocationV1 {
            subcommand: "test-v1".to_owned(),
            spec_path: root.join("spec.jcs"),
            request_path: root.join("request.jcs"),
            result_path: root.join("result.jcs"),
            inputs_path: root.join("inputs"),
            operation_identity_path: root.join("operation-identity.jcs"),
        };
        fs::create_dir(&invocation.inputs_path)
            .unwrap_or_else(|error| panic!("create inputs: {error}"));
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
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| panic!("job metadata: {error}"))
            .uid();
        LoadedAdapterJobV1::load(&invocation, profile, uid)
            .unwrap_or_else(|error| panic!("load job: {error}"))
    }

    fn observation(
        effect: KamalEffectKindV1,
        bundle: EvidenceDigest,
        plan: EvidenceDigest,
    ) -> KamalDeploymentObservationV1 {
        KamalDeploymentObservationV1 {
            schema_version: 1,
            effect,
            release_bundle_digest: bundle,
            deployment_plan_digest: plan,
            runtime_policy_digest: EvidenceDigest::sha256("runtime policy"),
            generated_config_digest: EvidenceDigest::sha256("generated config"),
            image_registry_digest: format!("sha256:{}", "a".repeat(64)),
            deployed_version: "b".repeat(40),
        }
    }

    #[test]
    fn deploy_observation_is_bound_to_the_exact_bundle_and_plan() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_bootstrap_phase_spec();
        let job = loaded_job(
            &directory.path().join("deploy-job"),
            &spec,
            FixedAdapterProfileV1::KamalBootstrapDeploy,
        );
        let bundle = spec
            .release_bundle_digest
            .clone()
            .unwrap_or_else(|| panic!("release bundle"));
        let plan = spec
            .deployment_plan_digest
            .clone()
            .unwrap_or_else(|| panic!("deployment plan"));
        let mut runtime = FakeRuntime {
            observation: observation(KamalEffectKindV1::Bootstrap, bundle.clone(), plan),
            applied_digest: None,
        };
        let result = execute_kamal_step(&job, &mut runtime, 900)
            .unwrap_or_else(|error| panic!("deploy result: {error}"));
        assert_eq!(runtime.applied_digest, Some(bundle));
        assert!(matches!(
            result.evidence,
            FixedAdapterEvidenceV1::DeploymentEvidence(_)
        ));
    }

    #[test]
    fn rollback_uses_only_the_content_addressed_previous_release() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_rollback_phase_spec();
        let job = loaded_job(
            &directory.path().join("rollback-job"),
            &spec,
            FixedAdapterProfileV1::KamalCodeRollback,
        );
        let previous = spec
            .expected_observation_artifacts
            .previous_release_bundle_digest
            .clone()
            .unwrap_or_else(|| panic!("previous release bundle"));
        let mut runtime = FakeRuntime {
            observation: observation(
                KamalEffectKindV1::Rollback,
                previous.clone(),
                EvidenceDigest::sha256("previous deployment plan"),
            ),
            applied_digest: None,
        };
        let result = execute_kamal_step(&job, &mut runtime, 950)
            .unwrap_or_else(|error| panic!("rollback result: {error}"));
        assert_eq!(runtime.applied_digest, Some(previous));
        assert!(matches!(
            result.evidence,
            FixedAdapterEvidenceV1::RollbackEvidence(_)
        ));
    }
}
