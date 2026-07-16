use std::{collections::BTreeMap, path::Path};

use crate::{
    adapter::{
        AdapterExecutionResultV1, PreparedAdapterJobStateV1, PreparedAdapterJobV1,
        SystemdTransientAdapterRunnerV1,
    },
    adapter_identity::AdapterOperationIdentityV1,
    adapter_result::{FixedAdapterResultV1, PhaseExecutionProjectionV1},
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1},
};

pub trait FixedAdapterJobRunnerV1: Clone + Send + Sync {
    fn execute_job(
        &self,
        job: &PreparedAdapterJobV1,
        spec: &AuthorizedPhaseSpecV1,
        prior_results: &[FixedAdapterResultV1],
    ) -> Result<AdapterExecutionResultV1, crate::adapter::AdapterJobError>;
}

pub trait AuthorizedAdapterPhaseExecutorV1: Clone + Send + Sync {
    fn observe_authorized(
        &self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Option<PhaseExecutionProjectionV1>, AdapterPhaseError>;

    fn execute_authorized(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        operation_identities: &[AdapterOperationIdentityV1],
    ) -> Result<PhaseExecutionProjectionV1, AdapterPhaseError>;
}

impl FixedAdapterJobRunnerV1 for SystemdTransientAdapterRunnerV1 {
    fn execute_job(
        &self,
        job: &PreparedAdapterJobV1,
        spec: &AuthorizedPhaseSpecV1,
        prior_results: &[FixedAdapterResultV1],
    ) -> Result<AdapterExecutionResultV1, crate::adapter::AdapterJobError> {
        self.execute(job, spec, prior_results)
    }
}

#[derive(Clone, Debug)]
pub struct FixedAdapterPhaseExecutorV1<R> {
    runner: R,
}

impl FixedAdapterPhaseExecutorV1<SystemdTransientAdapterRunnerV1> {
    pub fn installed() -> Self {
        Self {
            runner: SystemdTransientAdapterRunnerV1::default(),
        }
    }

    pub const fn installed_with_cancellation(
        cancellation: crate::adapter::AdapterExecutionCancellationV1,
    ) -> Self {
        Self {
            runner: SystemdTransientAdapterRunnerV1::new(cancellation),
        }
    }

    pub fn observe_installed(
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Option<PhaseExecutionProjectionV1>, AdapterPhaseError> {
        observe_in(Path::new(crate::adapter::FIXED_ADAPTER_JOB_ROOT), 0, spec)
    }

    pub fn execute_installed(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        operation_identities: &[AdapterOperationIdentityV1],
    ) -> Result<PhaseExecutionProjectionV1, AdapterPhaseError> {
        self.execute_in(
            Path::new(crate::adapter::FIXED_ADAPTER_JOB_ROOT),
            0,
            spec,
            operation_identities,
        )
    }
}

impl AuthorizedAdapterPhaseExecutorV1
    for FixedAdapterPhaseExecutorV1<SystemdTransientAdapterRunnerV1>
{
    fn observe_authorized(
        &self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Option<PhaseExecutionProjectionV1>, AdapterPhaseError> {
        Self::observe_installed(spec)
    }

    fn execute_authorized(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        operation_identities: &[AdapterOperationIdentityV1],
    ) -> Result<PhaseExecutionProjectionV1, AdapterPhaseError> {
        self.execute_installed(spec, operation_identities)
    }
}

impl<R: FixedAdapterJobRunnerV1> FixedAdapterPhaseExecutorV1<R> {
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    fn execute_in(
        &self,
        job_root: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
        operation_identities: &[AdapterOperationIdentityV1],
    ) -> Result<PhaseExecutionProjectionV1, AdapterPhaseError> {
        require_valid_spec(spec)?;
        let identities = validate_operation_identities(spec, operation_identities)?;
        if let Some(projection) = observe_in(job_root, required_uid, spec)? {
            return Ok(projection);
        }

        let mut results = Vec::with_capacity(spec.steps.len());
        for step in &spec.steps {
            let job =
                PreparedAdapterJobV1::prepare_in(job_root, required_uid, spec, step.sequence)?;
            let result = match job.state() {
                PreparedAdapterJobStateV1::ResultRequiresReconciliation => {
                    job.reconcile_result(spec, &results)?
                }
                PreparedAdapterJobStateV1::ReadyToExecute => {
                    if let Some(identity) = identities.get(&step.sequence) {
                        job.materialize_operation_identity(spec, identity)?;
                    }
                    self.runner.execute_job(&job, spec, &results)?.result
                }
            };
            results.push(result);
        }
        Ok(PhaseExecutionProjectionV1::from_results(spec, &results)?)
    }
}

fn observe_in(
    job_root: &Path,
    required_uid: u32,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<Option<PhaseExecutionProjectionV1>, AdapterPhaseError> {
    require_valid_spec(spec)?;
    let mut results = Vec::with_capacity(spec.steps.len());
    for step in &spec.steps {
        let job = PreparedAdapterJobV1::prepare_in(job_root, required_uid, spec, step.sequence)?;
        if job.state() == PreparedAdapterJobStateV1::ReadyToExecute {
            return Ok(None);
        }
        results.push(job.reconcile_result(spec, &results)?);
    }
    Ok(Some(PhaseExecutionProjectionV1::from_results(
        spec, &results,
    )?))
}

fn require_valid_spec(spec: &AuthorizedPhaseSpecV1) -> Result<(), AdapterPhaseError> {
    if spec.has_valid_digest()? {
        Ok(())
    } else {
        Err(AdapterPhaseError::InvalidAuthorizedSpec)
    }
}

fn validate_operation_identities<'a>(
    spec: &AuthorizedPhaseSpecV1,
    identities: &'a [AdapterOperationIdentityV1],
) -> Result<BTreeMap<u16, &'a AdapterOperationIdentityV1>, AdapterPhaseError> {
    let mut by_sequence = BTreeMap::new();
    for identity in identities {
        let request = spec.fixed_adapter_request(identity.sequence)?;
        identity.validate_for(spec, &request)?;
        if !profile_requires_operation_identity(request.profile)
            || by_sequence.insert(identity.sequence, identity).is_some()
        {
            return Err(AdapterPhaseError::OperationIdentityMismatch);
        }
    }
    for step in &spec.steps {
        if profile_requires_operation_identity(step.profile)
            != by_sequence.contains_key(&step.sequence)
        {
            return Err(AdapterPhaseError::OperationIdentityMismatch);
        }
    }
    Ok(by_sequence)
}

const fn profile_requires_operation_identity(profile: FixedAdapterProfileV1) -> bool {
    matches!(
        profile,
        FixedAdapterProfileV1::BackupCapture
            | FixedAdapterProfileV1::RimgDrain
            | FixedAdapterProfileV1::RimgMigrate
    )
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterPhaseError {
    #[error("the root-authorized phase specification is invalid")]
    InvalidAuthorizedSpec,
    #[error("the root operation identity set does not match the fixed adapter steps")]
    OperationIdentityMismatch,
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error(transparent)]
    Identity(#[from] crate::adapter_identity::AdapterIdentityError),
    #[error(transparent)]
    Job(#[from] crate::adapter::AdapterJobError),
    #[error(transparent)]
    Result(#[from] crate::adapter_result::AdapterResultContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        sync::{Arc, Mutex},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter::AdapterExecutionOutputV1,
        adapter_result::{FixedAdapterEvidenceV1, PhaseObservationEvidenceV1},
        domain::EvidenceDigest,
        phase6::tests::{test_bootstrap_phase_spec, test_migration_phase_spec},
    };

    #[derive(Clone, Debug, Default)]
    struct FakeRunner {
        calls: Arc<Mutex<usize>>,
    }

    fn private_job_root(path: &Path) -> u32 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job root permissions: {error}"));
        fs::metadata(path)
            .unwrap_or_else(|error| panic!("job root metadata: {error}"))
            .uid()
    }

    impl FixedAdapterJobRunnerV1 for FakeRunner {
        fn execute_job(
            &self,
            job: &PreparedAdapterJobV1,
            spec: &AuthorizedPhaseSpecV1,
            prior_results: &[FixedAdapterResultV1],
        ) -> Result<AdapterExecutionResultV1, crate::adapter::AdapterJobError> {
            *self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            let artifacts = spec
                .bind_artifacts(spec.expected_observation_artifacts.clone())
                .unwrap_or_else(|error| panic!("bind artifacts: {error}"));
            let evidence = FixedAdapterEvidenceV1::DeploymentEvidence(
                PhaseObservationEvidenceV1::new(
                    900,
                    EvidenceDigest::sha256("fake deployment observation"),
                    artifacts,
                )
                .unwrap_or_else(|error| panic!("deployment evidence: {error}")),
            );
            let result = FixedAdapterResultV1::new(spec, job.sequence(), evidence, prior_results)
                .unwrap_or_else(|error| panic!("result: {error}"));
            let bytes = result
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("result bytes: {error}"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(job.result_path())
                .unwrap_or_else(|error| panic!("create result: {error}"));
            file.write_all(&bytes)
                .unwrap_or_else(|error| panic!("write result: {error}"));
            file.sync_all()
                .unwrap_or_else(|error| panic!("sync result: {error}"));
            fs::File::open(job.job_directory())
                .and_then(|directory| directory.sync_all())
                .unwrap_or_else(|error| panic!("sync job: {error}"));
            Ok(AdapterExecutionResultV1 {
                output: AdapterExecutionOutputV1 {
                    unit_name: "fake-adapter.service".to_owned(),
                },
                result,
            })
        }
    }

    #[test]
    fn complete_phase_chain_is_projected_and_replayed_without_another_effect() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = private_job_root(temp.path());
        let spec = test_bootstrap_phase_spec();
        let runner = FakeRunner::default();
        let calls = runner.calls.clone();
        let executor = FixedAdapterPhaseExecutorV1::new(runner);

        let first = executor
            .execute_in(temp.path(), uid, &spec, &[])
            .unwrap_or_else(|error| panic!("first execution: {error}"));
        let replay = executor
            .execute_in(temp.path(), uid, &spec, &[])
            .unwrap_or_else(|error| panic!("replay: {error}"));

        assert_eq!(first, replay);
        assert_eq!(
            *calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            1
        );
    }

    #[test]
    fn identity_bound_profiles_cannot_run_without_the_exact_root_identity() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = private_job_root(temp.path());
        let executor = FixedAdapterPhaseExecutorV1::new(FakeRunner::default());

        assert!(matches!(
            executor.execute_in(temp.path(), uid, &test_migration_phase_spec(), &[]),
            Err(AdapterPhaseError::OperationIdentityMismatch)
        ));
    }
}
