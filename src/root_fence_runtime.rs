use crate::{
    domain::{EvidenceDigest, ExecutorPhaseBranch, OperationPhase, ProjectId},
    fence_adapter::{FenceAdapterActionV1, FenceAdapterRequestV1, FenceAdapterResultV1},
    fence_job::{PreparedFenceJobStateV1, PreparedFenceJobV1, SystemdTransientFenceRunnerV1},
    rimg_adapter::{
        RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION, RimgObservedDocumentV1, RimgOperationalModeV1,
        RimgOperationalStatusV1, runtime::InstalledRimgFenceObserverV1,
    },
    root_adapter_runtime::load_bound_spec_from_store,
    store::{FenceJournalState, FenceLease, FenceObservation, SecurityStore},
};

pub trait FenceStatusObserverV1: Clone + Send + Sync + 'static {
    fn observe(
        &self,
        project_id: &ProjectId,
        installed_rimg_policy_digest: &EvidenceDigest,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RootFenceRuntimeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InstalledFenceStatusObserverV1;

impl FenceStatusObserverV1 for InstalledFenceStatusObserverV1 {
    fn observe(
        &self,
        project_id: &ProjectId,
        installed_rimg_policy_digest: &EvidenceDigest,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RootFenceRuntimeError> {
        Ok(
            InstalledRimgFenceObserverV1::new(project_id, installed_rimg_policy_digest)?
                .observe()?,
        )
    }
}

pub trait AuthorizedFenceJobExecutorV1: Clone + Send + Sync + 'static {
    fn execute(
        &self,
        request: &FenceAdapterRequestV1,
        lease: &FenceLease,
    ) -> Result<FenceAdapterResultV1, RootFenceRuntimeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FixedFenceJobExecutorV1;

impl AuthorizedFenceJobExecutorV1 for FixedFenceJobExecutorV1 {
    fn execute(
        &self,
        request: &FenceAdapterRequestV1,
        lease: &FenceLease,
    ) -> Result<FenceAdapterResultV1, RootFenceRuntimeError> {
        let job = PreparedFenceJobV1::prepare(request, lease)?;
        match job.state() {
            PreparedFenceJobStateV1::ReadyToExecute => {
                Ok(SystemdTransientFenceRunnerV1.execute(&job)?)
            }
            PreparedFenceJobStateV1::ResultRequiresReconciliation => Ok(job.reconcile_result()?),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootFenceRuntimeV1<O = InstalledFenceStatusObserverV1, J = FixedFenceJobExecutorV1> {
    security: SecurityStore,
    observer: O,
    executor: J,
}

impl RootFenceRuntimeV1<InstalledFenceStatusObserverV1, FixedFenceJobExecutorV1> {
    pub const fn installed(security: SecurityStore) -> Self {
        Self {
            security,
            observer: InstalledFenceStatusObserverV1,
            executor: FixedFenceJobExecutorV1,
        }
    }
}

impl<O: FenceStatusObserverV1, J: AuthorizedFenceJobExecutorV1> RootFenceRuntimeV1<O, J> {
    pub const fn new(security: SecurityStore, observer: O, executor: J) -> Self {
        Self {
            security,
            observer,
            executor,
        }
    }

    pub fn observe_fence(
        &self,
        project_id: &ProjectId,
    ) -> Result<FenceObservation, RootFenceRuntimeError> {
        let Some(lease) = self.security.latest_fence(project_id)? else {
            return Ok(FenceObservation::Released);
        };
        if lease.project_id != *project_id {
            return Err(RootFenceRuntimeError::LeaseBindingMismatch);
        }
        let policy_digest = self.installed_policy_digest(&lease)?;
        let observed = self.observer.observe(project_id, &policy_digest)?;
        observation_from_status(&lease, &observed.document)
    }

    pub fn acquire_fence(&self, lease: &FenceLease) -> Result<(), RootFenceRuntimeError> {
        self.execute_transition(FenceAdapterActionV1::Acquire, lease)
    }

    pub fn release_fence(&self, lease: &FenceLease) -> Result<(), RootFenceRuntimeError> {
        self.execute_transition(FenceAdapterActionV1::ReleaseAndResume, lease)
    }

    fn execute_transition(
        &self,
        action: FenceAdapterActionV1,
        lease: &FenceLease,
    ) -> Result<(), RootFenceRuntimeError> {
        let current = self
            .security
            .latest_fence(&lease.project_id)?
            .ok_or(RootFenceRuntimeError::LeaseBindingMismatch)?;
        if current != *lease {
            return Err(RootFenceRuntimeError::LeaseBindingMismatch);
        }
        let policy_digest = self.installed_policy_digest(lease)?;
        let request = FenceAdapterRequestV1::from_lease(action, lease, policy_digest)?;
        let result = self.executor.execute(&request, lease)?;
        result.validate(&request)?;
        Ok(())
    }

    fn installed_policy_digest(
        &self,
        lease: &FenceLease,
    ) -> Result<EvidenceDigest, RootFenceRuntimeError> {
        let spec = load_bound_spec_from_store(
            &self.security,
            lease.attempt_id,
            OperationPhase::Draining,
            ExecutorPhaseBranch::Primary,
        )?;
        if spec.project_id != lease.project_id {
            return Err(RootFenceRuntimeError::LeaseBindingMismatch);
        }
        Ok(spec.installed_rimg_policy_digest)
    }
}

fn observation_from_status(
    lease: &FenceLease,
    status: &RimgOperationalStatusV1,
) -> Result<FenceObservation, RootFenceRuntimeError> {
    let common = status.schema_version == RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        && status.last_epoch == lease.epoch
        && status.last_token == Some(lease.token)
        && status.updated_at >= 0;
    let active = common
        && status.active_epoch == Some(lease.epoch)
        && status.active_token == Some(lease.token)
        && !status.intake_open
        && status.workers_drained
        && status.active_write_leases == 0
        && status.processing_jobs == 0
        && status.delivering_webhooks == 0;
    let fenced = active && status.mode == RimgOperationalModeV1::Fenced;
    let draining = active && status.mode == RimgOperationalModeV1::Draining;
    let resumed = common
        && status.mode == RimgOperationalModeV1::Normal
        && status.active_epoch.is_none()
        && status.active_token.is_none()
        && status.intake_open;

    let held = FenceObservation::Held {
        attempt_id: lease.attempt_id,
        epoch: lease.epoch,
        token: lease.token,
    };
    match lease.state {
        FenceJournalState::AcquireIntent if draining || resumed => Ok(FenceObservation::Released),
        FenceJournalState::AcquireIntent | FenceJournalState::Held if fenced => Ok(held),
        FenceJournalState::Held if draining || resumed => Ok(FenceObservation::Released),
        FenceJournalState::ReleaseIntent
        | FenceJournalState::Released
        | FenceJournalState::NeedsReconcile
            if fenced || draining =>
        {
            Ok(held)
        }
        FenceJournalState::ReleaseIntent
        | FenceJournalState::Released
        | FenceJournalState::NeedsReconcile
            if resumed =>
        {
            Ok(FenceObservation::Released)
        }
        _ => Err(RootFenceRuntimeError::ObservationMismatch),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootFenceRuntimeError {
    #[error("the security-journal fence lease does not match the requested root transition")]
    LeaseBindingMismatch,
    #[error("the live rimg status cannot be projected to the durable fence lease")]
    ObservationMismatch,
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    RootAdapter(#[from] crate::root_adapter_runtime::RootAdapterRuntimeError),
    #[error(transparent)]
    Fence(#[from] crate::fence_adapter::FenceAdapterError),
    #[error(transparent)]
    FenceJob(#[from] crate::fence_job::FenceJobError),
    #[error(transparent)]
    Rimg(#[from] crate::rimg_adapter::RimgAdapterError),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::store::FenceJournalState;

    fn lease(state: FenceJournalState) -> FenceLease {
        FenceLease {
            journal_id: 1,
            project_id: ProjectId::from_str("rimg")
                .unwrap_or_else(|error| panic!("project: {error}")),
            attempt_id: uuid::Uuid::new_v4(),
            epoch: 11,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 100,
            state,
            release_safe_receipt_digest: matches!(
                state,
                FenceJournalState::ReleaseIntent | FenceJournalState::Released
            )
            .then(|| EvidenceDigest::sha256("release receipt")),
        }
    }

    fn status(lease: &FenceLease, mode: RimgOperationalModeV1) -> RimgOperationalStatusV1 {
        let active = matches!(
            mode,
            RimgOperationalModeV1::Draining | RimgOperationalModeV1::Fenced
        );
        RimgOperationalStatusV1 {
            schema_version: RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION,
            mode,
            last_epoch: lease.epoch,
            last_token: Some(lease.token),
            active_epoch: active.then_some(lease.epoch),
            active_token: active.then_some(lease.token),
            intake_open: !active,
            workers_drained: active,
            active_write_leases: 0,
            processing_jobs: 0,
            delivering_webhooks: 0,
            updated_at: 200,
        }
    }

    #[test]
    fn acquire_and_release_crash_states_project_without_guessing() {
        let acquire = lease(FenceJournalState::AcquireIntent);
        assert_eq!(
            observation_from_status(&acquire, &status(&acquire, RimgOperationalModeV1::Draining))
                .unwrap_or_else(|error| panic!("draining acquire: {error}")),
            FenceObservation::Released
        );
        assert!(matches!(
            observation_from_status(&acquire, &status(&acquire, RimgOperationalModeV1::Fenced)),
            Ok(FenceObservation::Held { .. })
        ));

        let release = lease(FenceJournalState::ReleaseIntent);
        assert!(matches!(
            observation_from_status(&release, &status(&release, RimgOperationalModeV1::Draining)),
            Ok(FenceObservation::Held { .. })
        ));
        assert_eq!(
            observation_from_status(&release, &status(&release, RimgOperationalModeV1::Normal))
                .unwrap_or_else(|error| panic!("resumed release: {error}")),
            FenceObservation::Released
        );
    }

    #[test]
    fn foreign_or_incomplete_status_never_projects_as_held_or_released() {
        let lease = lease(FenceJournalState::Held);
        let mut foreign = status(&lease, RimgOperationalModeV1::Fenced);
        foreign.active_token = Some(uuid::Uuid::new_v4());
        assert!(matches!(
            observation_from_status(&lease, &foreign),
            Err(RootFenceRuntimeError::ObservationMismatch)
        ));
    }
}
