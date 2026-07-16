use crate::{
    adapter::{AdapterExecutionCancellationV1, SystemdTransientAdapterRunnerV1},
    adapter_phase::FixedAdapterPhaseExecutorV1,
    executor::{
        EffectObservation, ExternalEffectError, ExternalEffects, PhaseEffectEvidence, PhaseIntent,
        PhaseOperationIdentityLeaseV1,
    },
    root_adapter_runtime::RootAdapterPhaseRuntimeV1,
    root_fence_runtime::RootFenceRuntimeV1,
    store::{FenceLease, FenceObservation, SecurityStore},
    unix_time_ms,
};

pub trait NonPrivilegedPhaseEffectsV1: Clone + Send + Sync + 'static {
    fn observe_non_privileged(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError>;

    fn apply_non_privileged(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectNonPrivilegedPhaseEffectsV1;

impl NonPrivilegedPhaseEffectsV1 for RejectNonPrivilegedPhaseEffectsV1 {
    fn observe_non_privileged(
        &self,
        _intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        Err(ExternalEffectError::ConflictingState)
    }

    fn apply_non_privileged(&self, _intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        Err(ExternalEffectError::ConflictingState)
    }
}

impl<T: ExternalEffects> NonPrivilegedPhaseEffectsV1 for T {
    fn observe_non_privileged(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        self.observe_phase(intent)
    }

    fn apply_non_privileged(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        self.apply_phase(intent)
    }
}

#[derive(Clone, Debug)]
pub struct InstalledAdapterExternalEffectsV1<D> {
    phase: RootAdapterPhaseRuntimeV1<FixedAdapterPhaseExecutorV1<SystemdTransientAdapterRunnerV1>>,
    fence: RootFenceRuntimeV1,
    delegate: D,
}

impl<D: NonPrivilegedPhaseEffectsV1> InstalledAdapterExternalEffectsV1<D> {
    pub fn new(security: SecurityStore, delegate: D) -> Self {
        Self::new_with_cancellation(
            security,
            delegate,
            AdapterExecutionCancellationV1::default(),
        )
    }

    pub fn new_with_cancellation(
        security: SecurityStore,
        delegate: D,
        cancellation: AdapterExecutionCancellationV1,
    ) -> Self {
        Self {
            phase: RootAdapterPhaseRuntimeV1::new(
                security.clone(),
                FixedAdapterPhaseExecutorV1::installed_with_cancellation(cancellation),
            ),
            fence: RootFenceRuntimeV1::installed(security),
            delegate,
        }
    }

    fn observe_privileged(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        let projection = self
            .phase
            .observe_bound_phase(intent)
            .map_err(|_| ExternalEffectError::ConflictingState)?;
        Ok(projection.map_or(EffectObservation::Absent, |projection| {
            EffectObservation::Applied(Box::new(PhaseEffectEvidence {
                intent_digest: intent.digest.clone(),
                observation_digest: projection.observation_digest,
                artifacts: projection.artifacts,
            }))
        }))
    }

    fn apply_privileged(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        let now_ms = unix_time_ms().map_err(|_| ExternalEffectError::ConflictingState)?;
        self.phase
            .execute_bound_phase(intent, now_ms)
            .map(|_| ())
            .map_err(|_| ExternalEffectError::ConflictingState)
    }
}

impl<D: NonPrivilegedPhaseEffectsV1> ExternalEffects for InstalledAdapterExternalEffectsV1<D> {
    fn observe_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        if privileged_phase(intent.phase) {
            self.observe_privileged(intent)
        } else {
            self.delegate.observe_non_privileged(intent)
        }
    }

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        if privileged_phase(intent.phase) {
            self.apply_privileged(intent)
        } else {
            self.delegate.apply_non_privileged(intent)
        }
    }

    fn observe_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        _operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<EffectObservation, ExternalEffectError> {
        self.observe_phase(intent)
    }

    fn apply_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        _operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<(), ExternalEffectError> {
        self.apply_phase(intent)
    }

    fn observe_fence(
        &self,
        project_id: &crate::domain::ProjectId,
    ) -> Result<FenceObservation, ExternalEffectError> {
        self.fence
            .observe_fence(project_id)
            .map_err(|_| ExternalEffectError::ConflictingState)
    }

    fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.fence
            .acquire_fence(lease)
            .map_err(|_| ExternalEffectError::ConflictingState)
    }

    fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.fence
            .release_fence(lease)
            .map_err(|_| ExternalEffectError::ConflictingState)
    }
}

const fn privileged_phase(phase: crate::domain::OperationPhase) -> bool {
    matches!(
        phase,
        crate::domain::OperationPhase::BackingUp
            | crate::domain::OperationPhase::Draining
            | crate::domain::OperationPhase::CutoverSnapshotting
            | crate::domain::OperationPhase::Migrating
            | crate::domain::OperationPhase::Deploying
            | crate::domain::OperationPhase::HealthChecking
            | crate::domain::OperationPhase::Soaking
            | crate::domain::OperationPhase::Rollback
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OperationPhase;

    #[test]
    fn privileged_phase_routing_is_explicit_and_complete() {
        for phase in [
            OperationPhase::BackingUp,
            OperationPhase::Draining,
            OperationPhase::CutoverSnapshotting,
            OperationPhase::Migrating,
            OperationPhase::Deploying,
            OperationPhase::HealthChecking,
            OperationPhase::Soaking,
            OperationPhase::Rollback,
        ] {
            assert!(privileged_phase(phase));
        }
        assert!(!privileged_phase(OperationPhase::Building));
    }
}
