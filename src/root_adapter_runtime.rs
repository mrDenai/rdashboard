use crate::{
    adapter_identity::AdapterOperationIdentityV1,
    adapter_phase::AuthorizedAdapterPhaseExecutorV1,
    adapter_result::PhaseExecutionProjectionV1,
    backup::BackupSnapshotKindV1,
    domain::{EvidenceDigest, ExecutorPhaseBranch, OperationPhase},
    executor::PhaseIntent,
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1},
    store::{
        BackupBoundaryLease, DrainIdentityLease, FenceLease, SecurityStore,
        VerifiedBackupChainBinding,
    },
};

#[derive(Clone, Debug)]
pub struct RootAdapterPhaseRuntimeV1<E> {
    security: SecurityStore,
    executor: E,
}

impl<E: AuthorizedAdapterPhaseExecutorV1> RootAdapterPhaseRuntimeV1<E> {
    pub const fn new(security: SecurityStore, executor: E) -> Self {
        Self { security, executor }
    }

    pub fn observe_bound_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<Option<PhaseExecutionProjectionV1>, RootAdapterRuntimeError> {
        let spec = self.load_bound_intent_spec(intent)?;
        let projection = self.executor.observe_authorized(&spec)?;
        if let Some(projection) = projection.as_ref() {
            self.persist_verified_backup_chain(&spec, projection)?;
        }
        Ok(projection)
    }

    pub fn execute_bound_phase(
        &self,
        intent: &PhaseIntent,
        authorized_at_ms: i64,
    ) -> Result<PhaseExecutionProjectionV1, RootAdapterRuntimeError> {
        let spec = self.load_bound_intent_spec(intent)?;
        if let Some(projection) = self.executor.observe_authorized(&spec)? {
            self.persist_verified_backup_chain(&spec, &projection)?;
            return Ok(projection);
        }

        let permit = self.security.authorize_bound_phase_spec(
            intent.attempt_id,
            intent.phase,
            intent.branch,
            authorized_at_ms,
        )?;
        if permit.attempt_id != spec.attempt_id
            || permit.project_id != spec.project_id
            || permit.phase != spec.phase
            || permit.branch != spec.branch
            || permit.intent_digest != spec.intent_digest
            || permit.spec_digest != spec.spec_digest
            || permit.document_digest != EvidenceDigest::sha256(spec.canonical_bytes()?)
        {
            return Err(RootAdapterRuntimeError::PermitBindingMismatch);
        }

        let identities = self.operation_identities(&spec)?;
        let projection = self.executor.execute_authorized(&spec, &identities)?;
        self.persist_verified_backup_chain(&spec, &projection)?;
        Ok(projection)
    }

    fn load_bound_intent_spec(
        &self,
        intent: &PhaseIntent,
    ) -> Result<AuthorizedPhaseSpecV1, RootAdapterRuntimeError> {
        if !intent.has_valid_digest()? {
            return Err(RootAdapterRuntimeError::IntentBindingMismatch);
        }
        let spec = load_bound_spec_from_store(
            &self.security,
            intent.attempt_id,
            intent.phase,
            intent.branch,
        )?;
        if spec.project_id != intent.project_id
            || spec.intent_digest != intent.digest
            || spec.request_id != intent.payload.request_id
            || spec.operation_kind != intent.payload.operation_kind
        {
            return Err(RootAdapterRuntimeError::IntentBindingMismatch);
        }
        Ok(spec)
    }

    fn operation_identities(
        &self,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Vec<AdapterOperationIdentityV1>, RootAdapterRuntimeError> {
        let needs_backup_boundary = spec.steps.iter().any(|step| {
            step.profile == FixedAdapterProfileV1::BackupCapture
                && spec
                    .backup
                    .as_ref()
                    .is_some_and(|backup| backup.snapshot_kind == BackupSnapshotKindV1::Base)
        });
        let needs_drain = spec
            .steps
            .iter()
            .any(|step| step.profile == FixedAdapterProfileV1::RimgDrain);
        let needs_fence = spec.steps.iter().any(|step| {
            step.profile == FixedAdapterProfileV1::RimgMigrate
                || step.profile == FixedAdapterProfileV1::BackupCapture
                    && spec
                        .backup
                        .as_ref()
                        .is_some_and(|backup| backup.snapshot_kind == BackupSnapshotKindV1::Cutover)
        });
        let backup_boundary = needs_backup_boundary
            .then(|| self.security.active_backup_boundary(&spec.project_id))
            .transpose()?
            .flatten();
        let drain = needs_drain
            .then(|| self.security.active_drain_identity(&spec.project_id))
            .transpose()?
            .flatten();
        let fence = needs_fence
            .then(|| self.security.active_fence(&spec.project_id))
            .transpose()?
            .flatten();
        operation_identities_from_leases(
            spec,
            backup_boundary.as_ref(),
            drain.as_ref(),
            fence.as_ref(),
        )
    }

    fn persist_verified_backup_chain(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        projection: &PhaseExecutionProjectionV1,
    ) -> Result<(), RootAdapterRuntimeError> {
        if let Some(chain) = projection.verified_backup_chain.as_ref() {
            self.security
                .bind_verified_backup_chain(VerifiedBackupChainBinding {
                    attempt_id: spec.attempt_id,
                    project_id: &spec.project_id,
                    phase: spec.phase,
                    branch: spec.branch,
                    authorized_phase_spec_digest: &spec.spec_digest,
                    chain,
                    persisted_at_ms: projection.completed_at_ms,
                })?;
        }
        Ok(())
    }
}

pub(crate) fn load_bound_spec_from_store(
    security: &SecurityStore,
    attempt_id: uuid::Uuid,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
) -> Result<AuthorizedPhaseSpecV1, RootAdapterRuntimeError> {
    let record = security
        .authorized_phase_spec_in_branch(attempt_id, phase, branch)?
        .ok_or(RootAdapterRuntimeError::AuthorizedSpecMissing)?;
    let spec = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)?;
    if record.attempt_id != attempt_id
        || record.project_id != spec.project_id
        || record.phase != phase
        || record.branch != branch
        || record.intent_digest != spec.intent_digest
        || record.spec_digest != spec.spec_digest
        || record.document_digest != EvidenceDigest::sha256(&record.canonical_json)
        || spec.attempt_id != attempt_id
        || spec.phase != phase
        || spec.branch != branch
    {
        return Err(RootAdapterRuntimeError::AuthorizedSpecBindingMismatch);
    }
    Ok(spec)
}

fn operation_identities_from_leases(
    spec: &AuthorizedPhaseSpecV1,
    backup_boundary: Option<&BackupBoundaryLease>,
    drain: Option<&DrainIdentityLease>,
    fence: Option<&FenceLease>,
) -> Result<Vec<AdapterOperationIdentityV1>, RootAdapterRuntimeError> {
    let mut identities = Vec::new();
    for step in &spec.steps {
        let identity = match step.profile {
            FixedAdapterProfileV1::BackupCapture => {
                match spec.backup.as_ref().map(|backup| backup.snapshot_kind) {
                    Some(BackupSnapshotKindV1::Base) => {
                        Some(AdapterOperationIdentityV1::from_backup_boundary(
                            spec,
                            step.sequence,
                            backup_boundary
                                .ok_or(RootAdapterRuntimeError::OperationIdentityUnavailable)?,
                        )?)
                    }
                    Some(BackupSnapshotKindV1::Cutover) => {
                        Some(AdapterOperationIdentityV1::from_fence_lease(
                            spec,
                            step.sequence,
                            fence.ok_or(RootAdapterRuntimeError::OperationIdentityUnavailable)?,
                        )?)
                    }
                    None => return Err(RootAdapterRuntimeError::OperationIdentityUnavailable),
                }
            }
            FixedAdapterProfileV1::RimgDrain => Some(AdapterOperationIdentityV1::from_drain_lease(
                spec,
                step.sequence,
                drain.ok_or(RootAdapterRuntimeError::OperationIdentityUnavailable)?,
            )?),
            FixedAdapterProfileV1::RimgMigrate => {
                Some(AdapterOperationIdentityV1::from_fence_lease(
                    spec,
                    step.sequence,
                    fence.ok_or(RootAdapterRuntimeError::OperationIdentityUnavailable)?,
                )?)
            }
            _ => None,
        };
        identities.extend(identity);
    }
    Ok(identities)
}

#[derive(Debug, thiserror::Error)]
pub enum RootAdapterRuntimeError {
    #[error("the security journal does not contain the requested authorized phase spec")]
    AuthorizedSpecMissing,
    #[error("the persisted authorized phase spec does not match its security-journal binding")]
    AuthorizedSpecBindingMismatch,
    #[error("the caller phase intent does not exactly match the root-authorized phase spec")]
    IntentBindingMismatch,
    #[error("the durable phase permit does not match the authorized adapter spec")]
    PermitBindingMismatch,
    #[error("the required root-owned backup, drain or fence identity is unavailable")]
    OperationIdentityUnavailable,
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error(transparent)]
    Identity(#[from] crate::adapter_identity::AdapterIdentityError),
    #[error(transparent)]
    Adapter(#[from] crate::adapter_phase::AdapterPhaseError),
    #[error("phase intent canonical encoding failed: {0}")]
    IntentEncoding(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        phase6::tests::{test_bootstrap_phase_spec, test_migration_phase_spec},
        store::FenceJournalState,
    };

    #[test]
    fn root_identity_resolution_requires_the_exact_active_fence() {
        let spec = test_migration_phase_spec();
        assert!(matches!(
            operation_identities_from_leases(&spec, None, None, None),
            Err(RootAdapterRuntimeError::OperationIdentityUnavailable)
        ));

        let fence = FenceLease {
            journal_id: 1,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: spec.fencing_epoch.unwrap_or(0),
            token: uuid::Uuid::new_v4(),
            created_at_ms: 500,
            state: FenceJournalState::Held,
            release_safe_receipt_digest: None,
        };
        let identities = operation_identities_from_leases(&spec, None, None, Some(&fence))
            .unwrap_or_else(|error| panic!("resolve identities: {error}"));
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].sequence, 2);
        assert_eq!(identities[0].epoch, fence.epoch);
        assert_eq!(identities[0].token, fence.token);
    }

    #[test]
    fn bootstrap_has_no_fabricated_operation_identity() {
        assert!(
            operation_identities_from_leases(&test_bootstrap_phase_spec(), None, None, None)
                .unwrap_or_else(|error| panic!("bootstrap identities: {error}"))
                .is_empty()
        );
    }
}
