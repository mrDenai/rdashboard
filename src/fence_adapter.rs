use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{EvidenceDigest, ProjectId},
    rimg_adapter::{
        RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION, RimgAdapterError, RimgObservedDocumentV1,
        RimgOperationalModeV1, RimgOperationalStatusV1,
        runtime::{InstalledRimgAdminRuntimeV1, RimgAdminActionV1},
    },
    store::{FenceJournalState, FenceLease},
};

pub const FENCE_ADAPTER_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceAdapterActionV1 {
    Acquire,
    ReleaseAndResume,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FenceAdapterRequestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub action: FenceAdapterActionV1,
    pub project_id: ProjectId,
    pub attempt_id: uuid::Uuid,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub epoch: u64,
    pub token: uuid::Uuid,
    pub release_safe_receipt_digest: Option<EvidenceDigest>,
    pub request_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct FenceAdapterRequestDigestPayload<'a> {
    purpose: &'a str,
    schema_version: u16,
    action: FenceAdapterActionV1,
    project_id: &'a ProjectId,
    attempt_id: uuid::Uuid,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    epoch: u64,
    token: uuid::Uuid,
    release_safe_receipt_digest: &'a Option<EvidenceDigest>,
}

impl FenceAdapterRequestV1 {
    pub fn from_lease(
        action: FenceAdapterActionV1,
        lease: &FenceLease,
        installed_rimg_policy_digest: EvidenceDigest,
    ) -> Result<Self, FenceAdapterError> {
        let mut request = Self {
            purpose: "rdashboard.fence-adapter-request.v1".to_owned(),
            schema_version: FENCE_ADAPTER_SCHEMA_VERSION,
            action,
            project_id: lease.project_id.clone(),
            attempt_id: lease.attempt_id,
            installed_rimg_policy_digest,
            epoch: lease.epoch,
            token: lease.token,
            release_safe_receipt_digest: lease.release_safe_receipt_digest.clone(),
            request_digest: EvidenceDigest::sha256([]),
        };
        request.request_digest = request.calculate_digest()?;
        request.validate_for_lease(lease)?;
        Ok(request)
    }

    pub fn validate_for_lease(&self, lease: &FenceLease) -> Result<(), FenceAdapterError> {
        let state_matches = match self.action {
            FenceAdapterActionV1::Acquire => {
                matches!(
                    lease.state,
                    FenceJournalState::AcquireIntent | FenceJournalState::Held
                ) && self.release_safe_receipt_digest.is_none()
            }
            FenceAdapterActionV1::ReleaseAndResume => {
                matches!(
                    lease.state,
                    FenceJournalState::ReleaseIntent | FenceJournalState::Released
                ) && self.release_safe_receipt_digest.is_some()
            }
        };
        if self.purpose != "rdashboard.fence-adapter-request.v1"
            || self.schema_version != FENCE_ADAPTER_SCHEMA_VERSION
            || self.project_id != lease.project_id
            || self.attempt_id != lease.attempt_id
            || self.epoch != lease.epoch
            || self.token != lease.token
            || self.epoch == 0
            || self.attempt_id.is_nil()
            || self.token.is_nil()
            || self.release_safe_receipt_digest != lease.release_safe_receipt_digest
            || !state_matches
            || self.request_digest != self.calculate_digest()?
        {
            return Err(FenceAdapterError::RequestMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FenceAdapterError> {
        if self.request_digest != self.calculate_digest()? {
            return Err(FenceAdapterError::RequestMismatch);
        }
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FenceAdapterError> {
        let request: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&request)? != bytes
            || request.request_digest != request.calculate_digest()?
        {
            return Err(FenceAdapterError::RequestMismatch);
        }
        Ok(request)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, FenceAdapterError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &FenceAdapterRequestDigestPayload {
                purpose: &self.purpose,
                schema_version: self.schema_version,
                action: self.action,
                project_id: &self.project_id,
                attempt_id: self.attempt_id,
                installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
                epoch: self.epoch,
                token: self.token,
                release_safe_receipt_digest: &self.release_safe_receipt_digest,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FenceAdapterResultV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub request_digest: EvidenceDigest,
    pub completed_at_ms: i64,
    pub status: RimgOperationalStatusV1,
    pub status_observation_digest: EvidenceDigest,
    pub result_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct FenceAdapterResultDigestPayload<'a> {
    purpose: &'a str,
    schema_version: u16,
    request_digest: &'a EvidenceDigest,
    completed_at_ms: i64,
    status: &'a RimgOperationalStatusV1,
    status_observation_digest: &'a EvidenceDigest,
}

impl FenceAdapterResultV1 {
    pub fn new(
        request: &FenceAdapterRequestV1,
        completed_at_ms: i64,
        observed: RimgObservedDocumentV1<RimgOperationalStatusV1>,
    ) -> Result<Self, FenceAdapterError> {
        let mut result = Self {
            purpose: "rdashboard.fence-adapter-result.v1".to_owned(),
            schema_version: FENCE_ADAPTER_SCHEMA_VERSION,
            request_digest: request.request_digest.clone(),
            completed_at_ms,
            status: observed.document,
            status_observation_digest: observed.observation_digest,
            result_digest: EvidenceDigest::sha256([]),
        };
        result.result_digest = result.calculate_digest()?;
        result.validate(request)?;
        Ok(result)
    }

    pub fn validate(&self, request: &FenceAdapterRequestV1) -> Result<(), FenceAdapterError> {
        let status_matches = match request.action {
            FenceAdapterActionV1::Acquire => {
                self.status.mode == RimgOperationalModeV1::Fenced
                    && self.status.active_epoch == Some(request.epoch)
                    && self.status.active_token == Some(request.token)
                    && self.status.last_epoch == request.epoch
                    && self.status.last_token == Some(request.token)
                    && !self.status.intake_open
                    && self.status.workers_drained
                    && self.status.active_write_leases == 0
                    && self.status.processing_jobs == 0
                    && self.status.delivering_webhooks == 0
            }
            FenceAdapterActionV1::ReleaseAndResume => {
                self.status.mode == RimgOperationalModeV1::Normal
                    && self.status.active_epoch.is_none()
                    && self.status.active_token.is_none()
                    && self.status.last_epoch == request.epoch
                    && self.status.last_token == Some(request.token)
                    && self.status.intake_open
            }
        };
        if self.purpose != "rdashboard.fence-adapter-result.v1"
            || self.schema_version != FENCE_ADAPTER_SCHEMA_VERSION
            || self.request_digest != request.request_digest
            || self.completed_at_ms < 0
            || self.status.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
            || self.status.updated_at < 0
            || !status_matches
            || self.status_observation_digest
                != EvidenceDigest::sha256(serde_jcs::to_vec(&self.status)?)
            || self.result_digest != self.calculate_digest()?
        {
            return Err(FenceAdapterError::ResultMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FenceAdapterError> {
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(
        bytes: &[u8],
        request: &FenceAdapterRequestV1,
    ) -> Result<Self, FenceAdapterError> {
        let result: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&result)? != bytes {
            return Err(FenceAdapterError::ResultMismatch);
        }
        result.validate(request)?;
        Ok(result)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, FenceAdapterError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &FenceAdapterResultDigestPayload {
                purpose: &self.purpose,
                schema_version: self.schema_version,
                request_digest: &self.request_digest,
                completed_at_ms: self.completed_at_ms,
                status: &self.status,
                status_observation_digest: &self.status_observation_digest,
            },
        )?))
    }
}

pub trait FenceAdapterRuntimeV1 {
    fn transition(
        &mut self,
        request: &FenceAdapterRequestV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError>;
}

trait RimgFenceBackendV1 {
    fn status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError>;

    fn apply(
        &mut self,
        action: RimgAdminActionV1,
        request: &FenceAdapterRequestV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError>;
}

impl RimgFenceBackendV1 for InstalledRimgAdminRuntimeV1 {
    fn status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
        Ok(self.fence_status()?)
    }

    fn apply(
        &mut self,
        action: RimgAdminActionV1,
        request: &FenceAdapterRequestV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
        Ok(self.apply_admin_action_values(action, request.epoch, request.token)?)
    }
}

#[derive(Debug)]
pub struct InstalledFenceAdapterRuntimeV1 {
    inner: InstalledRimgAdminRuntimeV1,
}

impl InstalledFenceAdapterRuntimeV1 {
    pub fn new(
        job_directory: &std::path::Path,
        request: &FenceAdapterRequestV1,
    ) -> Result<Self, FenceAdapterError> {
        Ok(Self {
            inner: InstalledRimgAdminRuntimeV1::new_fence(
                job_directory,
                &request.project_id,
                &request.installed_rimg_policy_digest,
            )?,
        })
    }
}

impl FenceAdapterRuntimeV1 for InstalledFenceAdapterRuntimeV1 {
    fn transition(
        &mut self,
        request: &FenceAdapterRequestV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
        transition_fence(request, &mut self.inner)
    }
}

fn transition_fence<B: RimgFenceBackendV1>(
    request: &FenceAdapterRequestV1,
    backend: &mut B,
) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
    let observed = backend.status()?;
    match request.action {
        FenceAdapterActionV1::Acquire => {
            if status_is_fenced(&observed.document, request) {
                return Ok(observed);
            }
            if !status_is_draining(&observed.document, request) {
                return Err(FenceAdapterError::ResultMismatch);
            }
            let acquired = backend.apply(RimgAdminActionV1::AcquireFence, request)?;
            if !status_is_fenced(&acquired.document, request) {
                return Err(FenceAdapterError::ResultMismatch);
            }
            Ok(acquired)
        }
        FenceAdapterActionV1::ReleaseAndResume => {
            if status_is_resumed(&observed.document, request) {
                return Ok(observed);
            }
            let draining = if status_is_fenced(&observed.document, request) {
                let released = backend.apply(RimgAdminActionV1::ReleaseFence, request)?;
                if !status_is_draining(&released.document, request) {
                    return Err(FenceAdapterError::ResultMismatch);
                }
                released
            } else if status_is_draining(&observed.document, request) {
                observed
            } else {
                return Err(FenceAdapterError::ResultMismatch);
            };
            if !status_is_draining(&draining.document, request) {
                return Err(FenceAdapterError::ResultMismatch);
            }
            let resumed = backend.apply(RimgAdminActionV1::Resume, request)?;
            if !status_is_resumed(&resumed.document, request) {
                return Err(FenceAdapterError::ResultMismatch);
            }
            Ok(resumed)
        }
    }
}

fn status_has_identity(status: &RimgOperationalStatusV1, request: &FenceAdapterRequestV1) -> bool {
    status.schema_version == RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        && status.last_epoch == request.epoch
        && status.last_token == Some(request.token)
        && status.active_epoch == Some(request.epoch)
        && status.active_token == Some(request.token)
        && !status.intake_open
        && status.updated_at >= 0
}

fn status_is_draining(status: &RimgOperationalStatusV1, request: &FenceAdapterRequestV1) -> bool {
    status_has_identity(status, request)
        && status.mode == RimgOperationalModeV1::Draining
        && status.workers_drained
        && status.active_write_leases == 0
        && status.processing_jobs == 0
        && status.delivering_webhooks == 0
}

fn status_is_fenced(status: &RimgOperationalStatusV1, request: &FenceAdapterRequestV1) -> bool {
    status_has_identity(status, request)
        && status.mode == RimgOperationalModeV1::Fenced
        && status.workers_drained
        && status.active_write_leases == 0
        && status.processing_jobs == 0
        && status.delivering_webhooks == 0
}

fn status_is_resumed(status: &RimgOperationalStatusV1, request: &FenceAdapterRequestV1) -> bool {
    status.schema_version == RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        && status.mode == RimgOperationalModeV1::Normal
        && status.last_epoch == request.epoch
        && status.last_token == Some(request.token)
        && status.active_epoch.is_none()
        && status.active_token.is_none()
        && status.intake_open
        && status.updated_at >= 0
}

pub fn execute_fence_adapter<R: FenceAdapterRuntimeV1>(
    request: &FenceAdapterRequestV1,
    runtime: &mut R,
    completed_at_ms: i64,
) -> Result<FenceAdapterResultV1, FenceAdapterError> {
    if request.request_digest != request.calculate_digest()? || completed_at_ms < 0 {
        return Err(FenceAdapterError::RequestMismatch);
    }
    FenceAdapterResultV1::new(request, completed_at_ms, runtime.transition(request)?)
}

#[derive(Debug, thiserror::Error)]
pub enum FenceAdapterError {
    #[error("the fixed fence request does not match the root security-journal lease")]
    RequestMismatch,
    #[error("the observed rimg fence state does not match the requested transition")]
    ResultMismatch,
    #[error("fixed fence adapter runtime failed")]
    RuntimeFailure,
    #[error(transparent)]
    Rimg(#[from] RimgAdapterError),
    #[error("canonical fence adapter encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, str::FromStr as _};

    use super::*;

    struct FakeRuntime {
        status: RimgOperationalStatusV1,
    }

    struct ScriptedBackend {
        statuses: VecDeque<RimgOperationalStatusV1>,
        actions: Vec<RimgAdminActionV1>,
    }

    impl RimgFenceBackendV1 for ScriptedBackend {
        fn status(
            &mut self,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
            observed(
                self.statuses
                    .pop_front()
                    .ok_or(FenceAdapterError::RuntimeFailure)?,
            )
        }

        fn apply(
            &mut self,
            action: RimgAdminActionV1,
            _request: &FenceAdapterRequestV1,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
            self.actions.push(action);
            observed(
                self.statuses
                    .pop_front()
                    .ok_or(FenceAdapterError::RuntimeFailure)?,
            )
        }
    }

    fn observed(
        status: RimgOperationalStatusV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
        Ok(RimgObservedDocumentV1::from_document(status)?)
    }

    impl FenceAdapterRuntimeV1 for FakeRuntime {
        fn transition(
            &mut self,
            _request: &FenceAdapterRequestV1,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, FenceAdapterError> {
            RimgObservedDocumentV1::from_document(self.status.clone())
                .map_err(|_| FenceAdapterError::RuntimeFailure)
        }
    }

    fn lease(state: FenceJournalState) -> FenceLease {
        FenceLease {
            journal_id: 1,
            project_id: ProjectId::from_str("rimg")
                .unwrap_or_else(|error| panic!("project: {error}")),
            attempt_id: uuid::Uuid::new_v4(),
            epoch: 7,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 100,
            state,
            release_safe_receipt_digest: (state == FenceJournalState::ReleaseIntent)
                .then(|| EvidenceDigest::sha256("release receipt")),
        }
    }

    fn status(request: &FenceAdapterRequestV1, released: bool) -> RimgOperationalStatusV1 {
        RimgOperationalStatusV1 {
            schema_version: RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION,
            mode: if released {
                RimgOperationalModeV1::Normal
            } else {
                RimgOperationalModeV1::Fenced
            },
            last_epoch: request.epoch,
            last_token: Some(request.token),
            active_epoch: (!released).then_some(request.epoch),
            active_token: (!released).then_some(request.token),
            intake_open: released,
            workers_drained: !released,
            active_write_leases: 0,
            processing_jobs: 0,
            delivering_webhooks: 0,
            updated_at: 1,
        }
    }

    fn draining_status(request: &FenceAdapterRequestV1) -> RimgOperationalStatusV1 {
        let mut draining = status(request, false);
        draining.mode = RimgOperationalModeV1::Draining;
        draining
    }

    #[test]
    fn exact_acquire_and_release_results_are_lease_bound() {
        for (action, lease_state, released) in [
            (
                FenceAdapterActionV1::Acquire,
                FenceJournalState::AcquireIntent,
                false,
            ),
            (
                FenceAdapterActionV1::ReleaseAndResume,
                FenceJournalState::ReleaseIntent,
                true,
            ),
        ] {
            let lease = lease(lease_state);
            let request = FenceAdapterRequestV1::from_lease(
                action,
                &lease,
                EvidenceDigest::sha256("installed rimg policy"),
            )
            .unwrap_or_else(|error| panic!("request: {error}"));
            let mut runtime = FakeRuntime {
                status: status(&request, released),
            };
            let result = execute_fence_adapter(&request, &mut runtime, 200)
                .unwrap_or_else(|error| panic!("execute: {error}"));
            result
                .validate(&request)
                .unwrap_or_else(|error| panic!("validate: {error}"));
        }
    }

    #[test]
    fn released_state_cannot_satisfy_an_acquire_request() {
        let lease = lease(FenceJournalState::AcquireIntent);
        let request = FenceAdapterRequestV1::from_lease(
            FenceAdapterActionV1::Acquire,
            &lease,
            EvidenceDigest::sha256("installed rimg policy"),
        )
        .unwrap_or_else(|error| panic!("request: {error}"));
        let mut runtime = FakeRuntime {
            status: status(&request, true),
        };
        assert!(matches!(
            execute_fence_adapter(&request, &mut runtime, 200),
            Err(FenceAdapterError::ResultMismatch)
        ));
    }

    #[test]
    fn transition_sequence_is_restart_safe_at_every_fence_boundary() {
        let acquire_lease = lease(FenceJournalState::AcquireIntent);
        let acquire = FenceAdapterRequestV1::from_lease(
            FenceAdapterActionV1::Acquire,
            &acquire_lease,
            EvidenceDigest::sha256("installed rimg policy"),
        )
        .unwrap_or_else(|error| panic!("acquire request: {error}"));
        let mut acquiring = ScriptedBackend {
            statuses: VecDeque::from([draining_status(&acquire), status(&acquire, false)]),
            actions: Vec::new(),
        };
        transition_fence(&acquire, &mut acquiring)
            .unwrap_or_else(|error| panic!("acquire: {error}"));
        assert_eq!(acquiring.actions, [RimgAdminActionV1::AcquireFence]);

        let mut acquired_replay = ScriptedBackend {
            statuses: VecDeque::from([status(&acquire, false)]),
            actions: Vec::new(),
        };
        transition_fence(&acquire, &mut acquired_replay)
            .unwrap_or_else(|error| panic!("acquire replay: {error}"));
        assert!(acquired_replay.actions.is_empty());

        let release_lease = lease(FenceJournalState::ReleaseIntent);
        let release = FenceAdapterRequestV1::from_lease(
            FenceAdapterActionV1::ReleaseAndResume,
            &release_lease,
            EvidenceDigest::sha256("installed rimg policy"),
        )
        .unwrap_or_else(|error| panic!("release request: {error}"));
        let mut releasing = ScriptedBackend {
            statuses: VecDeque::from([
                status(&release, false),
                draining_status(&release),
                status(&release, true),
            ]),
            actions: Vec::new(),
        };
        transition_fence(&release, &mut releasing)
            .unwrap_or_else(|error| panic!("release: {error}"));
        assert_eq!(
            releasing.actions,
            [RimgAdminActionV1::ReleaseFence, RimgAdminActionV1::Resume]
        );

        let mut released_before_resume = ScriptedBackend {
            statuses: VecDeque::from([draining_status(&release), status(&release, true)]),
            actions: Vec::new(),
        };
        transition_fence(&release, &mut released_before_resume)
            .unwrap_or_else(|error| panic!("release crash replay: {error}"));
        assert_eq!(released_before_resume.actions, [RimgAdminActionV1::Resume]);
    }
}
