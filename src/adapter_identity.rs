use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    backup::BackupSnapshotKindV1,
    domain::{EvidenceDigest, ProjectId},
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1, FixedAdapterRequestV1},
    store::{BackupBoundaryLease, DrainIdentityLease, FenceJournalState, FenceLease},
};

pub const ADAPTER_OPERATION_IDENTITY_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOperationIdentityKindV1 {
    BaseBackup,
    Drain,
    Fence,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterOperationIdentityV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub kind: AdapterOperationIdentityKindV1,
    pub attempt_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub authorized_phase_spec_digest: EvidenceDigest,
    pub sequence: u16,
    pub profile: FixedAdapterProfileV1,
    pub epoch: u64,
    pub token: uuid::Uuid,
    pub lease_created_at_ms: i64,
    pub identity_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct AdapterOperationIdentityDigestPayload<'a> {
    purpose: &'a str,
    schema_version: u16,
    kind: AdapterOperationIdentityKindV1,
    attempt_id: uuid::Uuid,
    project_id: &'a ProjectId,
    authorized_phase_spec_digest: &'a EvidenceDigest,
    sequence: u16,
    profile: FixedAdapterProfileV1,
    epoch: u64,
    token: uuid::Uuid,
    lease_created_at_ms: i64,
}

impl AdapterOperationIdentityV1 {
    pub fn from_backup_boundary(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        lease: &BackupBoundaryLease,
    ) -> Result<Self, AdapterIdentityError> {
        if lease.project_id != spec.project_id || lease.attempt_id != spec.attempt_id {
            return Err(AdapterIdentityError::LeaseBindingMismatch);
        }
        Self::new(
            spec,
            sequence,
            AdapterOperationIdentityKindV1::BaseBackup,
            lease.epoch,
            lease.token,
            lease.created_at_ms,
        )
    }

    pub fn from_drain_lease(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        lease: &DrainIdentityLease,
    ) -> Result<Self, AdapterIdentityError> {
        if lease.project_id != spec.project_id || lease.attempt_id != spec.attempt_id {
            return Err(AdapterIdentityError::LeaseBindingMismatch);
        }
        Self::new(
            spec,
            sequence,
            AdapterOperationIdentityKindV1::Drain,
            lease.epoch,
            lease.token,
            lease.created_at_ms,
        )
    }

    pub fn from_fence_lease(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        lease: &FenceLease,
    ) -> Result<Self, AdapterIdentityError> {
        if lease.project_id != spec.project_id
            || lease.attempt_id != spec.attempt_id
            || lease.state != FenceJournalState::Held
            || spec.fencing_epoch != Some(lease.epoch)
        {
            return Err(AdapterIdentityError::LeaseBindingMismatch);
        }
        Self::new(
            spec,
            sequence,
            AdapterOperationIdentityKindV1::Fence,
            lease.epoch,
            lease.token,
            lease.created_at_ms,
        )
    }

    fn new(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        kind: AdapterOperationIdentityKindV1,
        epoch: u64,
        token: uuid::Uuid,
        lease_created_at_ms: i64,
    ) -> Result<Self, AdapterIdentityError> {
        let request = spec.fixed_adapter_request(sequence)?;
        let mut identity = Self {
            purpose: "rdashboard.adapter-operation-identity.v1".to_owned(),
            schema_version: ADAPTER_OPERATION_IDENTITY_SCHEMA_VERSION,
            kind,
            attempt_id: spec.attempt_id,
            project_id: spec.project_id.clone(),
            authorized_phase_spec_digest: spec.spec_digest.clone(),
            sequence,
            profile: request.profile,
            epoch,
            token,
            lease_created_at_ms,
            identity_digest: EvidenceDigest::sha256([]),
        };
        identity.identity_digest = identity.calculate_digest()?;
        identity.validate_for(spec, &request)?;
        Ok(identity)
    }

    pub fn validate_for(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        request: &FixedAdapterRequestV1,
    ) -> Result<(), AdapterIdentityError> {
        let kind_matches_profile = match self.kind {
            AdapterOperationIdentityKindV1::BaseBackup => {
                self.profile == FixedAdapterProfileV1::BackupCapture
                    && spec.backup.as_ref().is_some_and(|backup| {
                        backup.snapshot_kind == BackupSnapshotKindV1::Base
                            && backup.fencing_epoch.is_none()
                    })
            }
            AdapterOperationIdentityKindV1::Drain => {
                self.profile == FixedAdapterProfileV1::RimgDrain
            }
            AdapterOperationIdentityKindV1::Fence => matches!(
                self.profile,
                FixedAdapterProfileV1::BackupCapture | FixedAdapterProfileV1::RimgMigrate
            ),
        };
        if self.purpose != "rdashboard.adapter-operation-identity.v1"
            || self.schema_version != ADAPTER_OPERATION_IDENTITY_SCHEMA_VERSION
            || self.attempt_id != spec.attempt_id
            || self.project_id != spec.project_id
            || self.authorized_phase_spec_digest != spec.spec_digest
            || self.sequence != request.sequence
            || self.profile != request.profile
            || self.epoch == 0
            || self.epoch > i64::MAX.unsigned_abs()
            || self.token.is_nil()
            || self.lease_created_at_ms < 0
            || !kind_matches_profile
            || self.identity_digest != self.calculate_digest()?
        {
            return Err(AdapterIdentityError::InvalidDocument);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdapterIdentityError> {
        if self.identity_digest != self.calculate_digest()? {
            return Err(AdapterIdentityError::InvalidDocument);
        }
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_authorized(
        bytes: &[u8],
        spec: &AuthorizedPhaseSpecV1,
        request: &FixedAdapterRequestV1,
    ) -> Result<Self, AdapterIdentityError> {
        let identity: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&identity)? != bytes {
            return Err(AdapterIdentityError::NonCanonicalDocument);
        }
        identity.validate_for(spec, request)?;
        Ok(identity)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, AdapterIdentityError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &AdapterOperationIdentityDigestPayload {
                purpose: &self.purpose,
                schema_version: self.schema_version,
                kind: self.kind,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                authorized_phase_spec_digest: &self.authorized_phase_spec_digest,
                sequence: self.sequence,
                profile: self.profile,
                epoch: self.epoch,
                token: self.token,
                lease_created_at_ms: self.lease_created_at_ms,
            },
        )?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterIdentityError {
    #[error("adapter operation lease does not belong to the authorized attempt and phase")]
    LeaseBindingMismatch,
    #[error("adapter operation identity is invalid or not authorized for this profile")]
    InvalidDocument,
    #[error("adapter operation identity is not canonical JCS")]
    NonCanonicalDocument,
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error("adapter operation identity encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase6::tests::test_migration_phase_spec;

    fn held_fence(spec: &AuthorizedPhaseSpecV1) -> FenceLease {
        FenceLease {
            journal_id: 11,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: spec.fencing_epoch.unwrap_or(0),
            token: uuid::Uuid::new_v4(),
            created_at_ms: 1_000,
            state: FenceJournalState::Held,
            release_safe_receipt_digest: None,
        }
    }

    #[test]
    fn fenced_migration_identity_is_canonical_and_bound_to_the_exact_step() {
        let spec = test_migration_phase_spec();
        let lease = held_fence(&spec);
        let identity = AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease)
            .unwrap_or_else(|error| panic!("identity: {error}"));
        let request = spec
            .fixed_adapter_request(2)
            .unwrap_or_else(|error| panic!("request: {error}"));
        assert_eq!(identity.kind, AdapterOperationIdentityKindV1::Fence);
        assert_eq!(identity.profile, FixedAdapterProfileV1::RimgMigrate);
        assert_eq!(identity.epoch, 7);
        assert_eq!(identity.token, lease.token);

        let bytes = identity
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("identity bytes: {error}"));
        assert_eq!(
            AdapterOperationIdentityV1::decode_authorized(&bytes, &spec, &request)
                .unwrap_or_else(|error| panic!("decode identity: {error}")),
            identity
        );

        let inspect_request = spec
            .fixed_adapter_request(1)
            .unwrap_or_else(|error| panic!("inspect request: {error}"));
        assert!(matches!(
            AdapterOperationIdentityV1::decode_authorized(&bytes, &spec, &inspect_request),
            Err(AdapterIdentityError::InvalidDocument)
        ));
    }

    #[test]
    fn fence_identity_rejects_non_held_or_foreign_lease_and_tampering() {
        let spec = test_migration_phase_spec();
        let mut lease = held_fence(&spec);
        lease.state = FenceJournalState::NeedsReconcile;
        assert!(matches!(
            AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease),
            Err(AdapterIdentityError::LeaseBindingMismatch)
        ));

        lease = held_fence(&spec);
        lease.attempt_id = uuid::Uuid::new_v4();
        assert!(matches!(
            AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease),
            Err(AdapterIdentityError::LeaseBindingMismatch)
        ));

        lease = held_fence(&spec);
        let mut identity = AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease)
            .unwrap_or_else(|error| panic!("identity: {error}"));
        identity.token = uuid::Uuid::new_v4();
        assert!(matches!(
            identity.canonical_bytes(),
            Err(AdapterIdentityError::InvalidDocument)
        ));
    }
}
