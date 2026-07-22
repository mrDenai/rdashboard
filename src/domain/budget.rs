use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::EvidenceDigest;
use crate::build_storage::recovery_reserve_bytes;

pub const GIB: u64 = 1024 * 1024 * 1024;
pub const CONTROL_SQLITE_CAP_BYTES: u64 = 512 * 1024 * 1024;
pub const METRICS_SQLITE_CAP_BYTES: u64 = 2 * GIB;
pub const HOT_LOG_CAP_BYTES: u64 = 2 * GIB;
pub const PROJECT_HOT_LOG_CAP_BYTES: u64 = 256 * 1024 * 1024;
pub const OPERATION_OUTPUT_CAP_BYTES: u64 = 64 * 1024 * 1024;
pub const FAILURE_CAPSULE_CAP_BYTES: usize = 64 * 1024;
pub const LOG_EVENT_CAP_BYTES: usize = 256 * 1024;
pub const DISK_OBSERVATION_MAX_AGE_MS: i64 = 30_000;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiskAvailabilityObservation {
    pub filesystem_identity: EvidenceDigest,
    pub available_bytes: u64,
    pub observed_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiskReservation {
    pub filesystem_identity: EvidenceDigest,
    pub filesystem_total_bytes: u64,
    pub filesystem_available_bytes: u64,
    pub observed_at_ms: i64,
    pub backup_staging_bytes: u64,
    pub build_peak_bytes: u64,
    pub registry_peak_bytes: u64,
    pub last_known_good_bytes: u64,
    pub projected_hot_store_growth_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedDiskReservation {
    pub operation_digest: EvidenceDigest,
    pub reservation_digest: EvidenceDigest,
    pub required_bytes: u64,
    pub available_bytes: u64,
    pub emergency_reserve_bytes: u64,
    pub filesystem_identity: EvidenceDigest,
    pub observed_at_ms: i64,
}

impl DiskReservation {
    pub fn emergency_reserve_bytes(&self) -> u64 {
        recovery_reserve_bytes(self.filesystem_total_bytes)
    }

    pub fn required_bytes(&self) -> Option<u64> {
        self.operation_bytes()?
            .checked_add(self.emergency_reserve_bytes())
    }

    pub fn operation_bytes(&self) -> Option<u64> {
        [
            self.backup_staging_bytes,
            self.build_peak_bytes,
            self.registry_peak_bytes,
            self.last_known_good_bytes,
            self.projected_hot_store_growth_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }

    pub fn evaluate(&self) -> Result<(), DiskReservationError> {
        if self.filesystem_total_bytes == 0
            || self.filesystem_available_bytes > self.filesystem_total_bytes
            || self.observed_at_ms < 0
        {
            return Err(DiskReservationError::InvalidFilesystemMeasurement);
        }
        let required = self
            .required_bytes()
            .ok_or(DiskReservationError::CalculationOverflow)?;
        if self.filesystem_available_bytes < required {
            return Err(DiskReservationError::InsufficientSpace {
                required,
                available: self.filesystem_available_bytes,
                deficit: required - self.filesystem_available_bytes,
            });
        }
        Ok(())
    }
}

impl AuthorizedDiskReservation {
    pub fn calculate_reservation_digest(
        operation_digest: &EvidenceDigest,
        required_bytes: u64,
        available_bytes: u64,
        emergency_reserve_bytes: u64,
        filesystem_identity: &EvidenceDigest,
        observed_at_ms: i64,
    ) -> Result<EvidenceDigest, serde_json::Error> {
        serde_jcs::to_vec(&(
            "rdashboard.resource-reservation.v1",
            operation_digest,
            required_bytes,
            available_bytes,
            emergency_reserve_bytes,
            filesystem_identity,
            observed_at_ms,
        ))
        .map(EvidenceDigest::sha256)
    }

    pub fn has_valid_reservation_digest(&self) -> Result<bool, serde_json::Error> {
        Ok(self.reservation_digest
            == Self::calculate_reservation_digest(
                &self.operation_digest,
                self.required_bytes,
                self.available_bytes,
                self.emergency_reserve_bytes,
                &self.filesystem_identity,
                self.observed_at_ms,
            )?)
    }

    pub fn operation_bytes(&self) -> Option<u64> {
        self.required_bytes
            .checked_sub(self.emergency_reserve_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiskReservationError {
    #[error("filesystem measurements are internally inconsistent")]
    InvalidFilesystemMeasurement,
    #[error("disk reservation calculation overflowed")]
    CalculationOverflow,
    #[error(
        "insufficient disk space: required {required}, available {available}, deficit {deficit}"
    )]
    InsufficientSpace {
        required: u64,
        available: u64,
        deficit: u64,
    },
}
