use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    adapter_entrypoint::LoadedAdapterJobV1,
    adapter_identity::{AdapterOperationIdentityKindV1, AdapterOperationIdentityV1},
    adapter_result::{
        AdapterResultContractError, FixedAdapterEvidenceV1, FixedAdapterResultV1,
        PhaseObservationEvidenceV1, RimgSchemaCompatibilityV1, RimgSchemaObservationEvidenceV1,
        RimgSchemaObservationInputV1,
    },
    domain::EvidenceDigest,
    phase6::FixedAdapterProfileV1,
};

#[cfg(unix)]
pub mod runtime;

pub const RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RimgOperationalModeV1 {
    Normal,
    Maintenance,
    Draining,
    Fenced,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgOperationalStatusV1 {
    pub schema_version: u16,
    pub mode: RimgOperationalModeV1,
    pub last_epoch: u64,
    pub last_token: Option<uuid::Uuid>,
    pub active_epoch: Option<u64>,
    pub active_token: Option<uuid::Uuid>,
    pub intake_open: bool,
    pub workers_drained: bool,
    pub active_write_leases: u64,
    pub processing_jobs: u64,
    pub delivering_webhooks: u64,
    pub updated_at: i64,
}

impl RimgOperationalStatusV1 {
    pub(crate) fn validate_active_identity(
        &self,
        identity: &AdapterOperationIdentityV1,
        expected_mode: RimgOperationalModeV1,
    ) -> Result<(), RimgAdapterError> {
        if self.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
            || self.mode != expected_mode
            || self.last_epoch != identity.epoch
            || self.last_token != Some(identity.token)
            || self.active_epoch != Some(identity.epoch)
            || self.active_token != Some(identity.token)
            || self.intake_open
            || self.updated_at < 0
        {
            return Err(RimgAdapterError::OperationalStateMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_drained(
        &self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<(), RimgAdapterError> {
        self.validate_active_identity(identity, RimgOperationalModeV1::Draining)?;
        if !self.workers_drained
            || self.active_write_leases != 0
            || self.processing_jobs != 0
            || self.delivering_webhooks != 0
        {
            return Err(RimgAdapterError::DrainIncomplete);
        }
        Ok(())
    }

    pub(crate) fn validate_fenced(
        &self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<(), RimgAdapterError> {
        self.validate_active_identity(identity, RimgOperationalModeV1::Fenced)?;
        if !self.workers_drained
            || self.active_write_leases != 0
            || self.processing_jobs != 0
            || self.delivering_webhooks != 0
        {
            return Err(RimgAdapterError::OperationalStateMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_resumed(
        &self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<(), RimgAdapterError> {
        if self.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
            || self.mode != RimgOperationalModeV1::Normal
            || self.last_epoch != identity.epoch
            || self.last_token != Some(identity.token)
            || self.active_epoch.is_some()
            || self.active_token.is_some()
            || !self.intake_open
            || self.updated_at < 0
        {
            return Err(RimgAdapterError::OperationalStateMismatch);
        }
        Ok(())
    }

    pub(crate) fn allows_new_identity(&self, identity: &AdapterOperationIdentityV1) -> bool {
        self.schema_version == RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
            && self.mode == RimgOperationalModeV1::Normal
            && self.last_epoch < identity.epoch
            && self.active_epoch.is_none()
            && self.active_token.is_none()
            && self.intake_open
            && self.updated_at >= 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RimgRuntimeSchemaCompatibilityV1 {
    Empty,
    UpgradeRequired,
    Current,
    UnsupportedNewer,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgRuntimeSchemaInspectionV1 {
    pub schema_version: u16,
    pub database_exists: bool,
    pub current_application_schema: u32,
    pub latest_application_schema: u32,
    pub pending_migrations: i32,
    pub compatibility: RimgRuntimeSchemaCompatibilityV1,
    pub integrity_check: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgRuntimeMigrationReportV1 {
    pub schema_version: u16,
    pub from_application_schema: u32,
    pub to_application_schema: u32,
    pub applied_migrations: u32,
    pub compatibility: RimgRuntimeSchemaCompatibilityV1,
    pub backup_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RimgHealthCheckKindV1 {
    DirectReadiness,
    ConsumerNetwork,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgHealthObservationV1 {
    pub schema_version: u16,
    pub check: RimgHealthCheckKindV1,
    pub target_host: String,
    pub target_port: u16,
    pub network: Option<String>,
    pub image_digest: Option<String>,
    pub successful_samples: u16,
    pub minimum_interval_ms: u64,
}

impl RimgHealthObservationV1 {
    fn validate(&self, expected: RimgHealthCheckKindV1) -> Result<(), RimgAdapterError> {
        let kind_fields_match = match expected {
            RimgHealthCheckKindV1::DirectReadiness => {
                self.network.is_none()
                    && self.image_digest.is_none()
                    && self.successful_samples == 1
                    && self.minimum_interval_ms == 0
            }
            RimgHealthCheckKindV1::ConsumerNetwork => {
                self.network.as_ref().is_some_and(|value| !value.is_empty())
                    && self
                        .image_digest
                        .as_ref()
                        .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71)
                    && self.successful_samples == 2
                    && self.minimum_interval_ms >= 120_000
            }
        };
        if self.schema_version != 1
            || self.check != expected
            || self.target_host.is_empty()
            || self.target_port == 0
            || !kind_fields_match
        {
            return Err(RimgAdapterError::HealthObservationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RimgObservedDocumentV1<T> {
    pub document: T,
    pub observation_digest: EvidenceDigest,
}

impl<T: Serialize> RimgObservedDocumentV1<T> {
    pub fn from_document(document: T) -> Result<Self, RimgAdapterError> {
        let observation_digest = EvidenceDigest::sha256(serde_jcs::to_vec(&document)?);
        Ok(Self {
            document,
            observation_digest,
        })
    }
}

pub trait RimgAdminRuntimeV1 {
    fn begin_drain(
        &mut self,
        identity: &AdapterOperationIdentityV1,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError>;

    fn operational_status(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError>;

    fn schema_inspection(
        &mut self,
    ) -> Result<RimgObservedDocumentV1<RimgRuntimeSchemaInspectionV1>, RimgAdapterError>;

    fn migrate(
        &mut self,
        identity: &AdapterOperationIdentityV1,
        from_application_schema: u32,
        to_application_schema: u32,
    ) -> Result<RimgObservedDocumentV1<RimgRuntimeMigrationReportV1>, RimgAdapterError>;

    fn wait_before_drain_poll(&mut self) -> Result<(), RimgAdapterError>;

    fn readiness(
        &mut self,
        _spec: &crate::phase6::AuthorizedPhaseSpecV1,
    ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
        Err(RimgAdapterError::UnsupportedProfile)
    }

    fn consumer_smoke(
        &mut self,
        _spec: &crate::phase6::AuthorizedPhaseSpecV1,
    ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
        Err(RimgAdapterError::UnsupportedProfile)
    }

    fn wait_before_soak_poll(&mut self) -> Result<(), RimgAdapterError> {
        Err(RimgAdapterError::UnsupportedProfile)
    }
}

pub fn execute_rimg_admin_step<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    completed_at_ms: i64,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    execute_rimg_admin_step_with_clock(job, runtime, || Ok(completed_at_ms))
}

pub fn execute_rimg_admin_step_with_clock<R, C>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    mut clock: C,
) -> Result<FixedAdapterResultV1, RimgAdapterError>
where
    R: RimgAdminRuntimeV1,
    C: FnMut() -> Result<i64, RimgAdapterError>,
{
    match job.request.profile {
        FixedAdapterProfileV1::RimgDrain => execute_drain(job, runtime, &mut clock),
        FixedAdapterProfileV1::RimgSchemaInspect => {
            execute_schema_inspection(job, runtime, &mut clock)
        }
        FixedAdapterProfileV1::RimgMigrate => execute_migration(job, runtime, &mut clock),
        FixedAdapterProfileV1::RimgReadiness => execute_health_check(
            job,
            runtime,
            &mut clock,
            RimgHealthCheckKindV1::DirectReadiness,
        ),
        FixedAdapterProfileV1::RimgConsumerSmoke => execute_health_check(
            job,
            runtime,
            &mut clock,
            RimgHealthCheckKindV1::ConsumerNetwork,
        ),
        FixedAdapterProfileV1::RimgSoakObserve => execute_soak(job, runtime, &mut clock),
        _ => Err(RimgAdapterError::UnsupportedProfile),
    }
}

fn execute_health_check<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
    check: RimgHealthCheckKindV1,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    let observed = match check {
        RimgHealthCheckKindV1::DirectReadiness => runtime.readiness(&job.spec)?,
        RimgHealthCheckKindV1::ConsumerNetwork => runtime.consumer_smoke(&job.spec)?,
    };
    observed.document.validate(check)?;
    let completed_at_ms = completion_time(clock)?;
    let mut artifacts = job.spec.expected_observation_artifacts.clone();
    artifacts.health_evidence_digest = Some(observed.observation_digest.clone());
    let evidence = PhaseObservationEvidenceV1::new(
        completed_at_ms,
        observed.observation_digest,
        job.spec.bind_artifacts(artifacts)?,
    )?;
    let evidence = match check {
        RimgHealthCheckKindV1::DirectReadiness => {
            FixedAdapterEvidenceV1::ReadinessEvidence(evidence)
        }
        RimgHealthCheckKindV1::ConsumerNetwork => {
            FixedAdapterEvidenceV1::ConsumerSmokeEvidence(evidence)
        }
    };
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        evidence,
        &job.prior_results,
    )?)
}

#[derive(Serialize)]
struct SoakObservationDigestPayload<'a> {
    purpose: &'static str,
    samples: &'a [EvidenceDigest],
}

fn execute_soak<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    const INTERVAL_MS: u64 = 30_000;
    const COMPLETION_MARGIN_MS: u64 = 5_000;

    let observation_window = job
        .request
        .timeout_ms
        .checked_sub(COMPLETION_MARGIN_MS)
        .ok_or(RimgAdapterError::InvalidSoakWindow)?;
    let sample_count = observation_window
        .checked_div(INTERVAL_MS)
        .and_then(|intervals| intervals.checked_add(1))
        .ok_or(RimgAdapterError::InvalidSoakWindow)?;
    if !(2..=240).contains(&sample_count) {
        return Err(RimgAdapterError::InvalidSoakWindow);
    }
    let mut samples = Vec::with_capacity(
        usize::try_from(sample_count).map_err(|_| RimgAdapterError::InvalidSoakWindow)?,
    );
    for index in 0..sample_count {
        let observed = runtime.readiness(&job.spec)?;
        observed
            .document
            .validate(RimgHealthCheckKindV1::DirectReadiness)?;
        samples.push(observed.observation_digest);
        if index + 1 < sample_count {
            runtime.wait_before_soak_poll()?;
        }
    }
    let observation_digest =
        EvidenceDigest::sha256(serde_jcs::to_vec(&SoakObservationDigestPayload {
            purpose: "rdashboard.rimg-soak-observation.v1",
            samples: &samples,
        })?);
    let completed_at_ms = completion_time(clock)?;
    let mut artifacts = job.spec.expected_observation_artifacts.clone();
    artifacts.health_evidence_digest = Some(observation_digest.clone());
    let evidence = PhaseObservationEvidenceV1::new(
        completed_at_ms,
        observation_digest,
        job.spec.bind_artifacts(artifacts)?,
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::SoakEvidence(evidence),
        &job.prior_results,
    )?)
}

fn execute_drain<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    let identity = job.operation_identity()?;
    if identity.kind != AdapterOperationIdentityKindV1::Drain {
        return Err(RimgAdapterError::OperationIdentityMismatch);
    }
    let started = runtime.begin_drain(&identity)?;
    started
        .document
        .validate_active_identity(&identity, RimgOperationalModeV1::Draining)?;

    let maximum_polls = job.request.timeout_ms.div_ceil(250).clamp(1, 7_200);
    let mut final_observation = None;
    for _ in 0..maximum_polls {
        let observed = runtime.operational_status()?;
        match observed.document.validate_drained(&identity) {
            Ok(()) => {
                final_observation = Some(observed);
                break;
            }
            Err(RimgAdapterError::DrainIncomplete) => runtime.wait_before_drain_poll()?,
            Err(error) => return Err(error),
        }
    }
    let final_observation = final_observation.ok_or(RimgAdapterError::DrainDeadlineExceeded)?;
    let completed_at_ms = completion_time(clock)?;
    let mut artifacts = job.spec.expected_observation_artifacts.clone();
    artifacts.drain_evidence_digest = Some(final_observation.observation_digest.clone());
    let artifacts = job.spec.bind_artifacts(artifacts)?;
    let evidence = PhaseObservationEvidenceV1::new(
        completed_at_ms,
        final_observation.observation_digest,
        artifacts,
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::DrainEvidence(evidence),
        &job.prior_results,
    )?)
}

fn execute_schema_inspection<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    let observation = runtime.schema_inspection()?;
    let document = &observation.document;
    let compatibility = validate_schema_inspection(job, document)?;
    let pending_migrations = u32::try_from(document.pending_migrations)
        .map_err(|_| RimgAdapterError::SchemaStateMismatch)?;
    let completed_at_ms = completion_time(clock)?;
    let evidence = RimgSchemaObservationEvidenceV1::new(
        &job.spec,
        RimgSchemaObservationInputV1 {
            current_schema_version: document.current_application_schema.to_string(),
            candidate_schema_version: document.latest_application_schema.to_string(),
            pending_migrations,
            compatibility,
            integrity_check: document.integrity_check.clone(),
            inspected_at_ms: completed_at_ms,
            observation_digest: observation.observation_digest,
        },
    )?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::SchemaInspectionEvidence(evidence),
        &job.prior_results,
    )?)
}

fn validate_schema_inspection(
    job: &LoadedAdapterJobV1,
    document: &RimgRuntimeSchemaInspectionV1,
) -> Result<RimgSchemaCompatibilityV1, RimgAdapterError> {
    let expected_candidate = job
        .spec
        .expected_observation_artifacts
        .schema_version
        .as_deref()
        .ok_or(RimgAdapterError::SchemaStateMismatch)?
        .parse::<u32>()
        .map_err(|_| RimgAdapterError::SchemaStateMismatch)?;
    if document.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        || !document.database_exists
        || document.latest_application_schema != expected_candidate
        || document.integrity_check != "ok"
        || document.pending_migrations < 0
    {
        return Err(RimgAdapterError::SchemaStateMismatch);
    }
    let pending = u32::try_from(document.pending_migrations)
        .map_err(|_| RimgAdapterError::SchemaStateMismatch)?;
    match document.compatibility {
        RimgRuntimeSchemaCompatibilityV1::Current
            if document.current_application_schema == expected_candidate && pending == 0 =>
        {
            Ok(RimgSchemaCompatibilityV1::Current)
        }
        RimgRuntimeSchemaCompatibilityV1::UpgradeRequired
            if document.current_application_schema < expected_candidate
                && pending == expected_candidate - document.current_application_schema =>
        {
            Ok(RimgSchemaCompatibilityV1::UpgradeRequired)
        }
        _ => Err(RimgAdapterError::SchemaStateMismatch),
    }
}

fn execute_migration<R: RimgAdminRuntimeV1>(
    job: &LoadedAdapterJobV1,
    runtime: &mut R,
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
) -> Result<FixedAdapterResultV1, RimgAdapterError> {
    let identity = job.operation_identity()?;
    if identity.kind != AdapterOperationIdentityKindV1::Fence {
        return Err(RimgAdapterError::OperationIdentityMismatch);
    }
    let status = runtime.operational_status()?;
    status.document.validate_fenced(&identity)?;
    let prior = prior_schema_observation(job)?;
    let before = runtime.schema_inspection()?;
    let before_compatibility = validate_schema_inspection(job, &before.document)?;
    let target = prior
        .candidate_schema_version
        .parse::<u32>()
        .map_err(|_| RimgAdapterError::SchemaStateMismatch)?;
    let prior_current = prior
        .current_schema_version
        .parse::<u32>()
        .map_err(|_| RimgAdapterError::SchemaStateMismatch)?;
    let current = before.document.current_application_schema;
    let valid_pre_migration_state = (current == prior_current
        && before_compatibility == RimgSchemaCompatibilityV1::UpgradeRequired)
        || (current == target && before_compatibility == RimgSchemaCompatibilityV1::Current);
    if !valid_pre_migration_state {
        return Err(RimgAdapterError::SchemaStateMismatch);
    }
    // The fenced rimg CLI persists a deterministic operation-bound backup before
    // changing SQLite and returns the same report after a crash. Always request
    // that report, including when the schema is already at target, so the audit
    // evidence does not depend on where the previous process stopped.
    let report = runtime.migrate(&identity, prior_current, target)?;
    validate_migration_report(&report.document, prior_current, target)?;
    let after = runtime.schema_inspection()?;
    if validate_schema_inspection(job, &after.document)? != RimgSchemaCompatibilityV1::Current {
        return Err(RimgAdapterError::MigrationIncomplete);
    }
    let final_observation = migration_observation_digest(Some(&report), &status, &after)?;
    let completed_at_ms = completion_time(clock)?;
    let artifacts = job
        .spec
        .bind_artifacts(job.spec.expected_observation_artifacts.clone())?;
    let evidence = PhaseObservationEvidenceV1::new(completed_at_ms, final_observation, artifacts)?;
    Ok(FixedAdapterResultV1::new(
        &job.spec,
        job.request.sequence,
        FixedAdapterEvidenceV1::MigrationEvidence(evidence),
        &job.prior_results,
    )?)
}

fn completion_time(
    clock: &mut dyn FnMut() -> Result<i64, RimgAdapterError>,
) -> Result<i64, RimgAdapterError> {
    let completed_at_ms = clock()?;
    if completed_at_ms < 0 {
        return Err(RimgAdapterError::InvalidClock);
    }
    Ok(completed_at_ms)
}

fn prior_schema_observation(
    job: &LoadedAdapterJobV1,
) -> Result<&RimgSchemaObservationEvidenceV1, RimgAdapterError> {
    job.prior_results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::SchemaInspectionEvidence(evidence) => Some(evidence),
            _ => None,
        })
        .ok_or(RimgAdapterError::MissingSchemaObservation)
}

fn validate_migration_report(
    report: &RimgRuntimeMigrationReportV1,
    source: u32,
    target: u32,
) -> Result<(), RimgAdapterError> {
    if report.schema_version != RIMG_MACHINE_PROTOCOL_SCHEMA_VERSION
        || report.from_application_schema != source
        || report.to_application_schema != target
        || report.applied_migrations != target.saturating_sub(source)
        || report.compatibility != RimgRuntimeSchemaCompatibilityV1::Current
        || source >= target
        || report.backup_path.is_none()
    {
        return Err(RimgAdapterError::MigrationReportMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
struct MigrationObservationDigestPayload<'a> {
    purpose: &'static str,
    fence_status_digest: &'a EvidenceDigest,
    migration_report_digest: Option<&'a EvidenceDigest>,
    final_schema_digest: &'a EvidenceDigest,
}

fn migration_observation_digest(
    report: Option<&RimgObservedDocumentV1<RimgRuntimeMigrationReportV1>>,
    status: &RimgObservedDocumentV1<RimgOperationalStatusV1>,
    schema: &RimgObservedDocumentV1<RimgRuntimeSchemaInspectionV1>,
) -> Result<EvidenceDigest, RimgAdapterError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &MigrationObservationDigestPayload {
            purpose: "rdashboard.rimg-migration-observation.v1",
            fence_status_digest: &status.observation_digest,
            migration_report_digest: report.map(|value| &value.observation_digest),
            final_schema_digest: &schema.observation_digest,
        },
    )?))
}

#[derive(Debug, thiserror::Error)]
pub enum RimgAdapterError {
    #[error("the fixed rimg adapter profile is not implemented by this executable")]
    UnsupportedProfile,
    #[error("the adapter operation identity does not authorize this rimg action")]
    OperationIdentityMismatch,
    #[error("rimg operational state does not match the authorized operation identity")]
    OperationalStateMismatch,
    #[error("rimg worker drain is not complete")]
    DrainIncomplete,
    #[error("rimg worker drain exceeded its authorized deadline")]
    DrainDeadlineExceeded,
    #[error("the runtime rimg schema observation does not match the authorized target")]
    SchemaStateMismatch,
    #[error("the required prior rimg schema observation is missing")]
    MissingSchemaObservation,
    #[error("the rimg migration report does not match the authorized schema transition")]
    MigrationReportMismatch,
    #[error("rimg migration did not produce the authorized current schema")]
    MigrationIncomplete,
    #[error("the adapter clock is invalid")]
    InvalidClock,
    #[error("the rimg readiness or consumer-network observation is not exact and successful")]
    HealthObservationMismatch,
    #[error("the authorized soak window cannot provide two bounded readiness samples")]
    InvalidSoakWindow,
    #[error("the installed rimg adapter runtime does not match the authorized project policy")]
    RuntimeConfigMismatch,
    #[error("an installed rimg adapter runtime file is not stable, bounded and owner-controlled")]
    UnsafeRuntimeFile,
    #[error("a durable rimg identity request conflicts with the authorized replay")]
    RequestFileConflict,
    #[error("fixed rimg command failed: {0}")]
    CommandFailed(String),
    #[error("fixed rimg command output exceeded its bounded contract")]
    CommandOutputTooLarge,
    #[error("fixed rimg command exceeded its thirty-second deadline")]
    CommandDeadlineExceeded,
    #[error("fixed rimg command output is not valid UTF-8 JSON: {0}")]
    CommandOutput(#[from] serde_json::Error),
    #[error("fixed rimg adapter filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Entrypoint(#[from] crate::adapter_entrypoint::AdapterEntrypointError),
    #[error(transparent)]
    Phase6(#[from] crate::phase6::Phase6ContractError),
    #[error(transparent)]
    Result(#[from] AdapterResultContractError),
    #[error(transparent)]
    ReleaseBundle(#[from] crate::build::ReleaseBundleStoreError),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        adapter_entrypoint::FixedAdapterInvocationV1,
        adapter_identity::AdapterOperationIdentityV1,
        phase6::{
            AuthorizedPhaseSpecV1,
            tests::{test_drain_phase_spec, test_migration_phase_spec},
        },
        store::{DrainIdentityLease, FenceJournalState, FenceLease},
    };

    #[derive(Default)]
    struct FakeRuntime {
        drain_start: Option<RimgOperationalStatusV1>,
        statuses: VecDeque<RimgOperationalStatusV1>,
        schemas: VecDeque<RimgRuntimeSchemaInspectionV1>,
        migrations: VecDeque<RimgRuntimeMigrationReportV1>,
        readiness: VecDeque<RimgHealthObservationV1>,
        smoke: VecDeque<RimgHealthObservationV1>,
        migration_calls: usize,
        waits: usize,
        soak_waits: usize,
    }

    impl RimgAdminRuntimeV1 for FakeRuntime {
        fn begin_drain(
            &mut self,
            _identity: &AdapterOperationIdentityV1,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
            observed(
                self.drain_start
                    .take()
                    .ok_or(RimgAdapterError::OperationalStateMismatch)?,
            )
        }

        fn operational_status(
            &mut self,
        ) -> Result<RimgObservedDocumentV1<RimgOperationalStatusV1>, RimgAdapterError> {
            observed(
                self.statuses
                    .pop_front()
                    .ok_or(RimgAdapterError::OperationalStateMismatch)?,
            )
        }

        fn schema_inspection(
            &mut self,
        ) -> Result<RimgObservedDocumentV1<RimgRuntimeSchemaInspectionV1>, RimgAdapterError>
        {
            observed(
                self.schemas
                    .pop_front()
                    .ok_or(RimgAdapterError::SchemaStateMismatch)?,
            )
        }

        fn migrate(
            &mut self,
            _identity: &AdapterOperationIdentityV1,
            _from_application_schema: u32,
            _to_application_schema: u32,
        ) -> Result<RimgObservedDocumentV1<RimgRuntimeMigrationReportV1>, RimgAdapterError>
        {
            self.migration_calls += 1;
            observed(
                self.migrations
                    .pop_front()
                    .ok_or(RimgAdapterError::MigrationReportMismatch)?,
            )
        }

        fn wait_before_drain_poll(&mut self) -> Result<(), RimgAdapterError> {
            self.waits += 1;
            Ok(())
        }

        fn readiness(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
        ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
            observed(
                self.readiness
                    .pop_front()
                    .ok_or(RimgAdapterError::HealthObservationMismatch)?,
            )
        }

        fn consumer_smoke(
            &mut self,
            _spec: &AuthorizedPhaseSpecV1,
        ) -> Result<RimgObservedDocumentV1<RimgHealthObservationV1>, RimgAdapterError> {
            observed(
                self.smoke
                    .pop_front()
                    .ok_or(RimgAdapterError::HealthObservationMismatch)?,
            )
        }

        fn wait_before_soak_poll(&mut self) -> Result<(), RimgAdapterError> {
            self.soak_waits += 1;
            Ok(())
        }
    }

    fn observed<T: Serialize>(document: T) -> Result<RimgObservedDocumentV1<T>, RimgAdapterError> {
        RimgObservedDocumentV1::from_document(document)
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write fixture: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("fixture permissions: {error}"));
    }

    fn invocation(root: &Path, subcommand: &str) -> FixedAdapterInvocationV1 {
        FixedAdapterInvocationV1 {
            subcommand: subcommand.to_owned(),
            spec_path: root.join("spec.jcs"),
            request_path: root.join("request.jcs"),
            result_path: root.join("result.jcs"),
            inputs_path: root.join("inputs"),
            operation_identity_path: root.join("operation-identity.jcs"),
        }
    }

    fn materialize_loaded_job(
        root: &Path,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        profile: FixedAdapterProfileV1,
        identity: Option<&AdapterOperationIdentityV1>,
        prior_result: Option<&FixedAdapterResultV1>,
    ) -> LoadedAdapterJobV1 {
        fs::create_dir(root).unwrap_or_else(|error| panic!("job directory: {error}"));
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job permissions: {error}"));
        let invocation = invocation(root, "test-v1");
        fs::create_dir(&invocation.inputs_path)
            .unwrap_or_else(|error| panic!("input directory: {error}"));
        write_private(
            &invocation.spec_path,
            &spec
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("spec bytes: {error}")),
        );
        write_private(
            &invocation.request_path,
            &spec
                .fixed_adapter_request(sequence)
                .and_then(|request| request.canonical_bytes())
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        if let Some(identity) = identity {
            write_private(
                &invocation.operation_identity_path,
                &identity
                    .canonical_bytes()
                    .unwrap_or_else(|error| panic!("identity bytes: {error}")),
            );
        }
        if let Some(result) = prior_result {
            let prior_directory = invocation.inputs_path.join("step-00001");
            fs::create_dir(&prior_directory)
                .unwrap_or_else(|error| panic!("prior directory: {error}"));
            write_private(
                &prior_directory.join("result.jcs"),
                &result
                    .canonical_bytes()
                    .unwrap_or_else(|error| panic!("prior result bytes: {error}")),
            );
        }
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| panic!("job metadata: {error}"))
            .uid();
        LoadedAdapterJobV1::load(&invocation, profile, uid)
            .unwrap_or_else(|error| panic!("load job: {error}"))
    }

    fn operational_status(
        mode: RimgOperationalModeV1,
        epoch: u64,
        token: uuid::Uuid,
        drained: bool,
    ) -> RimgOperationalStatusV1 {
        RimgOperationalStatusV1 {
            schema_version: 1,
            mode,
            last_epoch: epoch,
            last_token: Some(token),
            active_epoch: Some(epoch),
            active_token: Some(token),
            intake_open: false,
            workers_drained: drained,
            active_write_leases: u64::from(!drained),
            processing_jobs: 0,
            delivering_webhooks: 0,
            updated_at: 1,
        }
    }

    fn schema(
        current: u32,
        latest: u32,
        compatibility: RimgRuntimeSchemaCompatibilityV1,
    ) -> RimgRuntimeSchemaInspectionV1 {
        RimgRuntimeSchemaInspectionV1 {
            schema_version: 1,
            database_exists: true,
            current_application_schema: current,
            latest_application_schema: latest,
            pending_migrations: i32::try_from(latest.saturating_sub(current)).unwrap_or(i32::MAX),
            compatibility,
            integrity_check: "ok".to_owned(),
        }
    }

    fn readiness_observation() -> RimgHealthObservationV1 {
        RimgHealthObservationV1 {
            schema_version: 1,
            check: RimgHealthCheckKindV1::DirectReadiness,
            target_host: "127.0.0.1".to_owned(),
            target_port: 8080,
            network: None,
            image_digest: None,
            successful_samples: 1,
            minimum_interval_ms: 0,
        }
    }

    fn smoke_observation() -> RimgHealthObservationV1 {
        RimgHealthObservationV1 {
            schema_version: 1,
            check: RimgHealthCheckKindV1::ConsumerNetwork,
            target_host: "rimg".to_owned(),
            target_port: 8080,
            network: Some("kamal".to_owned()),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            successful_samples: 2,
            minimum_interval_ms: 120_000,
        }
    }

    #[test]
    fn drain_polls_exact_identity_and_projects_runtime_observation() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_drain_phase_spec();
        let lease = DrainIdentityLease {
            journal_id: 10,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: 8,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 100,
        };
        let identity = AdapterOperationIdentityV1::from_drain_lease(&spec, 1, &lease)
            .unwrap_or_else(|error| panic!("identity: {error}"));
        let job = materialize_loaded_job(
            &directory.path().join("drain-job"),
            &spec,
            1,
            FixedAdapterProfileV1::RimgDrain,
            Some(&identity),
            None,
        );
        let mut runtime = FakeRuntime {
            drain_start: Some(operational_status(
                RimgOperationalModeV1::Draining,
                lease.epoch,
                lease.token,
                false,
            )),
            statuses: VecDeque::from([
                operational_status(
                    RimgOperationalModeV1::Draining,
                    lease.epoch,
                    lease.token,
                    false,
                ),
                operational_status(
                    RimgOperationalModeV1::Draining,
                    lease.epoch,
                    lease.token,
                    true,
                ),
            ]),
            ..FakeRuntime::default()
        };
        let result = execute_rimg_admin_step(&job, &mut runtime, 1_000)
            .unwrap_or_else(|error| panic!("drain result: {error}"));
        let FixedAdapterEvidenceV1::DrainEvidence(evidence) = result.evidence else {
            panic!("drain evidence");
        };
        assert_eq!(runtime.waits, 1);
        assert_eq!(
            evidence.artifacts.source_gate_proof_digest,
            spec.expected_observation_artifacts.source_gate_proof_digest
        );
        assert_eq!(
            evidence.artifacts.drain_evidence_digest,
            Some(evidence.observation_digest)
        );
    }

    #[test]
    fn migration_requires_fence_and_prior_schema_then_accepts_crash_replay() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_migration_phase_spec();
        let inspection_job = materialize_loaded_job(
            &directory.path().join("inspection-job"),
            &spec,
            1,
            FixedAdapterProfileV1::RimgSchemaInspect,
            None,
            None,
        );
        let mut inspection_runtime = FakeRuntime {
            schemas: VecDeque::from([schema(
                1,
                2,
                RimgRuntimeSchemaCompatibilityV1::UpgradeRequired,
            )]),
            ..FakeRuntime::default()
        };
        let inspection_result =
            execute_rimg_admin_step(&inspection_job, &mut inspection_runtime, 500)
                .unwrap_or_else(|error| panic!("inspection result: {error}"));
        let lease = FenceLease {
            journal_id: 12,
            project_id: spec.project_id.clone(),
            attempt_id: spec.attempt_id,
            epoch: 7,
            token: uuid::Uuid::new_v4(),
            created_at_ms: 900,
            state: FenceJournalState::Held,
            release_safe_receipt_digest: None,
        };
        let identity = AdapterOperationIdentityV1::from_fence_lease(&spec, 2, &lease)
            .unwrap_or_else(|error| panic!("identity: {error}"));
        let migration_job = materialize_loaded_job(
            &directory.path().join("migration-job"),
            &spec,
            2,
            FixedAdapterProfileV1::RimgMigrate,
            Some(&identity),
            Some(&inspection_result),
        );
        let fenced = operational_status(
            RimgOperationalModeV1::Fenced,
            lease.epoch,
            lease.token,
            true,
        );
        let mut runtime = FakeRuntime {
            statuses: VecDeque::from([fenced.clone()]),
            schemas: VecDeque::from([
                schema(1, 2, RimgRuntimeSchemaCompatibilityV1::UpgradeRequired),
                schema(2, 2, RimgRuntimeSchemaCompatibilityV1::Current),
            ]),
            migrations: VecDeque::from([RimgRuntimeMigrationReportV1 {
                schema_version: 1,
                from_application_schema: 1,
                to_application_schema: 2,
                applied_migrations: 1,
                compatibility: RimgRuntimeSchemaCompatibilityV1::Current,
                backup_path: Some(PathBuf::from(
                    "/var/lib/rimg/data/migration-backups/backup.db",
                )),
            }]),
            ..FakeRuntime::default()
        };
        let result = execute_rimg_admin_step(&migration_job, &mut runtime, 600)
            .unwrap_or_else(|error| panic!("migration result: {error}"));
        assert!(matches!(
            result.evidence,
            FixedAdapterEvidenceV1::MigrationEvidence(_)
        ));
        assert_eq!(runtime.migration_calls, 1);

        let mut crash_replay_runtime = FakeRuntime {
            statuses: VecDeque::from([fenced]),
            schemas: VecDeque::from([
                schema(2, 2, RimgRuntimeSchemaCompatibilityV1::Current),
                schema(2, 2, RimgRuntimeSchemaCompatibilityV1::Current),
            ]),
            migrations: VecDeque::from([RimgRuntimeMigrationReportV1 {
                schema_version: 1,
                from_application_schema: 1,
                to_application_schema: 2,
                applied_migrations: 1,
                compatibility: RimgRuntimeSchemaCompatibilityV1::Current,
                backup_path: Some(PathBuf::from(
                    "/var/lib/rimg/data/migration-backups/backup.db",
                )),
            }]),
            ..FakeRuntime::default()
        };
        let replayed = execute_rimg_admin_step(&migration_job, &mut crash_replay_runtime, 600)
            .unwrap_or_else(|error| panic!("migration replay result: {error}"));
        assert_eq!(crash_replay_runtime.migration_calls, 1);
        assert_eq!(replayed, result);
    }

    #[test]
    fn health_requires_direct_readiness_then_exact_consumer_network_smoke() {
        use crate::phase6::tests::test_health_phase_spec;

        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_health_phase_spec();
        let readiness_job = materialize_loaded_job(
            &directory.path().join("readiness-job"),
            &spec,
            1,
            FixedAdapterProfileV1::RimgReadiness,
            None,
            None,
        );
        let mut readiness_runtime = FakeRuntime {
            readiness: VecDeque::from([readiness_observation()]),
            ..FakeRuntime::default()
        };
        let readiness = execute_rimg_admin_step(&readiness_job, &mut readiness_runtime, 700)
            .unwrap_or_else(|error| panic!("readiness: {error}"));
        assert!(matches!(
            readiness.evidence,
            FixedAdapterEvidenceV1::ReadinessEvidence(_)
        ));

        let smoke_job = materialize_loaded_job(
            &directory.path().join("smoke-job"),
            &spec,
            2,
            FixedAdapterProfileV1::RimgConsumerSmoke,
            None,
            Some(&readiness),
        );
        let mut smoke_runtime = FakeRuntime {
            smoke: VecDeque::from([smoke_observation()]),
            ..FakeRuntime::default()
        };
        let smoke = execute_rimg_admin_step(&smoke_job, &mut smoke_runtime, 800)
            .unwrap_or_else(|error| panic!("consumer smoke: {error}"));
        assert!(matches!(
            smoke.evidence,
            FixedAdapterEvidenceV1::ConsumerSmokeEvidence(_)
        ));
    }

    #[test]
    fn soak_aggregates_multiple_readiness_samples() {
        use crate::phase6::tests::test_soak_phase_spec;

        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let spec = test_soak_phase_spec();
        let job = materialize_loaded_job(
            &directory.path().join("soak-job"),
            &spec,
            1,
            FixedAdapterProfileV1::RimgSoakObserve,
            None,
            None,
        );
        let mut runtime = FakeRuntime {
            readiness: VecDeque::from([readiness_observation(), readiness_observation()]),
            ..FakeRuntime::default()
        };
        let result = execute_rimg_admin_step(&job, &mut runtime, 900)
            .unwrap_or_else(|error| panic!("soak: {error}"));
        assert!(matches!(
            result.evidence,
            FixedAdapterEvidenceV1::SoakEvidence(_)
        ));
        assert_eq!(runtime.soak_waits, 1);
    }
}
