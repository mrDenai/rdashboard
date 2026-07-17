use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::domain::{
    HostHistorySnapshot, HostHistoryWindow, HostHistoryWindowKind, HostMetricMedians,
    HostMetricTotals, HostTelemetry, ObservationStatus, ProjectCondition, ProjectId,
    ProjectRepositorySample, ProjectTelemetry, PsiMeasurement, truncate_utf8,
};
use crate::source::SourceTreeObservationV1;

use super::{StoreError, lock_connection, verify_sqlite_version};

const METRICS_SCHEMA_VERSION: i64 = 4;
pub const MINUTE_ROLLUP_MS: i64 = 60_000;
const LOG_SKETCH_RELATIVE_ACCURACY: f64 = 0.01;
const ROLLUP_DETAIL_MAX_BYTES: usize = 1_024;
const ROLLUP_REASON_MAX_BYTES: usize = 512;
const ROLLUP_REASON_LIMIT: usize = 8;
const HOST_HISTORY_SCHEMA_VERSION: u16 = 2;
pub const PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS: i64 = 60 * 60 * 1_000;
pub const PROJECT_REPOSITORY_HISTORY_LIMIT: usize = 24 * 31 + 1;
const HOST_HISTORY_WINDOWS: [(HostHistoryWindowKind, i64, u64); 4] = [
    (HostHistoryWindowKind::Hour, 60 * MINUTE_ROLLUP_MS, 60),
    (
        HostHistoryWindowKind::Day,
        24 * 60 * MINUTE_ROLLUP_MS,
        24 * 60,
    ),
    (
        HostHistoryWindowKind::Week,
        7 * 24 * 60 * MINUTE_ROLLUP_MS,
        7 * 24 * 60,
    ),
    (
        HostHistoryWindowKind::Month,
        30 * 24 * 60 * MINUTE_ROLLUP_MS,
        30 * 24 * 60,
    ),
];

#[derive(Clone, Debug)]
pub struct MetricsStore {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySampleWrite {
    Recorded,
    NotDue { next_observation_at_ms: i64 },
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RelativeLogSketch {
    count: u64,
    zero_count: u64,
    bins: BTreeMap<i32, u64>,
}

impl RelativeLogSketch {
    pub const fn count(&self) -> u64 {
        self.count
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    pub fn quantile(&self, quantile: f64) -> Option<f64> {
        if self.count == 0 || !quantile.is_finite() || !(0.0..=1.0).contains(&quantile) {
            return None;
        }
        let target = ((self.count - 1) as f64 * quantile).round() as u64;
        if target < self.zero_count {
            return Some(0.0);
        }
        let mut seen = self.zero_count;
        for (index, count) in &self.bins {
            seen = seen.saturating_add(*count);
            if target < seen {
                return Some(bin_value(*index));
            }
        }
        None
    }

    fn add(&mut self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        self.count = self.count.saturating_add(1);
        if value < f64::MIN_POSITIVE {
            self.zero_count = self.zero_count.saturating_add(1);
            return;
        }
        let count = self.bins.entry(bin_index(value)).or_default();
        *count = count.saturating_add(1);
    }

    fn add_optional_f64(&mut self, value: Option<f64>) {
        if let Some(value) = value {
            self.add(value);
        }
    }

    fn add_optional_u64(&mut self, value: Option<u64>) {
        if let Some(value) = value {
            self.add(u64_as_f64(value));
        }
    }

    fn merge(&mut self, other: &Self) {
        self.count = self.count.saturating_add(other.count);
        self.zero_count = self.zero_count.saturating_add(other.zero_count);
        for (index, incoming) in &other.bins {
            let count = self.bins.entry(*index).or_default();
            *count = count.saturating_add(*incoming);
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct HostMetricSketches {
    pub cpu_percent: RelativeLogSketch,
    pub load_1: RelativeLogSketch,
    pub load_5: RelativeLogSketch,
    pub load_15: RelativeLogSketch,
    pub memory_total_bytes: RelativeLogSketch,
    pub memory_available_bytes: RelativeLogSketch,
    pub memory_used_bytes: RelativeLogSketch,
    pub memory_used_percent: RelativeLogSketch,
    pub swap_total_bytes: RelativeLogSketch,
    pub swap_free_bytes: RelativeLogSketch,
    pub swap_used_bytes: RelativeLogSketch,
    pub swap_used_percent: RelativeLogSketch,
    pub disk_total_bytes: RelativeLogSketch,
    pub disk_available_bytes: RelativeLogSketch,
    pub disk_used_bytes: RelativeLogSketch,
    pub disk_used_percent: RelativeLogSketch,
    pub network_rx_bytes: RelativeLogSketch,
    pub network_tx_bytes: RelativeLogSketch,
    pub network_rx_bytes_per_second: RelativeLogSketch,
    pub network_tx_bytes_per_second: RelativeLogSketch,
    pub psi_cpu_some_avg10: RelativeLogSketch,
    pub psi_memory_some_avg10: RelativeLogSketch,
    pub psi_io_some_avg10: RelativeLogSketch,
}

impl HostMetricSketches {
    fn add(&mut self, sample: &HostTelemetry) {
        self.cpu_percent.add_optional_f64(sample.cpu_percent);
        self.load_1.add_optional_f64(sample.load_1);
        self.load_5.add_optional_f64(sample.load_5);
        self.load_15.add_optional_f64(sample.load_15);
        self.memory_total_bytes
            .add_optional_u64(sample.memory_total_bytes);
        self.memory_available_bytes
            .add_optional_u64(sample.memory_available_bytes);
        add_usage(
            &mut self.memory_used_bytes,
            &mut self.memory_used_percent,
            sample.memory_total_bytes,
            sample.memory_available_bytes,
        );
        self.swap_total_bytes
            .add_optional_u64(sample.swap_total_bytes);
        self.swap_free_bytes
            .add_optional_u64(sample.swap_free_bytes);
        add_usage(
            &mut self.swap_used_bytes,
            &mut self.swap_used_percent,
            sample.swap_total_bytes,
            sample.swap_free_bytes,
        );
        self.disk_total_bytes
            .add_optional_u64(sample.disk_total_bytes);
        self.disk_available_bytes
            .add_optional_u64(sample.disk_available_bytes);
        add_usage(
            &mut self.disk_used_bytes,
            &mut self.disk_used_percent,
            sample.disk_total_bytes,
            sample.disk_available_bytes,
        );
        self.network_rx_bytes
            .add_optional_u64(sample.network_rx_bytes);
        self.network_tx_bytes
            .add_optional_u64(sample.network_tx_bytes);
        self.network_rx_bytes_per_second
            .add_optional_u64(sample.network_rx_bytes_per_second);
        self.network_tx_bytes_per_second
            .add_optional_u64(sample.network_tx_bytes_per_second);
        self.psi_cpu_some_avg10
            .add_optional_f64(sample.psi.cpu_some_avg10);
        self.psi_memory_some_avg10
            .add_optional_f64(sample.psi.memory_some_avg10);
        self.psi_io_some_avg10
            .add_optional_f64(sample.psi.io_some_avg10);
    }

    fn merge(&mut self, other: &Self) {
        self.cpu_percent.merge(&other.cpu_percent);
        self.load_1.merge(&other.load_1);
        self.load_5.merge(&other.load_5);
        self.load_15.merge(&other.load_15);
        self.memory_total_bytes.merge(&other.memory_total_bytes);
        self.memory_available_bytes
            .merge(&other.memory_available_bytes);
        self.memory_used_bytes.merge(&other.memory_used_bytes);
        self.memory_used_percent.merge(&other.memory_used_percent);
        self.swap_total_bytes.merge(&other.swap_total_bytes);
        self.swap_free_bytes.merge(&other.swap_free_bytes);
        self.swap_used_bytes.merge(&other.swap_used_bytes);
        self.swap_used_percent.merge(&other.swap_used_percent);
        self.disk_total_bytes.merge(&other.disk_total_bytes);
        self.disk_available_bytes.merge(&other.disk_available_bytes);
        self.disk_used_bytes.merge(&other.disk_used_bytes);
        self.disk_used_percent.merge(&other.disk_used_percent);
        self.network_rx_bytes.merge(&other.network_rx_bytes);
        self.network_tx_bytes.merge(&other.network_tx_bytes);
        self.network_rx_bytes_per_second
            .merge(&other.network_rx_bytes_per_second);
        self.network_tx_bytes_per_second
            .merge(&other.network_tx_bytes_per_second);
        self.psi_cpu_some_avg10.merge(&other.psi_cpu_some_avg10);
        self.psi_memory_some_avg10
            .merge(&other.psi_memory_some_avg10);
        self.psi_io_some_avg10.merge(&other.psi_io_some_avg10);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct MonotonicCounterDelta {
    first_observed_at_ms: Option<i64>,
    first_value: Option<u64>,
    last_observed_at_ms: Option<i64>,
    last_value: Option<u64>,
    total_increase: u64,
    covered_ms: u64,
}

impl MonotonicCounterDelta {
    fn add(&mut self, observed_at_ms: i64, value: Option<u64>) {
        let Some(value) = value else { return };
        let (Some(last_at), Some(last_value)) = (self.last_observed_at_ms, self.last_value) else {
            self.set_first_and_last(observed_at_ms, value);
            return;
        };
        if observed_at_ms <= last_at {
            return;
        }
        self.add_interval(last_at, last_value, observed_at_ms, value);
        self.last_observed_at_ms = Some(observed_at_ms);
        self.last_value = Some(value);
    }

    fn merge(&mut self, other: &Self) {
        let (Some(self_first_at), Some(self_last_at)) =
            (self.first_observed_at_ms, self.last_observed_at_ms)
        else {
            self.clone_from(other);
            return;
        };
        let (Some(other_first_at), Some(other_last_at)) =
            (other.first_observed_at_ms, other.last_observed_at_ms)
        else {
            return;
        };
        if self_last_at <= other_first_at {
            self.append(other);
        } else if other_last_at <= self_first_at {
            let mut combined = other.clone();
            combined.append(self);
            *self = combined;
        } else {
            self.merge_overlapping(other);
        }
    }

    const fn total(&self) -> Option<u64> {
        if self.covered_ms == 0 {
            None
        } else {
            Some(self.total_increase)
        }
    }

    const fn covered_ms(&self) -> u64 {
        self.covered_ms
    }

    fn set_first_and_last(&mut self, observed_at_ms: i64, value: u64) {
        self.first_observed_at_ms = Some(observed_at_ms);
        self.first_value = Some(value);
        self.last_observed_at_ms = Some(observed_at_ms);
        self.last_value = Some(value);
    }

    fn append(&mut self, later: &Self) {
        let (Some(last_at), Some(last_value), Some(first_at), Some(first_value)) = (
            self.last_observed_at_ms,
            self.last_value,
            later.first_observed_at_ms,
            later.first_value,
        ) else {
            return;
        };
        self.total_increase = self.total_increase.saturating_add(later.total_increase);
        self.covered_ms = self.covered_ms.saturating_add(later.covered_ms);
        self.add_interval(last_at, last_value, first_at, first_value);
        self.last_observed_at_ms = later.last_observed_at_ms;
        self.last_value = later.last_value;
    }

    fn merge_overlapping(&mut self, other: &Self) {
        if other.first_observed_at_ms < self.first_observed_at_ms {
            self.first_observed_at_ms = other.first_observed_at_ms;
            self.first_value = other.first_value;
        }
        if other.last_observed_at_ms > self.last_observed_at_ms {
            self.last_observed_at_ms = other.last_observed_at_ms;
            self.last_value = other.last_value;
        }
        self.total_increase = self.total_increase.max(other.total_increase);
        self.covered_ms = self.covered_ms.max(other.covered_ms);
    }

    fn add_interval(&mut self, first_at: i64, first: u64, last_at: i64, last: u64) {
        if last_at <= first_at || last < first {
            return;
        }
        let Some(duration) = last_at.checked_sub(first_at) else {
            return;
        };
        let Ok(duration_ms) = u64::try_from(duration) else {
            return;
        };
        self.total_increase = self.total_increase.saturating_add(last - first);
        self.covered_ms = self.covered_ms.saturating_add(duration_ms);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct NetworkTrafficRollup {
    pub rx: MonotonicCounterDelta,
    pub tx: MonotonicCounterDelta,
}

impl NetworkTrafficRollup {
    fn add(&mut self, sample: &HostTelemetry) {
        self.rx.add(sample.observed_at_ms, sample.network_rx_bytes);
        self.tx.add(sample.observed_at_ms, sample.network_tx_bytes);
    }

    fn merge(&mut self, other: &Self) {
        self.rx.merge(&other.rx);
        self.tx.merge(&other.tx);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ObservationStatusCounts {
    pub fresh: u64,
    pub stale: u64,
    pub signal_lost: u64,
    pub partial: u64,
    pub unsupported: u64,
    pub unknown: u64,
}

impl ObservationStatusCounts {
    fn add(&mut self, status: ObservationStatus) {
        let count = match status {
            ObservationStatus::Fresh => &mut self.fresh,
            ObservationStatus::Stale => &mut self.stale,
            ObservationStatus::SignalLost => &mut self.signal_lost,
            ObservationStatus::Partial => &mut self.partial,
            ObservationStatus::Unsupported => &mut self.unsupported,
            ObservationStatus::Unknown => &mut self.unknown,
        };
        *count = count.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        self.fresh = self.fresh.saturating_add(other.fresh);
        self.stale = self.stale.saturating_add(other.stale);
        self.signal_lost = self.signal_lost.saturating_add(other.signal_lost);
        self.partial = self.partial.saturating_add(other.partial);
        self.unsupported = self.unsupported.saturating_add(other.unsupported);
        self.unknown = self.unknown.saturating_add(other.unknown);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ProjectConditionCounts {
    pub healthy: u64,
    pub degraded: u64,
    pub down: u64,
    pub maintenance: u64,
    pub migrating: u64,
    pub unknown: u64,
    pub signal_lost: u64,
}

impl ProjectConditionCounts {
    fn add(&mut self, condition: ProjectCondition) {
        let count = match condition {
            ProjectCondition::Healthy => &mut self.healthy,
            ProjectCondition::Degraded => &mut self.degraded,
            ProjectCondition::Down => &mut self.down,
            ProjectCondition::Maintenance => &mut self.maintenance,
            ProjectCondition::Migrating => &mut self.migrating,
            ProjectCondition::Unknown => &mut self.unknown,
            ProjectCondition::SignalLost => &mut self.signal_lost,
        };
        *count = count.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        self.healthy = self.healthy.saturating_add(other.healthy);
        self.degraded = self.degraded.saturating_add(other.degraded);
        self.down = self.down.saturating_add(other.down);
        self.maintenance = self.maintenance.saturating_add(other.maintenance);
        self.migrating = self.migrating.saturating_add(other.migrating);
        self.unknown = self.unknown.saturating_add(other.unknown);
        self.signal_lost = self.signal_lost.saturating_add(other.signal_lost);
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HostMinuteRollup {
    pub bucket_start_ms: i64,
    pub sample_count: u64,
    pub last_sample_id: i64,
    #[serde(default)]
    pub last_partial_sample_id: Option<i64>,
    #[serde(default)]
    pub last_partial_reasons: Vec<String>,
    pub statuses: ObservationStatusCounts,
    pub metrics: HostMetricSketches,
    #[serde(default)]
    pub traffic: NetworkTrafficRollup,
}

impl HostMinuteRollup {
    fn new(bucket_start_ms: i64) -> Self {
        Self {
            bucket_start_ms,
            sample_count: 0,
            last_sample_id: 0,
            last_partial_sample_id: None,
            last_partial_reasons: Vec::new(),
            statuses: ObservationStatusCounts::default(),
            metrics: HostMetricSketches::default(),
            traffic: NetworkTrafficRollup::default(),
        }
    }

    fn add(&mut self, sample_id: i64, sample: &HostTelemetry) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_sample_id = self.last_sample_id.max(sample_id);
        if !sample.partial_reasons.is_empty()
            && self
                .last_partial_sample_id
                .is_none_or(|current| sample_id >= current)
        {
            self.last_partial_sample_id = Some(sample_id);
            self.last_partial_reasons = sample
                .partial_reasons
                .iter()
                .take(ROLLUP_REASON_LIMIT)
                .map(|reason| truncate_utf8(reason, ROLLUP_REASON_MAX_BYTES, "…"))
                .collect();
        }
        self.statuses.add(sample.status);
        self.metrics.add(sample);
        self.traffic.add(sample);
    }

    fn merge(&mut self, other: &Self) {
        self.sample_count = self.sample_count.saturating_add(other.sample_count);
        self.last_sample_id = self.last_sample_id.max(other.last_sample_id);
        if let Some(other_id) = other.last_partial_sample_id
            && self
                .last_partial_sample_id
                .is_none_or(|current| other_id >= current)
        {
            self.last_partial_sample_id = Some(other_id);
            self.last_partial_reasons
                .clone_from(&other.last_partial_reasons);
        }
        self.statuses.merge(&other.statuses);
        self.metrics.merge(&other.metrics);
        self.traffic.merge(&other.traffic);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectMinuteRollup {
    pub bucket_start_ms: i64,
    pub project_id: String,
    pub sample_count: u64,
    pub last_sample_id: i64,
    pub display_name: String,
    pub conditions: ProjectConditionCounts,
    pub last_collected_at_ms: i64,
    pub last_observed_at_ms: Option<i64>,
    pub last_detail: String,
    #[serde(default)]
    pub last_non_healthy_sample_id: Option<i64>,
    #[serde(default)]
    pub last_non_healthy_detail: Option<String>,
}

impl ProjectMinuteRollup {
    fn new(bucket_start_ms: i64, project_id: String) -> Self {
        Self {
            bucket_start_ms,
            project_id,
            sample_count: 0,
            last_sample_id: 0,
            display_name: String::new(),
            conditions: ProjectConditionCounts::default(),
            last_collected_at_ms: 0,
            last_observed_at_ms: None,
            last_detail: String::new(),
            last_non_healthy_sample_id: None,
            last_non_healthy_detail: None,
        }
    }

    fn add(&mut self, sample_id: i64, collected_at_ms: i64, sample: ProjectTelemetry) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.conditions.add(sample.condition);
        if sample.condition != ProjectCondition::Healthy
            && self
                .last_non_healthy_sample_id
                .is_none_or(|current| sample_id >= current)
        {
            self.last_non_healthy_sample_id = Some(sample_id);
            self.last_non_healthy_detail =
                Some(truncate_utf8(&sample.detail, ROLLUP_DETAIL_MAX_BYTES, "…"));
        }
        if sample_id >= self.last_sample_id {
            self.last_sample_id = sample_id;
            self.display_name = sample.display_name;
            self.last_collected_at_ms = collected_at_ms;
            self.last_observed_at_ms = sample.observed_at_ms;
            self.last_detail = truncate_utf8(&sample.detail, ROLLUP_DETAIL_MAX_BYTES, "…");
        }
    }

    fn merge(&mut self, other: &Self) {
        self.sample_count = self.sample_count.saturating_add(other.sample_count);
        self.conditions.merge(&other.conditions);
        if other.last_sample_id >= self.last_sample_id {
            self.last_sample_id = other.last_sample_id;
            self.display_name.clone_from(&other.display_name);
            self.last_collected_at_ms = other.last_collected_at_ms;
            self.last_observed_at_ms = other.last_observed_at_ms;
            self.last_detail.clone_from(&other.last_detail);
        }
        if let Some(other_id) = other.last_non_healthy_sample_id
            && self
                .last_non_healthy_sample_id
                .is_none_or(|current| other_id >= current)
        {
            self.last_non_healthy_sample_id = Some(other_id);
            self.last_non_healthy_detail
                .clone_from(&other.last_non_healthy_detail);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetentionOutcome {
    pub raw_host_deleted: usize,
    pub raw_project_deleted: usize,
    pub host_rollups_written: usize,
    pub project_rollups_written: usize,
    pub host_rollups_deleted: usize,
    pub project_rollups_deleted: usize,
}

impl RetentionOutcome {
    pub const fn raw_deleted(self) -> usize {
        self.raw_host_deleted
            .saturating_add(self.raw_project_deleted)
    }
}

impl MetricsStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        verify_sqlite_version()?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        initialize_schema(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn record_host_sample(&self, sample: &HostTelemetry) -> Result<(), StoreError> {
        let connection = lock_connection(&self.connection)?;
        insert_host_sample(&connection, sample)?;
        Ok(())
    }

    pub fn record_collection(
        &self,
        host: &HostTelemetry,
        projects: &[ProjectTelemetry],
    ) -> Result<(), StoreError> {
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sample_id = insert_host_sample(&transaction, host)?;
        for project in projects {
            transaction.execute(
                "INSERT INTO project_samples(
                    sample_id, collected_at_ms, project_id, display_name, condition_json,
                    observed_at_ms, detail
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    sample_id,
                    host.observed_at_ms,
                    project.project_id.as_str(),
                    project.display_name,
                    serde_json::to_string(&project.condition)?,
                    project.observed_at_ms,
                    project.detail,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn apply_retention(
        &self,
        raw_cutoff_ms: i64,
        rollup_cutoff_ms: i64,
    ) -> Result<RetentionOutcome, StoreError> {
        if rollup_cutoff_ms > raw_cutoff_ms {
            return Err(StoreError::InvalidRetentionCutoffs {
                raw: raw_cutoff_ms,
                rollup: rollup_cutoff_ms,
            });
        }
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let host_rollups_written = roll_up_host_samples(&transaction, raw_cutoff_ms)?;
        let project_rollups_written = roll_up_project_samples(&transaction, raw_cutoff_ms)?;

        let raw_project_deleted = transaction.execute(
            "DELETE FROM project_samples WHERE collected_at_ms < ?1",
            [raw_cutoff_ms],
        )?;
        let raw_host_deleted = transaction.execute(
            "DELETE FROM host_samples WHERE observed_at_ms < ?1",
            [raw_cutoff_ms],
        )?;

        let rollup_boundary = minute_bucket(rollup_cutoff_ms);
        let host_rollups_deleted = transaction.execute(
            "DELETE FROM host_minute_rollups WHERE bucket_start_ms < ?1",
            [rollup_boundary],
        )?;
        let project_rollups_deleted = transaction.execute(
            "DELETE FROM project_minute_rollups WHERE bucket_start_ms < ?1",
            [rollup_boundary],
        )?;
        transaction.commit()?;

        Ok(RetentionOutcome {
            raw_host_deleted,
            raw_project_deleted,
            host_rollups_written,
            project_rollups_written,
            host_rollups_deleted,
            project_rollups_deleted,
        })
    }

    pub fn sample_count(&self) -> Result<u64, StoreError> {
        count_rows(&self.connection, "host_samples")
    }

    pub fn project_sample_count(&self) -> Result<u64, StoreError> {
        count_rows(&self.connection, "project_samples")
    }

    pub fn host_rollup_count(&self) -> Result<u64, StoreError> {
        count_rows(&self.connection, "host_minute_rollups")
    }

    pub fn project_rollup_count(&self) -> Result<u64, StoreError> {
        count_rows(&self.connection, "project_minute_rollups")
    }

    pub fn host_minute_rollup(
        &self,
        bucket_start_ms: i64,
    ) -> Result<Option<HostMinuteRollup>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_host_rollup(&connection, bucket_start_ms)
    }

    pub fn project_minute_rollup(
        &self,
        bucket_start_ms: i64,
        project_id: &str,
    ) -> Result<Option<ProjectMinuteRollup>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_project_rollup(&connection, bucket_start_ms, project_id)
    }

    pub fn host_history(&self, generated_at_ms: i64) -> Result<HostHistorySnapshot, StoreError> {
        let complete_through_ms = minute_bucket(generated_at_ms);
        let connection = lock_connection(&self.connection)?;
        let mut windows = Vec::with_capacity(HOST_HISTORY_WINDOWS.len());
        for (window, duration_ms, expected_minutes) in HOST_HISTORY_WINDOWS {
            let starts_at_ms = complete_through_ms.saturating_sub(duration_ms);
            windows.push(aggregate_host_window(
                &connection,
                window,
                starts_at_ms,
                complete_through_ms,
                expected_minutes,
            )?);
        }
        Ok(HostHistorySnapshot {
            schema_version: HOST_HISTORY_SCHEMA_VERSION,
            generated_at_ms,
            complete_through_ms,
            windows,
        })
    }

    pub fn record_project_repository_sample(
        &self,
        observed_at_ms: i64,
        observation: &SourceTreeObservationV1,
    ) -> Result<RepositorySampleWrite, StoreError> {
        if observed_at_ms < 0 {
            return Err(StoreError::InvalidMetricTimestamp);
        }
        let file_count =
            i64::try_from(observation.file_count).map_err(|_| StoreError::MetricRange {
                field: "repository_file_count",
            })?;
        let total_bytes =
            i64::try_from(observation.total_bytes).map_err(|_| StoreError::MetricRange {
                field: "repository_total_bytes",
            })?;
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest: Option<i64> = transaction.query_row(
            "SELECT MAX(observed_at_ms)
                 FROM project_repository_samples
                 WHERE project_id = ?1",
            [observation.project_id.as_str()],
            |row| row.get(0),
        )?;
        if let Some(latest) = latest {
            let next_observation_at_ms =
                latest.saturating_add(PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS);
            if observed_at_ms < next_observation_at_ms {
                return Ok(RepositorySampleWrite::NotDue {
                    next_observation_at_ms,
                });
            }
        }
        transaction.execute(
            "INSERT INTO project_repository_samples(
                project_id, observed_at_ms, head, file_count, total_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                observation.project_id.as_str(),
                observed_at_ms,
                observation.head.as_str(),
                file_count,
                total_bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(RepositorySampleWrite::Recorded)
    }

    pub fn next_project_repository_observation_at(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<i64>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let latest: Option<i64> = connection.query_row(
            "SELECT MAX(observed_at_ms)
             FROM project_repository_samples
             WHERE project_id = ?1",
            [project_id.as_str()],
            |row| row.get(0),
        )?;
        Ok(latest.map(|value| value.saturating_add(PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS)))
    }

    pub fn project_repository_history(
        &self,
        project_id: &ProjectId,
        since_ms: i64,
    ) -> Result<Vec<ProjectRepositorySample>, StoreError> {
        if since_ms < 0 {
            return Err(StoreError::InvalidMetricTimestamp);
        }
        let limit = i64::try_from(PROJECT_REPOSITORY_HISTORY_LIMIT).unwrap_or(i64::MAX);
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT observed_at_ms, head, file_count, total_bytes
             FROM (
                SELECT observed_at_ms, head, file_count, total_bytes
                FROM project_repository_samples
                WHERE project_id = ?1 AND observed_at_ms >= ?2
                ORDER BY observed_at_ms DESC
                LIMIT ?3
             )
             ORDER BY observed_at_ms",
        )?;
        let mut rows = statement.query(params![project_id.as_str(), since_ms, limit])?;
        let mut samples = Vec::new();
        while let Some(row) = rows.next()? {
            let head: String = row.get(1)?;
            samples.push(ProjectRepositorySample {
                observed_at_ms: row.get(0)?,
                head: head.parse().map_err(|_| StoreError::CorruptMetric {
                    field: "repository_head",
                })?,
                file_count: sqlite_required_u64(row, 2, "repository_file_count")?,
                total_bytes: sqlite_required_u64(row, 3, "repository_total_bytes")?,
            });
        }
        Ok(samples)
    }
}

fn aggregate_host_window(
    connection: &Connection,
    window: HostHistoryWindowKind,
    starts_at_ms: i64,
    ends_at_ms: i64,
    expected_minutes: u64,
) -> Result<HostHistoryWindow, StoreError> {
    let mut aggregate = HostMinuteRollup::new(starts_at_ms);
    let mut covered_buckets = BTreeSet::new();

    let mut rollup_statement = connection.prepare(
        "SELECT bucket_start_ms, rollup_json
         FROM host_minute_rollups
         WHERE bucket_start_ms >= ?1 AND bucket_start_ms < ?2
         ORDER BY bucket_start_ms",
    )?;
    let mut rollup_rows = rollup_statement.query(params![starts_at_ms, ends_at_ms])?;
    while let Some(row) = rollup_rows.next()? {
        let bucket_start_ms: i64 = row.get(0)?;
        let rollup_json: String = row.get(1)?;
        let rollup: HostMinuteRollup = serde_json::from_str(&rollup_json)?;
        if rollup.bucket_start_ms != bucket_start_ms {
            return Err(StoreError::CorruptRollup {
                kind: "host",
                key: bucket_start_ms.to_string(),
            });
        }
        covered_buckets.insert(bucket_start_ms);
        aggregate.merge(&rollup);
    }
    drop(rollup_rows);
    drop(rollup_statement);

    let mut sample_statement = connection.prepare(
        "SELECT
            sample_id, observed_at_ms, status_json, cpu_percent, load_1, load_5, load_15,
            memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
            disk_total_bytes, disk_available_bytes, network_rx_bytes, network_tx_bytes,
            network_rx_bytes_per_second, network_tx_bytes_per_second,
            psi_cpu_some_avg10, psi_memory_some_avg10, psi_io_some_avg10,
            partial_reasons_json
         FROM host_samples
         WHERE observed_at_ms >= ?1 AND observed_at_ms < ?2
         ORDER BY observed_at_ms, sample_id",
    )?;
    let mut sample_rows = sample_statement.query(params![starts_at_ms, ends_at_ms])?;
    while let Some(row) = sample_rows.next()? {
        let (sample_id, sample) = host_sample_from_row(row)?;
        covered_buckets.insert(minute_bucket(sample.observed_at_ms));
        aggregate.add(sample_id, &sample);
    }

    let covered_minutes = u64::try_from(covered_buckets.len()).unwrap_or(u64::MAX);
    Ok(HostHistoryWindow {
        window,
        starts_at_ms,
        ends_at_ms,
        sample_count: aggregate.sample_count,
        covered_minutes,
        expected_minutes,
        complete: covered_minutes == expected_minutes,
        medians: HostMetricMedians {
            cpu_percent: aggregate.metrics.cpu_percent.quantile(0.5),
            load_1: aggregate.metrics.load_1.quantile(0.5),
            memory_used_percent: aggregate.metrics.memory_used_percent.quantile(0.5),
            disk_used_percent: aggregate.metrics.disk_used_percent.quantile(0.5),
            network_rx_bytes_per_second: aggregate
                .metrics
                .network_rx_bytes_per_second
                .quantile(0.5),
            network_tx_bytes_per_second: aggregate
                .metrics
                .network_tx_bytes_per_second
                .quantile(0.5),
            psi_cpu_some_avg10: aggregate.metrics.psi_cpu_some_avg10.quantile(0.5),
            psi_memory_some_avg10: aggregate.metrics.psi_memory_some_avg10.quantile(0.5),
            psi_io_some_avg10: aggregate.metrics.psi_io_some_avg10.quantile(0.5),
        },
        totals: HostMetricTotals {
            network_rx_bytes: aggregate.traffic.rx.total(),
            network_tx_bytes: aggregate.traffic.tx.total(),
            network_rx_covered_ms: aggregate.traffic.rx.covered_ms(),
            network_tx_covered_ms: aggregate.traffic.tx.covered_ms(),
        },
    })
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 if table_exists(connection, "host_samples")? => migrate_legacy_schema(connection),
        0 => {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            create_schema(&transaction)?;
            transaction.pragma_update(None, "user_version", METRICS_SCHEMA_VERSION)?;
            transaction.commit()?;
            Ok(())
        }
        2 => migrate_v2_schema(connection),
        3 => migrate_v3_schema(connection),
        METRICS_SCHEMA_VERSION => create_schema(connection),
        actual => Err(StoreError::UnsupportedMetricsSchemaVersion {
            actual,
            supported: METRICS_SCHEMA_VERSION,
        }),
    }
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, StoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn migrate_legacy_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "ALTER TABLE host_samples RENAME TO host_samples_v1;
         ALTER TABLE project_samples RENAME TO project_samples_v1;
         DROP INDEX IF EXISTS host_samples_time;
         DROP INDEX IF EXISTS project_samples_project_time;
         DROP INDEX IF EXISTS project_samples_time;",
    )?;
    validate_legacy_project_ids(&transaction)?;
    create_schema(&transaction)?;
    transaction.execute_batch(
        "INSERT INTO host_samples(
            observed_at_ms, status_json, cpu_percent, load_1, load_5, load_15,
            memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
            disk_total_bytes, disk_available_bytes, network_rx_bytes, network_tx_bytes,
            network_rx_bytes_per_second, network_tx_bytes_per_second,
            psi_cpu_some_avg10, psi_memory_some_avg10, psi_io_some_avg10,
            partial_reasons_json
         )
         SELECT
            observed_at_ms, status_json, cpu_percent, load_1, load_5, load_15,
            memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
            disk_total_bytes, disk_available_bytes, network_rx_bytes, network_tx_bytes,
            network_rx_bytes_per_second, network_tx_bytes_per_second,
            psi_cpu_some_avg10, psi_memory_some_avg10, psi_io_some_avg10,
            partial_reasons_json
         FROM host_samples_v1
         ORDER BY observed_at_ms;",
    )?;
    let expected_projects: i64 =
        transaction.query_row("SELECT COUNT(*) FROM project_samples_v1", [], |row| {
            row.get(0)
        })?;
    let migrated_projects = transaction.execute(
        "INSERT INTO project_samples(
            sample_id, collected_at_ms, project_id, display_name, condition_json,
            observed_at_ms, detail
         )
         SELECT
            host.sample_id, project.collected_at_ms, project.project_id,
            project.display_name, project.condition_json, project.observed_at_ms, project.detail
         FROM project_samples_v1 AS project
         JOIN host_samples AS host ON host.observed_at_ms = project.collected_at_ms
         ORDER BY host.sample_id, project.project_id",
        [],
    )?;
    if usize::try_from(expected_projects).ok() != Some(migrated_projects) {
        return Err(StoreError::LegacyMetricsMigrationMismatch {
            expected: expected_projects,
            migrated: migrated_projects,
        });
    }
    transaction.execute_batch(
        "DROP TABLE project_samples_v1;
         DROP TABLE host_samples_v1;",
    )?;
    transaction.pragma_update(None, "user_version", METRICS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_legacy_project_ids(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let mut statement =
        transaction.prepare("SELECT DISTINCT project_id FROM project_samples_v1")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let project_id: String = row.get(0)?;
        if project_id.parse::<crate::domain::ProjectId>().is_err() {
            return Err(StoreError::InvalidLegacyProjectId {
                value: truncate_utf8(&project_id, 128, "…"),
            });
        }
    }
    Ok(())
}

fn migrate_v2_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "DROP INDEX IF EXISTS host_samples_time;
         DROP INDEX IF EXISTS project_samples_time;",
    )?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", METRICS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v3_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", METRICS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn create_schema(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS host_samples (
            sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at_ms INTEGER NOT NULL,
            status_json TEXT NOT NULL,
            cpu_percent REAL,
            load_1 REAL,
            load_5 REAL,
            load_15 REAL,
            memory_total_bytes INTEGER,
            memory_available_bytes INTEGER,
            swap_total_bytes INTEGER,
            swap_free_bytes INTEGER,
            disk_total_bytes INTEGER,
            disk_available_bytes INTEGER,
            network_rx_bytes INTEGER,
            network_tx_bytes INTEGER,
            network_rx_bytes_per_second INTEGER,
            network_tx_bytes_per_second INTEGER,
            psi_cpu_some_avg10 REAL,
            psi_memory_some_avg10 REAL,
            psi_io_some_avg10 REAL,
            partial_reasons_json TEXT NOT NULL
         ) STRICT;

         CREATE INDEX IF NOT EXISTS host_samples_time
            ON host_samples(observed_at_ms, sample_id);

         CREATE TABLE IF NOT EXISTS project_samples (
            sample_id INTEGER NOT NULL REFERENCES host_samples(sample_id) ON DELETE CASCADE,
            collected_at_ms INTEGER NOT NULL,
            project_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            condition_json TEXT NOT NULL,
            observed_at_ms INTEGER,
            detail TEXT NOT NULL,
            PRIMARY KEY (sample_id, project_id)
         ) STRICT;

         CREATE INDEX IF NOT EXISTS project_samples_project_time
            ON project_samples(project_id, collected_at_ms DESC);
         CREATE INDEX IF NOT EXISTS project_samples_time
            ON project_samples(collected_at_ms, sample_id, project_id);

         CREATE TABLE IF NOT EXISTS host_minute_rollups (
            bucket_start_ms INTEGER PRIMARY KEY,
            rollup_json TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS project_minute_rollups (
            bucket_start_ms INTEGER NOT NULL,
            project_id TEXT NOT NULL,
            rollup_json TEXT NOT NULL,
            PRIMARY KEY (bucket_start_ms, project_id)
         ) STRICT;

         CREATE INDEX IF NOT EXISTS project_minute_rollups_project_time
            ON project_minute_rollups(project_id, bucket_start_ms DESC);

         CREATE TABLE IF NOT EXISTS project_repository_samples (
            project_id TEXT NOT NULL,
            observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
            head TEXT NOT NULL,
            file_count INTEGER NOT NULL CHECK(file_count >= 0),
            total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
            PRIMARY KEY (project_id, observed_at_ms)
         ) STRICT;

         CREATE INDEX IF NOT EXISTS project_repository_samples_project_time
            ON project_repository_samples(project_id, observed_at_ms DESC);",
    )?;
    Ok(())
}

fn insert_host_sample(connection: &Connection, sample: &HostTelemetry) -> Result<i64, StoreError> {
    let memory_total = sqlite_integer(sample.memory_total_bytes, "memory_total_bytes")?;
    let memory_available = sqlite_integer(sample.memory_available_bytes, "memory_available_bytes")?;
    let swap_total = sqlite_integer(sample.swap_total_bytes, "swap_total_bytes")?;
    let swap_free = sqlite_integer(sample.swap_free_bytes, "swap_free_bytes")?;
    let disk_total = sqlite_integer(sample.disk_total_bytes, "disk_total_bytes")?;
    let disk_available = sqlite_integer(sample.disk_available_bytes, "disk_available_bytes")?;
    let network_rx = sqlite_integer(sample.network_rx_bytes, "network_rx_bytes")?;
    let network_tx = sqlite_integer(sample.network_tx_bytes, "network_tx_bytes")?;
    let incoming_network_rate = sqlite_integer(
        sample.network_rx_bytes_per_second,
        "network_rx_bytes_per_second",
    )?;
    let outgoing_network_rate = sqlite_integer(
        sample.network_tx_bytes_per_second,
        "network_tx_bytes_per_second",
    )?;
    connection.execute(
        "INSERT INTO host_samples(
            observed_at_ms, status_json, cpu_percent, load_1, load_5, load_15,
            memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
            disk_total_bytes, disk_available_bytes, network_rx_bytes, network_tx_bytes,
            network_rx_bytes_per_second, network_tx_bytes_per_second,
            psi_cpu_some_avg10, psi_memory_some_avg10, psi_io_some_avg10,
            partial_reasons_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
         )",
        params![
            sample.observed_at_ms,
            serde_json::to_string(&sample.status)?,
            sample.cpu_percent,
            sample.load_1,
            sample.load_5,
            sample.load_15,
            memory_total,
            memory_available,
            swap_total,
            swap_free,
            disk_total,
            disk_available,
            network_rx,
            network_tx,
            incoming_network_rate,
            outgoing_network_rate,
            sample.psi.cpu_some_avg10,
            sample.psi.memory_some_avg10,
            sample.psi.io_some_avg10,
            serde_json::to_string(&sample.partial_reasons)?,
        ],
    )?;
    Ok(connection.last_insert_rowid())
}

fn roll_up_host_samples(
    transaction: &Transaction<'_>,
    cutoff_ms: i64,
) -> Result<usize, StoreError> {
    let mut written = 0_usize;
    let mut current: Option<HostMinuteRollup> = None;
    let mut statement = transaction.prepare(
        "SELECT
            sample_id, observed_at_ms, status_json, cpu_percent, load_1, load_5, load_15,
            memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
            disk_total_bytes, disk_available_bytes, network_rx_bytes, network_tx_bytes,
            network_rx_bytes_per_second, network_tx_bytes_per_second,
            psi_cpu_some_avg10, psi_memory_some_avg10, psi_io_some_avg10,
            partial_reasons_json
         FROM host_samples
         WHERE observed_at_ms < ?1
         ORDER BY observed_at_ms, sample_id",
    )?;
    let mut rows = statement.query([cutoff_ms])?;
    while let Some(row) = rows.next()? {
        let (sample_id, sample) = host_sample_from_row(row)?;
        let bucket = minute_bucket(sample.observed_at_ms);
        if current
            .as_ref()
            .is_some_and(|rollup| rollup.bucket_start_ms != bucket)
            && let Some(rollup) = current.take()
        {
            write_host_rollup(transaction, &rollup)?;
            written = written.saturating_add(1);
        }
        current
            .get_or_insert_with(|| HostMinuteRollup::new(bucket))
            .add(sample_id, &sample);
    }
    drop(rows);
    drop(statement);
    if let Some(rollup) = current {
        write_host_rollup(transaction, &rollup)?;
        written = written.saturating_add(1);
    }
    Ok(written)
}

fn roll_up_project_samples(
    transaction: &Transaction<'_>,
    cutoff_ms: i64,
) -> Result<usize, StoreError> {
    let mut written = 0_usize;
    let mut current_bucket: Option<i64> = None;
    let mut current = BTreeMap::<String, ProjectMinuteRollup>::new();
    let mut statement = transaction.prepare(
        "SELECT
            sample_id, collected_at_ms, project_id, display_name, condition_json,
            observed_at_ms, detail
         FROM project_samples
         WHERE collected_at_ms < ?1
         ORDER BY collected_at_ms, sample_id, project_id",
    )?;
    let mut rows = statement.query([cutoff_ms])?;
    while let Some(row) = rows.next()? {
        let sample_id: i64 = row.get(0)?;
        let collected_at_ms: i64 = row.get(1)?;
        let project_id: String = row.get(2)?;
        let condition_json: String = row.get(4)?;
        let sample = ProjectTelemetry {
            project_id: project_id.parse().map_err(|_| StoreError::CorruptMetric {
                field: "project_id",
            })?,
            display_name: row.get(3)?,
            condition: serde_json::from_str(&condition_json)?,
            observed_at_ms: row.get(5)?,
            detail: row.get(6)?,
        };
        let bucket = minute_bucket(collected_at_ms);
        if current_bucket.is_some_and(|active| active != bucket) {
            written = written.saturating_add(write_project_bucket(transaction, current)?);
            current = BTreeMap::new();
        }
        current_bucket = Some(bucket);
        current
            .entry(project_id.clone())
            .or_insert_with(|| ProjectMinuteRollup::new(bucket, project_id))
            .add(sample_id, collected_at_ms, sample);
    }
    drop(rows);
    drop(statement);
    written = written.saturating_add(write_project_bucket(transaction, current)?);
    Ok(written)
}

fn write_host_rollup(
    transaction: &Transaction<'_>,
    incoming: &HostMinuteRollup,
) -> Result<(), StoreError> {
    let bucket = incoming.bucket_start_ms;
    let mut rollup =
        load_host_rollup(transaction, bucket)?.unwrap_or_else(|| HostMinuteRollup::new(bucket));
    rollup.merge(incoming);
    transaction.execute(
        "INSERT INTO host_minute_rollups(bucket_start_ms, rollup_json)
         VALUES (?1, ?2)
         ON CONFLICT(bucket_start_ms) DO UPDATE SET rollup_json = excluded.rollup_json",
        params![bucket, serde_json::to_string(&rollup)?],
    )?;
    Ok(())
}

fn write_project_bucket(
    transaction: &Transaction<'_>,
    pending: BTreeMap<String, ProjectMinuteRollup>,
) -> Result<usize, StoreError> {
    let written = pending.len();
    for (project_id, incoming) in pending {
        let bucket = incoming.bucket_start_ms;
        let mut rollup = load_project_rollup(transaction, bucket, &project_id)?
            .unwrap_or_else(|| ProjectMinuteRollup::new(bucket, project_id.clone()));
        rollup.merge(&incoming);
        transaction.execute(
            "INSERT INTO project_minute_rollups(bucket_start_ms, project_id, rollup_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(bucket_start_ms, project_id)
             DO UPDATE SET rollup_json = excluded.rollup_json",
            params![bucket, project_id, serde_json::to_string(&rollup)?],
        )?;
    }
    Ok(written)
}

fn load_host_rollup(
    connection: &Connection,
    bucket_start_ms: i64,
) -> Result<Option<HostMinuteRollup>, StoreError> {
    let json: Option<String> = connection
        .query_row(
            "SELECT rollup_json FROM host_minute_rollups WHERE bucket_start_ms = ?1",
            [bucket_start_ms],
            |row| row.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let rollup: HostMinuteRollup = serde_json::from_str(&json)?;
    if rollup.bucket_start_ms != bucket_start_ms {
        return Err(StoreError::CorruptRollup {
            kind: "host",
            key: bucket_start_ms.to_string(),
        });
    }
    Ok(Some(rollup))
}

fn load_project_rollup(
    connection: &Connection,
    bucket_start_ms: i64,
    project_id: &str,
) -> Result<Option<ProjectMinuteRollup>, StoreError> {
    let json: Option<String> = connection
        .query_row(
            "SELECT rollup_json FROM project_minute_rollups
             WHERE bucket_start_ms = ?1 AND project_id = ?2",
            params![bucket_start_ms, project_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let rollup: ProjectMinuteRollup = serde_json::from_str(&json)?;
    if rollup.bucket_start_ms != bucket_start_ms || rollup.project_id != project_id {
        return Err(StoreError::CorruptRollup {
            kind: "project",
            key: format!("{bucket_start_ms}:{project_id}"),
        });
    }
    Ok(Some(rollup))
}

fn host_sample_from_row(row: &Row<'_>) -> Result<(i64, HostTelemetry), StoreError> {
    let status_json: String = row.get(2)?;
    let partial_reasons_json: String = row.get(20)?;
    Ok((
        row.get(0)?,
        HostTelemetry {
            observed_at_ms: row.get(1)?,
            status: serde_json::from_str(&status_json)?,
            cpu_percent: row.get(3)?,
            load_1: row.get(4)?,
            load_5: row.get(5)?,
            load_15: row.get(6)?,
            memory_total_bytes: sqlite_u64(row, 7, "memory_total_bytes")?,
            memory_available_bytes: sqlite_u64(row, 8, "memory_available_bytes")?,
            swap_total_bytes: sqlite_u64(row, 9, "swap_total_bytes")?,
            swap_free_bytes: sqlite_u64(row, 10, "swap_free_bytes")?,
            disk_total_bytes: sqlite_u64(row, 11, "disk_total_bytes")?,
            disk_available_bytes: sqlite_u64(row, 12, "disk_available_bytes")?,
            network_rx_bytes: sqlite_u64(row, 13, "network_rx_bytes")?,
            network_tx_bytes: sqlite_u64(row, 14, "network_tx_bytes")?,
            network_rx_bytes_per_second: sqlite_u64(row, 15, "network_rx_bytes_per_second")?,
            network_tx_bytes_per_second: sqlite_u64(row, 16, "network_tx_bytes_per_second")?,
            psi: PsiMeasurement {
                cpu_some_avg10: row.get(17)?,
                memory_some_avg10: row.get(18)?,
                io_some_avg10: row.get(19)?,
            },
            partial_reasons: serde_json::from_str(&partial_reasons_json)?,
        },
    ))
}

fn count_rows(connection: &Mutex<Connection>, table: &'static str) -> Result<u64, StoreError> {
    let connection = lock_connection(connection)?;
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection.query_row(&query, [], |row| row.get(0))?;
    u64::try_from(count).map_err(|_| StoreError::SequenceRange)
}

fn sqlite_integer(value: Option<u64>, field: &'static str) -> Result<Option<i64>, StoreError> {
    value
        .map(|value| i64::try_from(value).map_err(|_| StoreError::MetricRange { field }))
        .transpose()
}

fn sqlite_u64(row: &Row<'_>, index: usize, field: &'static str) -> Result<Option<u64>, StoreError> {
    let value: Option<i64> = row.get(index)?;
    value
        .map(|value| u64::try_from(value).map_err(|_| StoreError::CorruptMetric { field }))
        .transpose()
}

fn sqlite_required_u64(
    row: &Row<'_>,
    index: usize,
    field: &'static str,
) -> Result<u64, StoreError> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| StoreError::CorruptMetric { field })
}

fn add_usage(
    used_sketch: &mut RelativeLogSketch,
    percent_sketch: &mut RelativeLogSketch,
    total: Option<u64>,
    available: Option<u64>,
) {
    let Some((total, available)) = total.zip(available) else {
        return;
    };
    let Some(used) = total.checked_sub(available) else {
        return;
    };
    used_sketch.add(u64_as_f64(used));
    if total > 0 {
        percent_sketch.add(u64_as_f64(used) * 100.0 / u64_as_f64(total));
    }
}

#[allow(clippy::cast_precision_loss)]
fn u64_as_f64(value: u64) -> f64 {
    value as f64
}

#[allow(clippy::cast_possible_truncation)]
fn bin_index(value: f64) -> i32 {
    let raw = (value.ln() / log_gamma()).ceil();
    if raw <= f64::from(i32::MIN) {
        i32::MIN
    } else if raw >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        raw as i32
    }
}

fn bin_value(index: i32) -> f64 {
    let gamma = gamma();
    gamma.powi(index) * 2.0 / (gamma + 1.0)
}

fn gamma() -> f64 {
    (1.0 + LOG_SKETCH_RELATIVE_ACCURACY) / (1.0 - LOG_SKETCH_RELATIVE_ACCURACY)
}

fn log_gamma() -> f64 {
    gamma().ln()
}

fn minute_bucket(timestamp_ms: i64) -> i64 {
    timestamp_ms
        .div_euclid(MINUTE_ROLLUP_MS)
        .saturating_mul(MINUTE_ROLLUP_MS)
}
