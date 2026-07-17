use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Fresh,
    Stale,
    SignalLost,
    Partial,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PsiMeasurement {
    pub cpu_some_avg10: Option<f64>,
    pub memory_some_avg10: Option<f64>,
    pub io_some_avg10: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostTelemetry {
    pub observed_at_ms: i64,
    pub status: ObservationStatus,
    pub cpu_percent: Option<f64>,
    pub load_1: Option<f64>,
    pub load_5: Option<f64>,
    pub load_15: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub disk_available_bytes: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub network_rx_bytes_per_second: Option<u64>,
    pub network_tx_bytes_per_second: Option<u64>,
    pub psi: PsiMeasurement,
    pub partial_reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHistoryWindowKind {
    Hour,
    Day,
    Week,
    Month,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetricMedians {
    pub cpu_percent: Option<f64>,
    pub load_1: Option<f64>,
    pub memory_used_percent: Option<f64>,
    pub disk_used_percent: Option<f64>,
    pub network_rx_bytes_per_second: Option<f64>,
    pub network_tx_bytes_per_second: Option<f64>,
    pub psi_cpu_some_avg10: Option<f64>,
    pub psi_memory_some_avg10: Option<f64>,
    pub psi_io_some_avg10: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetricTotals {
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub network_rx_covered_ms: u64,
    pub network_tx_covered_ms: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostHistoryWindow {
    pub window: HostHistoryWindowKind,
    pub starts_at_ms: i64,
    pub ends_at_ms: i64,
    pub sample_count: u64,
    pub covered_minutes: u64,
    pub expected_minutes: u64,
    pub complete: bool,
    pub medians: HostMetricMedians,
    pub totals: HostMetricTotals,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostHistorySnapshot {
    pub schema_version: u16,
    pub generated_at_ms: i64,
    pub complete_through_ms: i64,
    pub windows: Vec<HostHistoryWindow>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRepositorySample {
    pub observed_at_ms: i64,
    pub head: super::GitCommitId,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceTelemetry {
    pub status: ObservationStatus,
    pub observed_at_ms: Option<i64>,
    pub cpu_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceMetricMedians {
    pub cpu_percent: Option<f64>,
    pub memory_used_bytes: Option<f64>,
    pub memory_used_percent: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceMetricTotals {
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub network_rx_covered_ms: u64,
    pub network_tx_covered_ms: u64,
    pub block_read_covered_ms: u64,
    pub block_write_covered_ms: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceHistoryWindow {
    pub window: HostHistoryWindowKind,
    pub starts_at_ms: i64,
    pub ends_at_ms: i64,
    pub sample_count: u64,
    pub covered_minutes: u64,
    pub expected_minutes: u64,
    pub complete: bool,
    pub medians: ProjectResourceMetricMedians,
    pub totals: ProjectResourceMetricTotals,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceHistorySnapshot {
    pub schema_version: u16,
    pub generated_at_ms: i64,
    pub complete_through_ms: i64,
    pub project_id: super::ProjectId,
    pub windows: Vec<ProjectResourceHistoryWindow>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardSnapshot {
    pub generated_at_ms: i64,
    pub host: HostTelemetry,
    pub projects: Vec<ProjectTelemetry>,
    pub control: ControlSummary,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectTelemetry {
    pub project_id: super::ProjectId,
    pub display_name: String,
    pub condition: super::ProjectCondition,
    pub observed_at_ms: Option<i64>,
    pub detail: String,
    pub resources: ProjectResourceTelemetry,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSummary {
    pub sqlite_version: String,
    pub observation_operation_id: Uuid,
    pub sample_interval_seconds: u64,
}
