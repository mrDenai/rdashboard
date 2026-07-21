#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod adapter;
#[cfg(unix)]
pub mod adapter_entrypoint;
#[cfg(unix)]
pub mod adapter_identity;
#[cfg(unix)]
pub mod adapter_phase;
pub mod adapter_result;
pub mod authorization;
pub mod backup;
#[cfg(unix)]
pub mod backup_adapter;
#[cfg(unix)]
pub mod backup_driver;
pub mod build;
pub mod build_attestation;
pub mod build_source;
#[cfg(unix)]
pub mod cargo_prefetch;
pub mod controller;
#[cfg(unix)]
pub mod dependency_fetch;
#[cfg(unix)]
pub mod deploy_driver;
pub mod domain;
#[cfg(unix)]
pub mod execution_receipt;
pub mod executor;
#[cfg(unix)]
pub mod executor_authority;
pub mod executor_intent;
#[cfg(unix)]
pub mod executor_socket;
#[cfg(unix)]
pub mod fence_adapter;
#[cfg(unix)]
pub mod fence_job;
#[cfg(unix)]
pub mod installed_clock;
#[cfg(unix)]
pub mod installed_deploy;
#[cfg(unix)]
pub mod installed_effects;
#[cfg(unix)]
pub mod installed_intent_resolver;
#[cfg(unix)]
pub mod installed_policy;
#[cfg(unix)]
pub mod installed_source;
#[cfg(unix)]
pub mod installed_workflow;
pub mod integration_collectors;
pub mod integrations;
#[cfg(unix)]
pub mod kamal_adapter;
pub mod metrics;
#[cfg(unix)]
pub mod mutation_admission;
pub mod notification_delivery;
pub mod notification_planner;
pub mod notifications;
#[cfg(unix)]
pub mod notifier_socket;
#[cfg(unix)]
pub mod observer;
#[cfg(unix)]
pub mod oci_handoff;
#[cfg(unix)]
pub mod operation_state;
pub mod phase6;
pub mod policy;
#[cfg(unix)]
pub mod preparation;
pub mod projects;
pub mod protocol;
#[cfg(unix)]
pub mod rimg_adapter;
#[cfg(unix)]
pub mod root_adapter_runtime;
#[cfg(unix)]
pub mod root_fence_runtime;
#[cfg(unix)]
pub mod rootless_oci;
#[cfg(unix)]
pub mod rootless_oci_build;
pub mod scheduler;
#[cfg(unix)]
pub mod self_release_build;
#[cfg(unix)]
pub mod self_update;
#[cfg(unix)]
pub mod self_update_handoff;
#[cfg(unix)]
pub mod self_update_recovery;
#[cfg(unix)]
pub mod self_update_runtime;
pub mod source;
#[cfg(unix)]
pub mod source_delivery;
#[cfg(unix)]
pub mod source_delivery_socket;
#[cfg(unix)]
pub mod source_ingress_socket;
#[cfg(unix)]
pub mod source_socket;
pub mod store;
pub mod web;
#[cfg(unix)]
pub mod worker_socket;
#[cfg(unix)]
pub mod workflow_execution_authority;
#[cfg(unix)]
pub mod workflow_execution_grant;
#[cfg(unix)]
pub mod workflow_launcher;
#[cfg(unix)]
pub mod workflow_launcher_socket;
#[cfg(unix)]
pub mod workflow_worker;

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// Returns the current Unix time in milliseconds without silently accepting a broken host clock.
pub fn unix_time_ms() -> Result<i64, SystemTimeError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}
