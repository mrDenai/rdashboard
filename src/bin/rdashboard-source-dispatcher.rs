use std::{collections::BTreeSet, path::Path, str::FromStr as _, time::Duration};

use rdashboard::{
    domain::ProjectId,
    installed_source::load_installed_source_config,
    installed_workflow::InstalledWorkflowCatalogV1,
    scheduler::DurableWorkflowScheduler,
    source_delivery::SourceWorkflowAdmitterV1,
    source_delivery::SourceWorkflowDeliveryError,
    source_delivery_socket::SourceDeliveryClientV1,
    store::{ControlStore, StoreError},
    unix_time_ms,
};
use serde::Serialize;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const CONTROL_STORE_PATH: &str = "/var/lib/rdashboard/control.sqlite";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const TRANSIENT_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const POLICY_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const OUTBOX_BATCH: u8 = 32;
const MAX_BATCHES_PER_CYCLE: usize = 8;
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    init_tracing()?;
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 3 && arguments[1].to_str() == Some("shadow") {
        let project_id = arguments[2]
            .to_str()
            .ok_or(DispatcherError::InvalidInvocation)
            .and_then(|value| {
                ProjectId::from_str(value).map_err(|_| DispatcherError::InvalidInvocation)
            })?;
        return run_shadow(project_id).await;
    }
    if arguments.len() != 1 {
        return Err(DispatcherError::InvalidInvocation.into());
    }
    run_service().await
}

async fn run_service() -> Result<(), DynError> {
    let source_config = load_installed_source_config()?;
    let workflow_catalog =
        InstalledWorkflowCatalogV1::load_root_owned_for_group(source_config.controller_gid)?;
    let scheduler =
        DurableWorkflowScheduler::new(ControlStore::open(Path::new(CONTROL_STORE_PATH))?);
    let admitter =
        SourceWorkflowAdmitterV1::new(scheduler, workflow_catalog, source_config.clone())?;
    let delivery_socket_path = source_config.delivery_socket_path.clone();
    let client = SourceDeliveryClientV1::new(
        delivery_socket_path,
        source_config.source_uid,
        REQUEST_TIMEOUT,
    )?;

    let mut next_poll = Duration::ZERO;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            () = tokio::time::sleep(next_poll) => {
                next_poll = match drain_cycle(&client, &admitter).await {
                    Ok(DrainCycleOutcome::Drained) => POLL_INTERVAL,
                    Ok(DrainCycleOutcome::RetryAfter(delay)) => delay,
                    Err(error) => {
                        error!(error = %error, "source workflow delivery cycle failed");
                        TRANSIENT_RETRY_INTERVAL
                    }
                };
            }
        }
    }
}

async fn run_shadow(project_id: ProjectId) -> Result<(), DynError> {
    let source_config = load_installed_source_config()?;
    if rustix::process::geteuid().as_raw() != source_config.controller_uid {
        return Err(DispatcherError::WrongIdentity.into());
    }
    let workflow_catalog =
        InstalledWorkflowCatalogV1::load_root_owned_for_group(source_config.controller_gid)?;
    let scheduler =
        DurableWorkflowScheduler::new(ControlStore::open(Path::new(CONTROL_STORE_PATH))?);
    let admitter =
        SourceWorkflowAdmitterV1::new(scheduler, workflow_catalog, source_config.clone())?;
    let client = SourceDeliveryClientV1::new(
        source_config.delivery_socket_path.clone(),
        source_config.source_uid,
        REQUEST_TIMEOUT,
    )?;
    let entry = client.current_shadow(&project_id).await?;
    let admitted_at_ms = unix_time_ms()?;
    let outcome = admitter.admit_shadow(&entry, admitted_at_ms)?;
    let attempt = outcome.attempt();
    let receipt = ShadowAdmissionReceiptV1 {
        purpose: "rdashboard.workflow-shadow-admission.v1",
        schema_version: 1,
        project_id: &attempt.project_id,
        source_sha: attempt.source_sha.as_str(),
        source_sequence: attempt.source_sequence,
        attempt_id: attempt.attempt_id,
        created: outcome.created(),
        admitted_at_ms,
    };
    println!(
        "{}",
        String::from_utf8(serde_jcs::to_vec(&receipt)?)
            .map_err(|_| DispatcherError::InvalidReceiptEncoding)?
    );
    Ok(())
}

#[derive(Serialize)]
struct ShadowAdmissionReceiptV1<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    source_sha: &'a str,
    source_sequence: u64,
    attempt_id: uuid::Uuid,
    created: bool,
    admitted_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainCycleOutcome {
    Drained,
    RetryAfter(Duration),
}

async fn drain_cycle(
    client: &SourceDeliveryClientV1,
    admitter: &SourceWorkflowAdmitterV1,
) -> Result<DrainCycleOutcome, DynError> {
    let mut rejected_sequences = BTreeSet::new();
    let mut cycle_retry_after: Option<Duration> = None;
    for _ in 0..MAX_BATCHES_PER_CYCLE {
        let entries = client.pending(OUTBOX_BATCH).await?;
        if entries.is_empty() {
            return Ok(DrainCycleOutcome::Drained);
        }
        let mut made_progress = false;
        for entry in entries {
            if rejected_sequences.contains(&entry.outbox_sequence) {
                continue;
            }
            let admitted_at_ms = unix_time_ms()?;
            match admitter.admit(&entry, admitted_at_ms) {
                Ok(outcome) => {
                    client.acknowledge(&entry).await?;
                    made_progress = true;
                    info!(
                        project_id = %entry.project_id,
                        source_sequence = entry.source_sequence,
                        source_sha = %entry.attestation.payload.head,
                        attempt_id = %outcome.attempt().attempt_id,
                        created = outcome.created(),
                        "accepted source delivered to workflow scheduler"
                    );
                }
                Err(SourceWorkflowDeliveryError::Scheduler(StoreError::WorkflowStaleSource)) => {
                    client.acknowledge(&entry).await?;
                    made_progress = true;
                    info!(
                        project_id = %entry.project_id,
                        source_sequence = entry.source_sequence,
                        source_sha = %entry.attestation.payload.head,
                        "obsolete source delivery already superseded by scheduler head"
                    );
                }
                Err(error) => {
                    rejected_sequences.insert(entry.outbox_sequence);
                    cycle_retry_after = Some(cycle_retry_after.map_or_else(
                        || rejection_retry_interval(&error),
                        |current| current.max(rejection_retry_interval(&error)),
                    ));
                    error!(
                        project_id = %entry.project_id,
                        source_sequence = entry.source_sequence,
                        attestation_digest = %entry.attestation_digest,
                        error = %error,
                        "source outbox entry rejected by installed workflow policy"
                    );
                }
            }
        }
        if !made_progress {
            return Ok(
                cycle_retry_after.map_or(DrainCycleOutcome::Drained, DrainCycleOutcome::RetryAfter)
            );
        }
    }
    Ok(cycle_retry_after.map_or(DrainCycleOutcome::Drained, DrainCycleOutcome::RetryAfter))
}

fn rejection_retry_interval(error: &SourceWorkflowDeliveryError) -> Duration {
    if matches!(
        error,
        SourceWorkflowDeliveryError::Scheduler(_)
            | SourceWorkflowDeliveryError::Attestation(
                rdashboard::source::SourceAttestationError::Expired
            )
    ) {
        TRANSIENT_RETRY_INTERVAL
    } else {
        POLICY_RETRY_INTERVAL
    }
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum DispatcherError {
    #[error("source dispatcher accepts either no arguments or: shadow <project-id>")]
    InvalidInvocation,
    #[error("manual shadow admission must run as the installed rdashboard controller identity")]
    WrongIdentity,
    #[error("manual shadow admission receipt is not UTF-8")]
    InvalidReceiptEncoding,
}
