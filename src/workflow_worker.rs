use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{
        ffi::OsStringExt as _,
        fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    },
    panic::AssertUnwindSafe,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures_util::{FutureExt as _, future::BoxFuture};
use serde::Serialize;
use tar::{Archive, EntryType};
use tokio::{sync::watch, task::JoinSet, time::Instant};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    build_source::SourceArchiveReaderV1,
    cargo_prefetch::{
        CARGO_LOCK_MAX_BYTES, CargoLockPlanV1, CargoPrefetchError, CargoRegistryPackageV1,
        cargo_vendor_layout_digest, materialize_cargo_dependency_cancellable,
    },
    dependency_fetch::{DependencyFetchClientError, DependencyFetchClientV1},
    domain::{
        EvidenceDigest, WorkflowAdapterIdV1, WorkflowArtifactKindV1, WorkflowCleanupReceiptV1,
        WorkflowCleanupResultV1, WorkflowHostPreparationAdapterV1, WorkflowLeaseV1,
        WorkflowNodeKindV1, WorkflowNodeOutcomeV1, WorkflowNodeReceiptV1,
    },
    preparation::{
        MAX_PREPARATION_STORE_BYTES, MAX_PREPARATION_STORE_INODES, PREPARED_RUN_COMPOSITION_FILE,
        PREPARED_RUN_SOURCE_DIRECTORY, PreparationKeyMaterialV1, PreparationStore,
        PreparationStoreError, PreparedEntryV1, PreparedRunCompositionV1,
    },
    scheduler::{WorkflowCleanupObligationV1, WorkflowWorkerRegistrationV1},
    unix_time_ms,
    worker_socket::{
        WorkflowWorkerAssignmentV1, WorkflowWorkerClientError, WorkflowWorkerClientV1,
        WorkflowWorkerLeaseGrantV1,
    },
    workflow_launcher::{WorkflowLaunchStateV1, WorkflowLaunchStatusV1},
    workflow_launcher_socket::{WorkflowLauncherClientError, WorkflowLauncherClientV1},
};

const MAX_SOURCE_PATH_BYTES: usize = 4_096;
const DEPENDENCY_MARKER_FILE: &str = "source-tree.jcs";
const DEPENDENCY_MARKER_PURPOSE: &str = "rdashboard.source-tree-dependency.v1";
const PREPARED_SOURCE_INPUT_PURPOSE: &str = "rdashboard.prepared-source-input.v1";
const PREPARED_CARGO_INPUT_PURPOSE: &str = "rdashboard.prepared-cargo-input.v1";
const PREPARATION_EVIDENCE_PURPOSE: &str = "rdashboard.host-preparation-evidence.v1";
const PREPARATION_CLEANUP_PURPOSE: &str = "rdashboard.host-preparation-cleanup.v1";
const WORKER_FAILURE_PURPOSE: &str = "rdashboard.workflow-worker-failure.v1";
const WORKER_PENDING_CLEANUP_PURPOSE: &str = "rdashboard.workflow-worker-pending-cleanup.v1";
const MAX_WORKER_SLOTS: usize = 16;
const CARGO_VENDOR_INODES_PER_PACKAGE: u64 = 512;
type HostPreparationTask =
    tokio::task::JoinHandle<Result<WorkflowHostPreparationResultV1, WorkflowWorkerError>>;

#[derive(Clone)]
pub struct WorkflowHostPreparerV1 {
    store: PreparationStore,
    source_reader: SourceArchiveReaderV1,
}

impl WorkflowHostPreparerV1 {
    pub const fn new(store: PreparationStore, source_reader: SourceArchiveReaderV1) -> Self {
        Self {
            store,
            source_reader,
        }
    }

    pub fn store(&self) -> &PreparationStore {
        &self.store
    }

    pub fn prepare_source_tree(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<WorkflowHostPreparationResultV1, WorkflowWorkerError> {
        let context = self.source_context(
            lease,
            now_ms,
            WorkflowHostPreparationAdapterV1::SourceTreeV1,
        )?;
        let dependency_material = PreparationKeyMaterialV1::DependencySnapshot {
            toolchain_digest: EvidenceDigest::sha256("rdashboard.source-tree.no-toolchain.v1"),
            lockfile_digest: EvidenceDigest::sha256("rdashboard.source-tree.no-lockfile.v1"),
            platform: context.platform.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
        };
        let marker = SourceTreeDependencyMarkerV1 {
            purpose: DEPENDENCY_MARKER_PURPOSE,
            schema_version: 1,
            host_preparation_policy_digest: context.policy_digest.clone(),
        };
        let marker_bytes = serde_jcs::to_vec(&marker)?;
        let marker_length = u64::try_from(marker_bytes.len())
            .map_err(|_| WorkflowWorkerError::SourcePayloadTooLarge)?;
        let dependency = self.store.get_or_prepare_bounded_directory(
            &dependency_material,
            marker_length,
            1,
            now_ms,
            |payload| write_new_file(&payload.join(DEPENDENCY_MARKER_FILE), &marker_bytes),
        )?;

        let generated_input_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&PreparedSourceInputV1 {
                purpose: PREPARED_SOURCE_INPUT_PURPOSE,
                schema_version: 1,
                host_preparation_policy_digest: context.policy_digest.clone(),
            })?);
        self.finish_prepared_run(lease, now_ms, context, &dependency, generated_input_digest)
    }

    pub fn prepare_cargo_crates_io<F, E>(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
        fetch: F,
    ) -> Result<WorkflowHostPreparationResultV1, WorkflowWorkerError>
    where
        F: FnMut(&CargoRegistryPackageV1) -> Result<Vec<u8>, E>,
        E: std::fmt::Display,
    {
        self.prepare_cargo_crates_io_cancellable(lease, now_ms, fetch, || false)
    }

    pub fn prepare_cargo_crates_io_cancellable<F, E, C>(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
        mut fetch: F,
        cancelled: C,
    ) -> Result<WorkflowHostPreparationResultV1, WorkflowWorkerError>
    where
        F: FnMut(&CargoRegistryPackageV1) -> Result<Vec<u8>, E>,
        E: std::fmt::Display,
        C: FnMut() -> bool,
    {
        let context = self.source_context(
            lease,
            now_ms,
            WorkflowHostPreparationAdapterV1::CargoCratesIoV1,
        )?;
        let lockfile = context.inventory.read_regular_file(
            &context.source_archive,
            Path::new("Cargo.lock"),
            CARGO_LOCK_MAX_BYTES,
        )?;
        let plan = CargoLockPlanV1::parse(&lockfile)?;
        let package_count = u64::try_from(plan.packages().len())
            .map_err(|_| WorkflowWorkerError::SourcePayloadTooLarge)?;
        let maximum_dependency_inodes = package_count
            .checked_mul(CARGO_VENDOR_INODES_PER_PACKAGE)
            .and_then(|inodes| inodes.checked_add(2))
            .ok_or(WorkflowWorkerError::SourcePayloadTooLarge)?
            .min(context.maximum_payload_inodes.saturating_mul(4) / 5);
        if maximum_dependency_inodes < 3 {
            return Err(WorkflowWorkerError::SourcePayloadTooLarge);
        }
        let dependency_material = PreparationKeyMaterialV1::DependencySnapshot {
            toolchain_digest: cargo_vendor_layout_digest(),
            lockfile_digest: plan.lockfile_digest().clone(),
            platform: context.platform.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
        };
        let dependency = self.store.get_or_prepare_bounded_directory(
            &dependency_material,
            context.maximum_payload_bytes,
            maximum_dependency_inodes,
            now_ms,
            |payload| {
                materialize_cargo_dependency_cancellable(
                    payload,
                    &plan,
                    context.policy_digest.clone(),
                    context.maximum_payload_bytes,
                    maximum_dependency_inodes,
                    |package| fetch(package),
                    cancelled,
                )
            },
        )?;
        let generated_input_digest =
            EvidenceDigest::sha256(serde_jcs::to_vec(&PreparedCargoInputV1 {
                purpose: PREPARED_CARGO_INPUT_PURPOSE,
                schema_version: 1,
                host_preparation_policy_digest: context.policy_digest.clone(),
                lockfile_digest: plan.lockfile_digest().clone(),
                package_plan_digest: plan.package_plan_digest().clone(),
            })?);
        self.finish_prepared_run(lease, now_ms, context, &dependency, generated_input_digest)
    }

    fn source_context(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
        expected_adapter: WorkflowHostPreparationAdapterV1,
    ) -> Result<SourcePreparationContextV1, WorkflowWorkerError> {
        validate_host_preparation_lease(lease)?;
        let policy = lease
            .host_preparation
            .as_ref()
            .ok_or(WorkflowWorkerError::UnsupportedHostPreparation)?;
        if policy.adapter_id != expected_adapter {
            return Err(WorkflowWorkerError::UnsupportedHostPreparation);
        }
        let resources = lease
            .resources
            .as_ref()
            .ok_or(WorkflowWorkerError::InvalidLease)?;
        let maximum_payload_bytes = resources
            .output_max_bytes
            .min(MAX_PREPARATION_STORE_BYTES)
            .min(self.store.maximum_generated_payload_bytes());
        let maximum_payload_inodes = resources
            .scratch_max_inodes
            .min(MAX_PREPARATION_STORE_INODES.saturating_sub(4))
            .min(self.store.maximum_generated_payload_inodes());
        let source = self
            .store
            .publish_source_snapshot(&self.source_reader, lease, now_ms)?;
        let source_pin_id = Uuid::new_v4();
        let pin_expires_at_ms = now_ms
            .checked_add(
                i64::try_from(lease.timeout_ms).map_err(|_| WorkflowWorkerError::InvalidLease)?,
            )
            .ok_or(WorkflowWorkerError::InvalidLease)?;
        let source = self.store.open_pinned(
            crate::preparation::PreparationObjectKindV1::SourceSnapshot,
            &source.manifest.key,
            source_pin_id,
            pin_expires_at_ms,
            now_ms,
        )?;
        let source_pin = PreparationPinGuardV1 {
            store: self.store.clone(),
            pin_id: source_pin_id,
            key: source.manifest.key.clone(),
        };
        let source_archive = source.payload_path().join("source.tar");
        let inventory = SourceTarInventoryV1::inspect(
            &source_archive,
            maximum_payload_bytes,
            maximum_payload_inodes,
        )?;
        Ok(SourcePreparationContextV1 {
            source,
            source_archive,
            inventory,
            maximum_payload_bytes,
            maximum_payload_inodes,
            policy_digest: policy.digest()?,
            platform: policy.platform.clone(),
            _source_pin: source_pin,
        })
    }

    fn finish_prepared_run(
        &self,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
        context: SourcePreparationContextV1,
        dependency: &PreparedEntryV1,
        generated_input_digest: EvidenceDigest,
    ) -> Result<WorkflowHostPreparationResultV1, WorkflowWorkerError> {
        let dependency_pin_id = Uuid::new_v4();
        let pin_expires_at_ms = now_ms
            .checked_add(
                i64::try_from(lease.timeout_ms).map_err(|_| WorkflowWorkerError::InvalidLease)?,
            )
            .ok_or(WorkflowWorkerError::InvalidLease)?;
        let dependency = self.store.open_pinned(
            crate::preparation::PreparationObjectKindV1::DependencySnapshot,
            &dependency.manifest.key,
            dependency_pin_id,
            pin_expires_at_ms,
            now_ms,
        )?;
        let _dependency_pin = PreparationPinGuardV1 {
            store: self.store.clone(),
            pin_id: dependency_pin_id,
            key: dependency.manifest.key.clone(),
        };
        let prepared_material = PreparationKeyMaterialV1::PreparedRun {
            source_snapshot_key: context.source.manifest.key.clone(),
            dependency_snapshot_key: dependency.manifest.key.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
            generated_input_digest,
        };
        let composition_bytes =
            PreparedRunCompositionV1::new(&prepared_material)?.canonical_bytes()?;
        let composition_length = u64::try_from(composition_bytes.len())
            .map_err(|_| WorkflowWorkerError::SourcePayloadTooLarge)?;
        let prepared_payload_bytes = context
            .inventory
            .payload_bytes
            .checked_add(composition_length)
            .ok_or(WorkflowWorkerError::SourcePayloadTooLarge)?;
        let prepared_payload_inodes = context
            .inventory
            .payload_inodes
            .checked_add(2)
            .ok_or(WorkflowWorkerError::SourcePayloadTooLarge)?;
        if prepared_payload_bytes > context.maximum_payload_bytes
            || prepared_payload_inodes > context.maximum_payload_inodes
        {
            return Err(WorkflowWorkerError::SourcePayloadTooLarge);
        }
        let prepared = self.store.get_or_prepare_bounded_directory(
            &prepared_material,
            prepared_payload_bytes,
            prepared_payload_inodes,
            now_ms,
            |payload| {
                let source = payload.join(PREPARED_RUN_SOURCE_DIRECTORY);
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&source)?;
                context
                    .inventory
                    .extract(&context.source_archive, &source)?;
                write_new_file(
                    &payload.join(PREPARED_RUN_COMPOSITION_FILE),
                    &composition_bytes,
                )?;
                Ok::<_, WorkflowWorkerError>(())
            },
        )?;
        Ok(WorkflowHostPreparationResultV1 {
            source_snapshot_key: context.source.manifest.key,
            dependency_snapshot_key: dependency.manifest.key,
            prepared_run_key: prepared.manifest.key,
            prepared_run_manifest_digest: prepared.manifest.document_digest,
        })
    }
}

struct SourcePreparationContextV1 {
    source: PreparedEntryV1,
    source_archive: PathBuf,
    inventory: SourceTarInventoryV1,
    maximum_payload_bytes: u64,
    maximum_payload_inodes: u64,
    policy_digest: EvidenceDigest,
    platform: String,
    _source_pin: PreparationPinGuardV1,
}

struct PreparationPinGuardV1 {
    store: PreparationStore,
    pin_id: Uuid,
    key: EvidenceDigest,
}

impl Drop for PreparationPinGuardV1 {
    fn drop(&mut self) {
        let _ = self.store.unpin_if_present(self.pin_id, &self.key);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowHostPreparationResultV1 {
    pub source_snapshot_key: EvidenceDigest,
    pub dependency_snapshot_key: EvidenceDigest,
    pub prepared_run_key: EvidenceDigest,
    pub prepared_run_manifest_digest: EvidenceDigest,
}

impl WorkflowHostPreparationResultV1 {
    pub fn execution_receipt_digest(
        &self,
        lease: &WorkflowLeaseV1,
    ) -> Result<EvidenceDigest, WorkflowWorkerError> {
        host_preparation_evidence_digest(
            lease,
            &self.source_snapshot_key,
            &self.dependency_snapshot_key,
            &self.prepared_run_key,
            &self.prepared_run_manifest_digest,
        )
    }
}

#[derive(Serialize)]
struct SourceTreeDependencyMarkerV1 {
    purpose: &'static str,
    schema_version: u16,
    host_preparation_policy_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct PreparedSourceInputV1 {
    purpose: &'static str,
    schema_version: u16,
    host_preparation_policy_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct PreparedCargoInputV1 {
    purpose: &'static str,
    schema_version: u16,
    host_preparation_policy_digest: EvidenceDigest,
    lockfile_digest: EvidenceDigest,
    package_plan_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct HostPreparationEvidenceV1<'a> {
    purpose: &'static str,
    lease_digest: &'a EvidenceDigest,
    source_snapshot_key: &'a EvidenceDigest,
    dependency_snapshot_key: &'a EvidenceDigest,
    prepared_run_key: &'a EvidenceDigest,
    prepared_run_manifest_digest: &'a EvidenceDigest,
}

#[derive(Serialize)]
struct HostPreparationCleanupEvidenceV1<'a> {
    purpose: &'static str,
    lease_digest: &'a EvidenceDigest,
    transient_runtime_created: bool,
}

fn host_preparation_evidence_digest(
    lease: &WorkflowLeaseV1,
    source_snapshot_key: &EvidenceDigest,
    dependency_snapshot_key: &EvidenceDigest,
    prepared_run_key: &EvidenceDigest,
    prepared_run_manifest_digest: &EvidenceDigest,
) -> Result<EvidenceDigest, WorkflowWorkerError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &HostPreparationEvidenceV1 {
            purpose: PREPARATION_EVIDENCE_PURPOSE,
            lease_digest: &lease.lease_digest,
            source_snapshot_key,
            dependency_snapshot_key,
            prepared_run_key,
            prepared_run_manifest_digest,
        },
    )?))
}

pub fn host_preparation_cleanup_digest(
    lease: &WorkflowLeaseV1,
) -> Result<EvidenceDigest, WorkflowWorkerError> {
    lease.validate()?;
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &HostPreparationCleanupEvidenceV1 {
            purpose: PREPARATION_CLEANUP_PURPOSE,
            lease_digest: &lease.lease_digest,
            transient_runtime_created: false,
        },
    )?))
}

pub trait WorkflowWorkerGatewayClientV1: Send + Sync {
    fn poll(&self) -> BoxFuture<'_, Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError>>;

    fn renew_lease(
        &self,
        lease: WorkflowLeaseV1,
    ) -> BoxFuture<'_, Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError>>;

    fn complete_node(
        &self,
        receipt: WorkflowNodeReceiptV1,
    ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>>;

    fn complete_cleanup(
        &self,
        receipt: WorkflowCleanupReceiptV1,
    ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>>;
}

impl WorkflowWorkerGatewayClientV1 for WorkflowWorkerClientV1 {
    fn poll(&self) -> BoxFuture<'_, Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError>> {
        Box::pin(WorkflowWorkerClientV1::poll(self))
    }

    fn renew_lease(
        &self,
        lease: WorkflowLeaseV1,
    ) -> BoxFuture<'_, Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError>> {
        Box::pin(WorkflowWorkerClientV1::renew_lease(self, lease))
    }

    fn complete_node(
        &self,
        receipt: WorkflowNodeReceiptV1,
    ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
        Box::pin(async move {
            WorkflowWorkerClientV1::complete_node(self, receipt)
                .await
                .map(|_| ())
        })
    }

    fn complete_cleanup(
        &self,
        receipt: WorkflowCleanupReceiptV1,
    ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
        Box::pin(async move {
            WorkflowWorkerClientV1::complete_cleanup(self, receipt)
                .await
                .map(|_| ())
        })
    }
}

pub trait WorkflowWorkerLauncherClientV1: Send + Sync {
    fn launch(
        &self,
        lease: WorkflowLeaseV1,
        execution_grant: String,
    ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>>;

    fn observe(
        &self,
        lease_id: Uuid,
        lease_generation: u32,
    ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>;

    fn cleanup(
        &self,
        lease: WorkflowLeaseV1,
    ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>>;
}

impl WorkflowWorkerLauncherClientV1 for WorkflowLauncherClientV1 {
    fn launch(
        &self,
        lease: WorkflowLeaseV1,
        execution_grant: String,
    ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
        Box::pin(WorkflowLauncherClientV1::launch(
            self,
            lease,
            execution_grant,
        ))
    }

    fn observe(
        &self,
        lease_id: Uuid,
        lease_generation: u32,
    ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>> {
        Box::pin(WorkflowLauncherClientV1::observe(
            self,
            lease_id,
            lease_generation,
        ))
    }

    fn cleanup(
        &self,
        lease: WorkflowLeaseV1,
    ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
        Box::pin(WorkflowLauncherClientV1::cleanup(self, lease))
    }
}

pub trait WorkflowDependencyFetcherV1: Send + Sync {
    fn fetch<'a>(
        &'a self,
        package: &'a CargoRegistryPackageV1,
    ) -> BoxFuture<'a, Result<Vec<u8>, DependencyFetchClientError>>;
}

impl WorkflowDependencyFetcherV1 for DependencyFetchClientV1 {
    fn fetch<'a>(
        &'a self,
        package: &'a CargoRegistryPackageV1,
    ) -> BoxFuture<'a, Result<Vec<u8>, DependencyFetchClientError>> {
        Box::pin(self.fetch_crate(package))
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowWorkerRuntimeConfigV1 {
    pub slots: usize,
    pub idle_poll_interval: Duration,
    pub operation_poll_interval: Duration,
    pub retry_interval: Duration,
    pub renewal_margin: Duration,
}

impl WorkflowWorkerRuntimeConfigV1 {
    pub fn production(slots: usize) -> Result<Self, WorkflowWorkerError> {
        let config = Self {
            slots,
            idle_poll_interval: Duration::from_millis(250),
            operation_poll_interval: Duration::from_millis(500),
            retry_interval: Duration::from_millis(250),
            renewal_margin: Duration::from_secs(5),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), WorkflowWorkerError> {
        if !(1..=MAX_WORKER_SLOTS).contains(&self.slots)
            || self.idle_poll_interval.is_zero()
            || self.operation_poll_interval.is_zero()
            || self.retry_interval.is_zero()
            || self.renewal_margin.is_zero()
            || self.renewal_margin > Duration::from_secs(30)
        {
            return Err(WorkflowWorkerError::InvalidRuntimeConfig);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct WorkflowWorkerRuntimeV1 {
    registration: WorkflowWorkerRegistrationV1,
    gateway: Arc<dyn WorkflowWorkerGatewayClientV1>,
    launcher: Arc<dyn WorkflowWorkerLauncherClientV1>,
    preparer: Arc<WorkflowHostPreparerV1>,
    dependency_fetcher: Option<Arc<dyn WorkflowDependencyFetcherV1>>,
    config: WorkflowWorkerRuntimeConfigV1,
}

impl WorkflowWorkerRuntimeV1 {
    pub fn new(
        registration: WorkflowWorkerRegistrationV1,
        gateway: Arc<dyn WorkflowWorkerGatewayClientV1>,
        launcher: Arc<dyn WorkflowWorkerLauncherClientV1>,
        preparer: Arc<WorkflowHostPreparerV1>,
        config: WorkflowWorkerRuntimeConfigV1,
    ) -> Result<Self, WorkflowWorkerError> {
        registration
            .validate_unprivileged()
            .map_err(|_| WorkflowWorkerError::InvalidRuntimeConfig)?;
        config.validate()?;
        Ok(Self {
            registration,
            gateway,
            launcher,
            preparer,
            dependency_fetcher: None,
            config,
        })
    }

    #[must_use]
    pub fn with_dependency_fetcher(
        mut self,
        fetcher: Arc<dyn WorkflowDependencyFetcherV1>,
    ) -> Self {
        self.dependency_fetcher = Some(fetcher);
        self
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<(), WorkflowWorkerError>
    where
        F: std::future::Future<Output = ()>,
    {
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let mut tasks: JoinSet<(
            WorkflowAssignmentIdentityV1,
            Result<(), WorkflowWorkerError>,
        )> = JoinSet::new();
        let mut active = BTreeSet::<WorkflowAssignmentIdentityV1>::new();
        let mut next_poll = Instant::now();
        tokio::pin!(shutdown);

        let runtime_result = loop {
            tokio::select! {
                () = &mut shutdown => break Ok(()),
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Ok((identity, Ok(()))) => {
                            active.remove(&identity);
                        }
                        Ok((identity, Err(worker_error))) => {
                            active.remove(&identity);
                            error!(
                                lease_id = %identity.lease_id,
                                lease_generation = identity.lease_generation,
                                reason_code = worker_error.reason_code(),
                                error = %worker_error,
                                "workflow assignment failed"
                            );
                        }
                        Err(join_error) => {
                            error!(error = %join_error, "workflow assignment task terminated unexpectedly");
                        }
                    }
                    next_poll = Instant::now();
                }
                () = tokio::time::sleep_until(next_poll), if tasks.len() < self.config.slots => {
                    match self.gateway.poll().await {
                        Ok(WorkflowWorkerAssignmentV1::Idle) => {
                            next_poll = Instant::now() + self.config.idle_poll_interval;
                        }
                        Ok(assignment) => {
                            let identity = assignment_identity(&assignment);
                            if !active.insert(identity) {
                                next_poll = Instant::now() + self.config.retry_interval;
                                continue;
                            }
                            let runtime = self.clone();
                            let task_shutdown = shutdown_receiver.clone();
                            tasks.spawn(async move {
                                let result = AssertUnwindSafe(
                                    runtime.execute_assignment(assignment, task_shutdown),
                                )
                                .catch_unwind()
                                .await
                                .unwrap_or(Err(WorkflowWorkerError::TaskPanicked));
                                (identity, result)
                            });
                            next_poll = Instant::now();
                        }
                        Err(client_error) if worker_client_error_retryable(&client_error) => {
                            warn!(error = %client_error, "workflow gateway poll failed");
                            next_poll = Instant::now() + self.config.retry_interval;
                        }
                        Err(client_error) => {
                            break Err(client_error.into());
                        }
                    }
                }
            }
        };

        let _ = shutdown_sender.send(true);
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((identity, Err(worker_error))) => error!(
                    lease_id = %identity.lease_id,
                    lease_generation = identity.lease_generation,
                    reason_code = worker_error.reason_code(),
                    error = %worker_error,
                    "workflow assignment stopped during worker shutdown"
                ),
                Err(join_error) => error!(
                    error = %join_error,
                    "workflow assignment task terminated during worker shutdown"
                ),
                Ok((_, Ok(()))) => {}
            }
        }
        runtime_result
    }

    async fn execute_assignment(
        &self,
        assignment: WorkflowWorkerAssignmentV1,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkflowWorkerError> {
        match assignment {
            WorkflowWorkerAssignmentV1::Lease {
                lease,
                execution_grant,
            } => {
                self.validate_assignment(&lease)?;
                if execution_grant.is_empty() {
                    return Err(WorkflowWorkerError::InvalidAssignment);
                }
                if lease.node_kind == WorkflowNodeKindV1::HostPrepare {
                    self.execute_host_preparation(*lease, shutdown).await
                } else if lease.node_kind == WorkflowNodeKindV1::Verification
                    && lease.adapter_id == WorkflowAdapterIdV1::WorkerBareBinCiV1
                {
                    self.execute_launcher_job(*lease, execution_grant, shutdown)
                        .await
                } else {
                    self.fail_without_runtime(*lease, "unsupported_worker_adapter")
                        .await
                }
            }
            WorkflowWorkerAssignmentV1::Cleanup { obligation } => {
                self.execute_cleanup(*obligation, shutdown).await
            }
            WorkflowWorkerAssignmentV1::Idle => Ok(()),
        }
    }

    fn validate_assignment(&self, lease: &WorkflowLeaseV1) -> Result<(), WorkflowWorkerError> {
        lease.validate()?;
        let now_ms = current_time_ms()?;
        if lease.worker_id != self.registration.worker_id
            || lease.host_id != self.registration.host_id
            || !self.registration.pools.contains(&lease.worker_pool)
            || lease.expires_at_ms <= now_ms
        {
            return Err(WorkflowWorkerError::InvalidAssignment);
        }
        Ok(())
    }

    fn spawn_host_preparation(
        &self,
        lease: WorkflowLeaseV1,
        prepared_at_ms: i64,
        cancel: watch::Receiver<bool>,
    ) -> Result<Option<HostPreparationTask>, WorkflowWorkerError> {
        let adapter = lease
            .host_preparation
            .as_ref()
            .ok_or(WorkflowWorkerError::UnsupportedHostPreparation)?
            .adapter_id;
        let preparer = Arc::clone(&self.preparer);
        Ok(match adapter {
            WorkflowHostPreparationAdapterV1::SourceTreeV1 => {
                Some(tokio::task::spawn_blocking(move || {
                    preparer.prepare_source_tree(&lease, prepared_at_ms)
                }))
            }
            WorkflowHostPreparationAdapterV1::CargoCratesIoV1 => {
                let fetcher = self.dependency_fetcher.as_ref().map(Arc::clone);
                fetcher.map(|fetcher| {
                    let runtime = tokio::runtime::Handle::current();
                    let mut fetch_cancel = cancel.clone();
                    tokio::task::spawn_blocking(move || {
                        preparer.prepare_cargo_crates_io_cancellable(
                            &lease,
                            prepared_at_ms,
                            |package| {
                                runtime.block_on(async {
                                    tokio::select! {
                                        result = fetcher.fetch(package) => {
                                            result.map_err(WorkflowDependencyFetchError::Client)
                                        }
                                        changed = fetch_cancel.changed() => {
                                            let _ = changed;
                                            Err(WorkflowDependencyFetchError::Cancelled)
                                        }
                                    }
                                })
                            },
                            || *cancel.borrow(),
                        )
                    })
                })
            }
        })
    }

    async fn execute_host_preparation(
        &self,
        lease: WorkflowLeaseV1,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkflowWorkerError> {
        let mut current = lease;
        let prepared_at_ms = current_time_ms()?;
        let (cancel_sender, cancel_receiver) = watch::channel(false);
        let mut task =
            match self.spawn_host_preparation(current.clone(), prepared_at_ms, cancel_receiver) {
                Ok(Some(task)) => task,
                Ok(None) => {
                    return self
                        .fail_without_runtime(current, "dependency_fetcher_unavailable")
                        .await;
                }
                Err(preparation_error) => {
                    return self
                        .fail_without_runtime(current, preparation_error.reason_code())
                        .await;
                }
            };
        let preparation = loop {
            tokio::select! {
                joined = &mut task => break joined?,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = cancel_sender.send(true);
                        let _ = task.await;
                        return Err(WorkflowWorkerError::WorkerStopping);
                    }
                }
                () = tokio::time::sleep(self.config.operation_poll_interval) => {
                    if self.lease_needs_renewal(&current)? {
                        match self.renew_lease(current).await {
                            Ok(renewed) => current = renewed.lease,
                            Err(renewal_error) => {
                                let _ = cancel_sender.send(true);
                                let _ = task.await;
                                return Err(renewal_error);
                            }
                        }
                    }
                }
            }
        };
        let preparation_result = match preparation {
            Ok(result) => result,
            Err(preparation_error) => {
                let reason_code = preparation_error.reason_code();
                warn!(
                    project_id = %current.project_id,
                    source_sha = %current.source_sha,
                    lease_id = %current.lease_id,
                    reason_code,
                    error = %preparation_error,
                    "exact host preparation failed"
                );
                return self.fail_without_runtime(current, reason_code).await;
            }
        };
        current = self.freshen_for_receipt(current).await?;
        let completed_at_ms = current_time_ms()?;
        if completed_at_ms >= current.expires_at_ms {
            return Err(WorkflowWorkerError::LeaseLost);
        }
        let receipt = WorkflowNodeReceiptV1::new(
            &current,
            WorkflowNodeOutcomeV1::Succeeded,
            Some(preparation_result.prepared_run_key.clone()),
            preparation_result.execution_receipt_digest(&current)?,
            host_preparation_cleanup_digest(&current)?,
            WorkflowCleanupResultV1::Complete,
            completed_at_ms,
        )?;
        self.submit_node_receipt(receipt, current.expires_at_ms)
            .await?;
        info!(
            project_id = %current.project_id,
            source_sha = %current.source_sha,
            lease_id = %current.lease_id,
            prepared_run_key = %preparation_result.prepared_run_key,
            "exact source and dependency input prepared in shared CAS"
        );
        Ok(())
    }

    async fn execute_launcher_job(
        &self,
        lease: WorkflowLeaseV1,
        execution_grant: String,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkflowWorkerError> {
        let prepared_run_key = required_prepared_run_key(&lease)?.clone();
        if let Err(preparation_error) = self.pin_prepared_run(&lease, &prepared_run_key).await {
            return self
                .finish_prepared_run_pin_failure(lease, prepared_run_key, preparation_error)
                .await;
        }

        let mut current = lease;
        let mut status = match self.launcher.launch(current.clone(), execution_grant).await {
            Ok(status) => status,
            Err(client_error) => {
                return self
                    .finish_launcher_failure(
                        current,
                        &prepared_run_key,
                        "launcher_start_failed",
                        Some(client_error),
                    )
                    .await;
            }
        };
        loop {
            if let Err(status_error) = validate_launch_status(&status, &current) {
                warn!(
                    lease_id = %current.lease_id,
                    reason_code = status_error.reason_code(),
                    error = %status_error,
                    "workflow launcher returned an invalid status"
                );
                return self
                    .finish_launcher_failure(
                        current,
                        &prepared_run_key,
                        "launcher_status_invalid",
                        None,
                    )
                    .await;
            }
            match status.state {
                WorkflowLaunchStateV1::Succeeded
                | WorkflowLaunchStateV1::Failed
                | WorkflowLaunchStateV1::Cleaned => {
                    return self
                        .finish_launcher_terminal(current, &prepared_run_key, status)
                        .await;
                }
                WorkflowLaunchStateV1::NeedsReconcile | WorkflowLaunchStateV1::CleanupPending => {
                    return self
                        .finish_launcher_failure(
                            current,
                            &prepared_run_key,
                            "launcher_reconciliation_required",
                            None,
                        )
                        .await;
                }
                WorkflowLaunchStateV1::Accepted | WorkflowLaunchStateV1::Running => {}
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return self.finish_launcher_failure(
                            current,
                            &prepared_run_key,
                            "worker_shutdown",
                            None,
                        ).await;
                    }
                }
                () = tokio::time::sleep(self.config.operation_poll_interval) => {}
            }
            status = match self.next_launcher_status(&mut current).await {
                Ok(status) => status,
                Err(progress_error) => {
                    let reason_code = match &progress_error {
                        WorkflowWorkerError::Gateway(_) => "lease_renewal_failed",
                        WorkflowWorkerError::LaunchStatusLost => "launcher_status_lost",
                        WorkflowWorkerError::Launcher(_) => "launcher_status_refresh_failed",
                        _ => "launcher_progress_invalid",
                    };
                    warn!(
                        lease_id = %current.lease_id,
                        reason_code,
                        error = %progress_error,
                        "workflow launcher progress could not be refreshed"
                    );
                    return self
                        .finish_launcher_failure(current, &prepared_run_key, reason_code, None)
                        .await;
                }
            };
        }
    }

    async fn finish_prepared_run_pin_failure(
        &self,
        lease: WorkflowLeaseV1,
        prepared_run_key: EvidenceDigest,
        preparation_error: WorkflowWorkerError,
    ) -> Result<(), WorkflowWorkerError> {
        warn!(
            lease_id = %lease.lease_id,
            prepared_run_key = %prepared_run_key,
            error = %preparation_error,
            "prepared run could not be pinned"
        );
        let _ = self
            .unpin_prepared_run(lease.lease_id, prepared_run_key)
            .await;
        self.fail_without_runtime(lease, "prepared_run_pin_failed")
            .await
    }

    async fn next_launcher_status(
        &self,
        current: &mut WorkflowLeaseV1,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowWorkerError> {
        if self.lease_needs_renewal(current)? {
            let renewed = self.renew_lease(current.clone()).await?;
            *current = renewed.lease;
            Ok(self
                .launcher
                .launch(current.clone(), renewed.execution_grant)
                .await?)
        } else {
            self.launcher
                .observe(current.lease_id, current.lease_generation)
                .await?
                .ok_or(WorkflowWorkerError::LaunchStatusLost)
        }
    }

    async fn finish_launcher_terminal(
        &self,
        mut lease: WorkflowLeaseV1,
        prepared_run_key: &EvidenceDigest,
        status: WorkflowLaunchStatusV1,
    ) -> Result<(), WorkflowWorkerError> {
        let terminal = status
            .terminal
            .ok_or(WorkflowWorkerError::LaunchStatusLost)?;
        let cleaned = match self.launcher.cleanup(lease.clone()).await {
            Ok(cleaned) => cleaned,
            Err(cleanup_error) => {
                return self
                    .finish_launcher_failure(
                        lease,
                        prepared_run_key,
                        "launcher_cleanup_failed",
                        Some(cleanup_error),
                    )
                    .await;
            }
        };
        validate_launch_status(&cleaned, &lease)?;
        let cleanup = cleaned
            .cleanup
            .ok_or(WorkflowWorkerError::CleanupStatusLost)?;
        if cleaned.state != WorkflowLaunchStateV1::Cleaned {
            return Err(WorkflowWorkerError::CleanupStatusLost);
        }
        self.unpin_prepared_run(lease.lease_id, prepared_run_key.clone())
            .await?;
        lease = self.freshen_for_receipt(lease).await?;
        let completed_at_ms = terminal.completed_at_ms.max(cleanup.completed_at_ms);
        if completed_at_ms >= lease.expires_at_ms {
            return Err(WorkflowWorkerError::LeaseLost);
        }
        let operation_state_reusable = cleanup
            .operation_state
            .as_ref()
            .map_or(lease.operation_state.is_none(), |release| release.reusable);
        let succeeded = terminal.succeeded && operation_state_reusable;
        let outcome = if succeeded {
            WorkflowNodeOutcomeV1::Succeeded
        } else {
            WorkflowNodeOutcomeV1::Failed
        };
        let execution_digest = if terminal.succeeded && !operation_state_reusable {
            worker_failure_digest(&lease, "operation_state_unusable")?
        } else {
            terminal.evidence_digest.clone()
        };
        let output_digest = if !succeeded {
            None
        } else if lease.adapter_id == WorkflowAdapterIdV1::WorkerOciReleaseBuildV1 {
            Some(
                terminal
                    .output_digest
                    .clone()
                    .ok_or(WorkflowWorkerError::InvalidLaunchStatus)?,
            )
        } else {
            if terminal.output_digest.is_some() {
                return Err(WorkflowWorkerError::InvalidLaunchStatus);
            }
            Some(terminal.evidence_digest.clone())
        };
        let receipt = WorkflowNodeReceiptV1::new(
            &lease,
            outcome,
            output_digest,
            execution_digest,
            cleanup.evidence_digest,
            WorkflowCleanupResultV1::Complete,
            completed_at_ms,
        )?;
        self.submit_node_receipt(receipt, lease.expires_at_ms)
            .await?;
        Ok(())
    }

    async fn finish_launcher_failure(
        &self,
        mut lease: WorkflowLeaseV1,
        prepared_run_key: &EvidenceDigest,
        reason_code: &'static str,
        launcher_error: Option<WorkflowLauncherClientError>,
    ) -> Result<(), WorkflowWorkerError> {
        if let Some(client_error) = launcher_error.as_ref() {
            warn!(reason_code, error = %client_error, "workflow launch failed before terminal evidence");
        }
        let cleanup = self.launcher.cleanup(lease.clone()).await;
        let (cleanup_result, cleanup_digest) = match cleanup {
            Ok(status) => {
                validate_launch_status(&status, &lease)?;
                let cleanup = status
                    .cleanup
                    .ok_or(WorkflowWorkerError::CleanupStatusLost)?;
                if status.state != WorkflowLaunchStateV1::Cleaned {
                    return Err(WorkflowWorkerError::CleanupStatusLost);
                }
                self.unpin_prepared_run(lease.lease_id, prepared_run_key.clone())
                    .await?;
                (
                    WorkflowCleanupResultV1::Complete,
                    Some(cleanup.evidence_digest),
                )
            }
            Err(cleanup_error) => {
                warn!(reason_code, error = %cleanup_error, "workflow launcher cleanup remains pending");
                (WorkflowCleanupResultV1::Pending, None)
            }
        };
        lease = self.freshen_for_receipt(lease).await?;
        let cleanup_digest =
            cleanup_digest.map_or_else(|| pending_cleanup_digest(&lease, reason_code), Ok)?;
        let completed_at_ms = current_time_ms()?;
        if completed_at_ms >= lease.expires_at_ms {
            return Err(WorkflowWorkerError::LeaseLost);
        }
        let receipt = WorkflowNodeReceiptV1::new(
            &lease,
            WorkflowNodeOutcomeV1::Failed,
            None,
            worker_failure_digest(&lease, reason_code)?,
            cleanup_digest,
            cleanup_result,
            completed_at_ms,
        )?;
        self.submit_node_receipt(receipt, lease.expires_at_ms)
            .await?;
        Ok(())
    }

    async fn fail_without_runtime(
        &self,
        mut lease: WorkflowLeaseV1,
        reason_code: &'static str,
    ) -> Result<(), WorkflowWorkerError> {
        lease = self.freshen_for_receipt(lease).await?;
        let completed_at_ms = current_time_ms()?;
        if completed_at_ms >= lease.expires_at_ms {
            return Err(WorkflowWorkerError::LeaseLost);
        }
        let receipt = WorkflowNodeReceiptV1::new(
            &lease,
            WorkflowNodeOutcomeV1::Failed,
            None,
            worker_failure_digest(&lease, reason_code)?,
            host_preparation_cleanup_digest(&lease)?,
            WorkflowCleanupResultV1::Complete,
            completed_at_ms,
        )?;
        self.submit_node_receipt(receipt, lease.expires_at_ms)
            .await?;
        Ok(())
    }

    async fn execute_cleanup(
        &self,
        obligation: WorkflowCleanupObligationV1,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkflowWorkerError> {
        self.validate_cleanup_obligation(&obligation)?;
        let lease = obligation.lease;
        let cleanup_digest = if lease.node_kind == WorkflowNodeKindV1::HostPrepare {
            host_preparation_cleanup_digest(&lease)?
        } else {
            let status = self.launcher.cleanup(lease.clone()).await?;
            validate_launch_status(&status, &lease)?;
            let cleanup = status
                .cleanup
                .ok_or(WorkflowWorkerError::CleanupStatusLost)?;
            if status.state != WorkflowLaunchStateV1::Cleaned {
                return Err(WorkflowWorkerError::CleanupStatusLost);
            }
            if let Ok(key) = required_prepared_run_key(&lease) {
                self.unpin_prepared_run(lease.lease_id, key.clone()).await?;
            }
            cleanup.evidence_digest
        };
        let receipt = WorkflowCleanupReceiptV1::new(
            &lease,
            obligation.terminal_receipt.as_ref(),
            cleanup_digest,
            current_time_ms()?,
        )?;
        self.submit_cleanup_receipt(receipt, shutdown).await?;
        Ok(())
    }

    fn validate_cleanup_obligation(
        &self,
        obligation: &WorkflowCleanupObligationV1,
    ) -> Result<(), WorkflowWorkerError> {
        obligation.lease.validate()?;
        if obligation.lease.worker_id != self.registration.worker_id
            || obligation.lease.host_id != self.registration.host_id
            || !self
                .registration
                .pools
                .contains(&obligation.lease.worker_pool)
        {
            return Err(WorkflowWorkerError::InvalidAssignment);
        }
        Ok(())
    }

    async fn renew_lease(
        &self,
        current: WorkflowLeaseV1,
    ) -> Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerError> {
        let renewed = self.gateway.renew_lease(current.clone()).await?;
        if !current.same_execution_as(&renewed.lease)?
            || renewed.lease.worker_id != self.registration.worker_id
            || renewed.lease.host_id != self.registration.host_id
            || renewed.lease.expires_at_ms < current.expires_at_ms
            || renewed.execution_grant.is_empty()
        {
            return Err(WorkflowWorkerError::InvalidAssignment);
        }
        Ok(renewed)
    }

    async fn freshen_for_receipt(
        &self,
        current: WorkflowLeaseV1,
    ) -> Result<WorkflowLeaseV1, WorkflowWorkerError> {
        if self.lease_needs_renewal(&current)? {
            Ok(self.renew_lease(current).await?.lease)
        } else {
            Ok(current)
        }
    }

    fn lease_needs_renewal(&self, lease: &WorkflowLeaseV1) -> Result<bool, WorkflowWorkerError> {
        let margin_ms = i64::try_from(self.config.renewal_margin.as_millis())
            .map_err(|_| WorkflowWorkerError::InvalidRuntimeConfig)?;
        Ok(lease.expires_at_ms.saturating_sub(current_time_ms()?) <= margin_ms)
    }

    async fn submit_node_receipt(
        &self,
        receipt: WorkflowNodeReceiptV1,
        expires_at_ms: i64,
    ) -> Result<(), WorkflowWorkerError> {
        loop {
            if current_time_ms()? >= expires_at_ms {
                return Err(WorkflowWorkerError::LeaseLost);
            }
            match self.gateway.complete_node(receipt.clone()).await {
                Ok(()) => return Ok(()),
                Err(client_error) if worker_client_error_retryable(&client_error) => {
                    warn!(error = %client_error, "workflow node receipt submission will retry");
                    tokio::time::sleep(self.config.retry_interval).await;
                }
                Err(client_error) => return Err(client_error.into()),
            }
        }
    }

    async fn submit_cleanup_receipt(
        &self,
        receipt: WorkflowCleanupReceiptV1,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), WorkflowWorkerError> {
        loop {
            match self.gateway.complete_cleanup(receipt.clone()).await {
                Ok(()) => return Ok(()),
                Err(client_error) if worker_client_error_retryable(&client_error) => {
                    warn!(error = %client_error, "workflow cleanup receipt submission will retry");
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_ok() && *shutdown.borrow() {
                                return Err(WorkflowWorkerError::WorkerStopping);
                            }
                        }
                        () = tokio::time::sleep(self.config.retry_interval) => {}
                    }
                }
                Err(client_error) => return Err(client_error.into()),
            }
        }
    }

    async fn unpin_prepared_run(
        &self,
        pin_id: Uuid,
        key: EvidenceDigest,
    ) -> Result<(), WorkflowWorkerError> {
        let store = self.preparer.store().clone();
        tokio::task::spawn_blocking(move || store.unpin_if_present(pin_id, &key)).await??;
        Ok(())
    }

    async fn pin_prepared_run(
        &self,
        lease: &WorkflowLeaseV1,
        key: &EvidenceDigest,
    ) -> Result<(), WorkflowWorkerError> {
        let pin_expires_at_ms = lease
            .leased_at_ms
            .checked_add(
                i64::try_from(lease.timeout_ms).map_err(|_| WorkflowWorkerError::InvalidLease)?,
            )
            .ok_or(WorkflowWorkerError::InvalidLease)?;
        let store = self.preparer.store().clone();
        let pin_key = key.clone();
        let pin_id = lease.lease_id;
        let pin_now_ms = current_time_ms()?;
        tokio::task::spawn_blocking(move || {
            store.open_pinned(
                crate::preparation::PreparationObjectKindV1::PreparedRun,
                &pin_key,
                pin_id,
                pin_expires_at_ms,
                pin_now_ms,
            )
        })
        .await??;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum WorkflowDependencyFetchError {
    #[error("dependency fetch client failed: {0}")]
    Client(DependencyFetchClientError),
    #[error("dependency fetch was cancelled after lease loss or worker shutdown")]
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WorkflowAssignmentIdentityV1 {
    lease_id: Uuid,
    lease_generation: u32,
}

fn assignment_identity(assignment: &WorkflowWorkerAssignmentV1) -> WorkflowAssignmentIdentityV1 {
    match assignment {
        WorkflowWorkerAssignmentV1::Lease { lease, .. } => WorkflowAssignmentIdentityV1 {
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
        },
        WorkflowWorkerAssignmentV1::Cleanup { obligation } => WorkflowAssignmentIdentityV1 {
            lease_id: obligation.lease.lease_id,
            lease_generation: obligation.lease.lease_generation,
        },
        WorkflowWorkerAssignmentV1::Idle => WorkflowAssignmentIdentityV1 {
            lease_id: Uuid::nil(),
            lease_generation: 0,
        },
    }
}

fn required_prepared_run_key(
    lease: &WorkflowLeaseV1,
) -> Result<&EvidenceDigest, WorkflowWorkerError> {
    let inputs = lease.required_input_artifacts()?;
    let [input] = inputs else {
        return Err(WorkflowWorkerError::InvalidLease);
    };
    if input.artifact_kind != WorkflowArtifactKindV1::PreparedRun {
        return Err(WorkflowWorkerError::InvalidLease);
    }
    Ok(&input.output_digest)
}

fn validate_launch_status(
    status: &WorkflowLaunchStatusV1,
    lease: &WorkflowLeaseV1,
) -> Result<(), WorkflowWorkerError> {
    if status.lease_id != lease.lease_id
        || status.lease_generation != lease.lease_generation
        || status.attempt_id != lease.attempt_id
        || status.project_id != lease.project_id
        || status.lease_digest != lease.lease_digest
    {
        return Err(WorkflowWorkerError::InvalidLaunchStatus);
    }
    Ok(())
}

#[derive(Serialize)]
struct WorkflowWorkerFailureEvidenceV1<'a> {
    purpose: &'static str,
    lease_digest: &'a EvidenceDigest,
    reason_code: &'static str,
}

fn worker_failure_digest(
    lease: &WorkflowLeaseV1,
    reason_code: &'static str,
) -> Result<EvidenceDigest, WorkflowWorkerError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &WorkflowWorkerFailureEvidenceV1 {
            purpose: WORKER_FAILURE_PURPOSE,
            lease_digest: &lease.lease_digest,
            reason_code,
        },
    )?))
}

fn pending_cleanup_digest(
    lease: &WorkflowLeaseV1,
    reason_code: &'static str,
) -> Result<EvidenceDigest, WorkflowWorkerError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &WorkflowWorkerFailureEvidenceV1 {
            purpose: WORKER_PENDING_CLEANUP_PURPOSE,
            lease_digest: &lease.lease_digest,
            reason_code,
        },
    )?))
}

fn worker_client_error_retryable(error: &WorkflowWorkerClientError) -> bool {
    !matches!(
        error,
        WorkflowWorkerClientError::InvalidConfig
            | WorkflowWorkerClientError::WrongResponse
            | WorkflowWorkerClientError::Rejected {
                retryable: false,
                ..
            }
    )
}

fn current_time_ms() -> Result<i64, WorkflowWorkerError> {
    unix_time_ms().map_err(|_| WorkflowWorkerError::ClockUnavailable)
}

fn validate_host_preparation_lease(lease: &WorkflowLeaseV1) -> Result<(), WorkflowWorkerError> {
    lease.validate()?;
    let inputs = lease.required_input_artifacts()?;
    let [input] = inputs else {
        return Err(WorkflowWorkerError::InvalidLease);
    };
    let source_identity = lease.required_source_identity()?;
    if lease.node_kind != WorkflowNodeKindV1::HostPrepare
        || lease.adapter_id != WorkflowAdapterIdV1::WorkerHostPrepareV1
        || input.artifact_kind != WorkflowArtifactKindV1::SourceSnapshot
        || input.output_digest != source_identity.attestation_digest
        || lease.host_preparation.is_none()
    {
        return Err(WorkflowWorkerError::InvalidLease);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceTarInventoryV1 {
    directories: Vec<PathBuf>,
    files: BTreeMap<PathBuf, SourceTarFileV1>,
    payload_bytes: u64,
    payload_inodes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceTarFileV1 {
    bytes: u64,
    executable: bool,
}

impl SourceTarInventoryV1 {
    fn inspect(
        archive_path: &Path,
        maximum_payload_bytes: u64,
        maximum_payload_inodes: u64,
    ) -> Result<Self, WorkflowWorkerError> {
        if maximum_payload_bytes == 0 || maximum_payload_inodes == 0 {
            return Err(WorkflowWorkerError::SourcePayloadTooLarge);
        }
        let mut archive = Archive::new(File::open(archive_path)?);
        let mut directories = BTreeSet::new();
        let mut files = BTreeMap::new();
        let mut payload_bytes = 0_u64;
        for entry in archive.entries()? {
            let entry = entry?;
            let entry_type = entry.header().entry_type();
            let path = decode_tar_path(
                entry.path_bytes().as_ref(),
                entry_type == EntryType::Directory,
            )?;
            if entry_type == EntryType::Directory {
                if entry.header().size()? != 0
                    || files.contains_key(&path)
                    || !directories.insert(path.clone())
                {
                    return Err(WorkflowWorkerError::InvalidSourceArchive);
                }
                insert_parent_directories(&path, &mut directories, &files)?;
            } else if entry_type.is_file() {
                let bytes = entry.header().size()?;
                let executable = entry.header().mode()? & 0o111 != 0;
                if directories.contains(&path)
                    || files
                        .insert(path.clone(), SourceTarFileV1 { bytes, executable })
                        .is_some()
                {
                    return Err(WorkflowWorkerError::InvalidSourceArchive);
                }
                insert_parent_directories(&path, &mut directories, &files)?;
                payload_bytes = payload_bytes
                    .checked_add(bytes)
                    .ok_or(WorkflowWorkerError::SourcePayloadTooLarge)?;
            } else {
                return Err(WorkflowWorkerError::UnsupportedSourceEntry);
            }
            let entry_count = directories
                .len()
                .checked_add(files.len())
                .ok_or(WorkflowWorkerError::SourcePayloadTooLarge)?;
            if payload_bytes > maximum_payload_bytes
                || u64::try_from(entry_count)
                    .map_err(|_| WorkflowWorkerError::SourcePayloadTooLarge)?
                    > maximum_payload_inodes
            {
                return Err(WorkflowWorkerError::SourcePayloadTooLarge);
            }
        }
        if files.is_empty() {
            return Err(WorkflowWorkerError::InvalidSourceArchive);
        }
        for file in files.keys() {
            if file
                .ancestors()
                .skip(1)
                .any(|parent| files.contains_key(parent))
            {
                return Err(WorkflowWorkerError::InvalidSourceArchive);
            }
        }
        let mut directories = directories.into_iter().collect::<Vec<_>>();
        directories.sort_by(|left, right| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then_with(|| {
                    left.as_os_str()
                        .as_encoded_bytes()
                        .cmp(right.as_os_str().as_encoded_bytes())
                })
        });
        let payload_inodes = u64::try_from(directories.len().saturating_add(files.len()))
            .map_err(|_| WorkflowWorkerError::SourcePayloadTooLarge)?;
        Ok(Self {
            directories,
            files,
            payload_bytes,
            payload_inodes,
        })
    }

    fn read_regular_file(
        &self,
        archive_path: &Path,
        relative_path: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, WorkflowWorkerError> {
        let expected = self
            .files
            .get(relative_path)
            .ok_or(WorkflowWorkerError::RequiredSourceFileMissing)?;
        if expected.bytes == 0
            || usize::try_from(expected.bytes)
                .ok()
                .is_none_or(|bytes| bytes > maximum_bytes)
        {
            return Err(WorkflowWorkerError::RequiredSourceFileInvalid);
        }
        let mut archive = Archive::new(File::open(archive_path)?);
        let mut seen = BTreeSet::new();
        let mut selected = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            let relative = decode_tar_path(
                entry.path_bytes().as_ref(),
                entry_type == EntryType::Directory,
            )?;
            if entry_type == EntryType::Directory {
                if !self.directories.contains(&relative) || entry.header().size()? != 0 {
                    return Err(WorkflowWorkerError::SourceArchiveChanged);
                }
                continue;
            }
            let expected_entry = self
                .files
                .get(&relative)
                .ok_or(WorkflowWorkerError::SourceArchiveChanged)?;
            if !entry_type.is_file()
                || entry.header().size()? != expected_entry.bytes
                || (entry.header().mode()? & 0o111 != 0) != expected_entry.executable
                || !seen.insert(relative.clone())
            {
                return Err(WorkflowWorkerError::SourceArchiveChanged);
            }
            if relative == relative_path {
                let capacity = usize::try_from(expected_entry.bytes)
                    .map_err(|_| WorkflowWorkerError::RequiredSourceFileInvalid)?;
                let mut bytes = Vec::with_capacity(capacity);
                entry
                    .by_ref()
                    .take(expected_entry.bytes.saturating_add(1))
                    .read_to_end(&mut bytes)?;
                if bytes.len() != capacity {
                    return Err(WorkflowWorkerError::SourceArchiveChanged);
                }
                selected = Some(bytes);
            }
        }
        if seen.len() != self.files.len() {
            return Err(WorkflowWorkerError::SourceArchiveChanged);
        }
        selected.ok_or(WorkflowWorkerError::RequiredSourceFileMissing)
    }

    fn extract(&self, archive_path: &Path, destination: &Path) -> Result<(), WorkflowWorkerError> {
        for relative in &self.directories {
            let path = destination.join(relative);
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path)?;
        }
        let mut archive = Archive::new(File::open(archive_path)?);
        let mut seen = BTreeSet::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            let relative = decode_tar_path(
                entry.path_bytes().as_ref(),
                entry_type == EntryType::Directory,
            )?;
            if entry_type == EntryType::Directory {
                if !self.directories.contains(&relative) {
                    return Err(WorkflowWorkerError::SourceArchiveChanged);
                }
                continue;
            }
            let expected = self
                .files
                .get(&relative)
                .ok_or(WorkflowWorkerError::SourceArchiveChanged)?;
            if !entry_type.is_file()
                || entry.header().size()? != expected.bytes
                || (entry.header().mode()? & 0o111 != 0) != expected.executable
                || !seen.insert(relative.clone())
            {
                return Err(WorkflowWorkerError::SourceArchiveChanged);
            }
            let path = destination.join(relative);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut output = options.open(path)?;
            let copied = io::copy(
                &mut entry.by_ref().take(expected.bytes.saturating_add(1)),
                &mut output,
            )?;
            if copied != expected.bytes {
                return Err(WorkflowWorkerError::SourceArchiveChanged);
            }
            output.flush()?;
            output.set_permissions(std::fs::Permissions::from_mode(if expected.executable {
                0o700
            } else {
                0o600
            }))?;
            output.sync_all()?;
        }
        if seen.len() != self.files.len() {
            return Err(WorkflowWorkerError::SourceArchiveChanged);
        }
        Ok(())
    }
}

fn insert_parent_directories(
    path: &Path,
    directories: &mut BTreeSet<PathBuf>,
    files: &BTreeMap<PathBuf, SourceTarFileV1>,
) -> Result<(), WorkflowWorkerError> {
    let mut parent = path.parent();
    while let Some(value) = parent {
        if value.as_os_str().is_empty() {
            break;
        }
        if files.contains_key(value) {
            return Err(WorkflowWorkerError::InvalidSourceArchive);
        }
        directories.insert(value.to_path_buf());
        parent = value.parent();
    }
    Ok(())
}

fn decode_tar_path(bytes: &[u8], directory_entry: bool) -> Result<PathBuf, WorkflowWorkerError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_PATH_BYTES || bytes.contains(&0) {
        return Err(WorkflowWorkerError::InvalidSourcePath);
    }
    let normalized = if directory_entry {
        bytes.strip_suffix(b"/").unwrap_or(bytes)
    } else {
        if bytes.ends_with(b"/") {
            return Err(WorkflowWorkerError::InvalidSourcePath);
        }
        bytes
    };
    if normalized.is_empty() || normalized.ends_with(b"/") {
        return Err(WorkflowWorkerError::InvalidSourcePath);
    }
    let path = PathBuf::from(OsString::from_vec(normalized.to_vec()));
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.components().collect::<PathBuf>() != path
    {
        return Err(WorkflowWorkerError::InvalidSourcePath);
    }
    Ok(path)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowWorkerError {
    #[error("workflow worker runtime configuration is invalid")]
    InvalidRuntimeConfig,
    #[error("workflow assignment does not match this worker")]
    InvalidAssignment,
    #[error("workflow lease is invalid for the generic worker")]
    InvalidLease,
    #[error("workflow host-preparation adapter is not installed")]
    UnsupportedHostPreparation,
    #[error("source archive path is unsafe")]
    InvalidSourcePath,
    #[error("source archive structure is invalid")]
    InvalidSourceArchive,
    #[error("source archive contains a link or unsupported entry type")]
    UnsupportedSourceEntry,
    #[error("source archive exceeds the lease output or inode boundary")]
    SourcePayloadTooLarge,
    #[error("source archive changed between validation and extraction")]
    SourceArchiveChanged,
    #[error("required source file is missing")]
    RequiredSourceFileMissing,
    #[error("required source file is invalid")]
    RequiredSourceFileInvalid,
    #[error("Cargo dependency preparation failed: {0}")]
    CargoPrefetch(#[from] CargoPrefetchError),
    #[error("workflow launch status does not match the active lease")]
    InvalidLaunchStatus,
    #[error("workflow launch status disappeared before terminal evidence")]
    LaunchStatusLost,
    #[error("workflow cleanup status is incomplete")]
    CleanupStatusLost,
    #[error("workflow lease expired before its receipt was accepted")]
    LeaseLost,
    #[error("workflow worker is stopping with durable cleanup debt retained")]
    WorkerStopping,
    #[error("workflow worker clock is unavailable")]
    ClockUnavailable,
    #[error("workflow contract failed: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("preparation store failed: {0}")]
    Preparation(#[from] PreparationStoreError),
    #[error("workflow gateway failed: {0}")]
    Gateway(#[from] WorkflowWorkerClientError),
    #[error("workflow launcher failed: {0}")]
    Launcher(#[from] WorkflowLauncherClientError),
    #[error("workflow blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("workflow assignment task panicked")]
    TaskPanicked,
    #[error("worker evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("worker filesystem operation failed: {0}")]
    Io(#[from] io::Error),
}

impl WorkflowWorkerError {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRuntimeConfig => "invalid_runtime_config",
            Self::InvalidAssignment => "invalid_assignment",
            Self::InvalidLease | Self::Workflow(_) => "invalid_lease",
            Self::UnsupportedHostPreparation => "unsupported_host_preparation",
            Self::InvalidSourcePath => "invalid_source_path",
            Self::InvalidSourceArchive => "invalid_source_archive",
            Self::UnsupportedSourceEntry => "unsupported_source_entry",
            Self::SourcePayloadTooLarge => "source_payload_too_large",
            Self::SourceArchiveChanged => "source_archive_changed",
            Self::RequiredSourceFileMissing => "required_source_file_missing",
            Self::RequiredSourceFileInvalid => "required_source_file_invalid",
            Self::CargoPrefetch(_) => "cargo_dependency_preparation_failed",
            Self::InvalidLaunchStatus => "invalid_launch_status",
            Self::LaunchStatusLost => "launch_status_lost",
            Self::CleanupStatusLost => "cleanup_status_lost",
            Self::LeaseLost => "lease_lost",
            Self::WorkerStopping => "worker_stopping",
            Self::ClockUnavailable => "clock_unavailable",
            Self::Preparation(_) => "preparation_store_failed",
            Self::Gateway(_) => "workflow_gateway_failed",
            Self::Launcher(_) => "workflow_launcher_failed",
            Self::Join(_) => "worker_task_failed",
            Self::TaskPanicked => "worker_task_panicked",
            Self::Json(_) => "worker_evidence_failed",
            Self::Io(_) => "worker_filesystem_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        io::{Cursor, Write},
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use flate2::{Compression, write::GzEncoder};
    use tempfile::{TempDir, tempdir};
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        build_source::{SourceArchiveInputV1, SourceArchivePublisherV1},
        domain::{GitCommitId, InstalledPolicyIdentity, ProjectManifestV2, WorkflowLeaseInputV1},
        operation_state::{WorkflowOperationStateDispositionV1, WorkflowOperationStateReleaseV1},
        preparation::{PreparationObjectKindV1, open_test_preparation_store},
        scheduler::WorkflowCleanupReasonV1,
        worker_socket::WorkflowWorkerRejectionCodeV1,
        workflow_launcher::{
            WorkflowLaunchCleanupV1, WorkflowLaunchTerminalKindV1, WorkflowLaunchTerminalV1,
        },
    };

    struct PreparationFixture {
        directory: TempDir,
        preparer: WorkflowHostPreparerV1,
        lease: WorkflowLeaseV1,
        cargo_archive: Option<Vec<u8>>,
    }

    fn preparation_fixture(leased_at_ms: i64, expires_at_ms: i64) -> PreparationFixture {
        preparation_fixture_for_adapter(
            leased_at_ms,
            expires_at_ms,
            WorkflowHostPreparationAdapterV1::SourceTreeV1,
        )
    }

    fn manifest_for_adapter(adapter: WorkflowHostPreparationAdapterV1) -> ProjectManifestV2 {
        let mut manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("decode project manifest");
        let preparation_profile_id = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .expect("host preparation node")
            .profile_id
            .clone();
        let policy = manifest
            .host_preparation
            .as_mut()
            .expect("host preparation policy");
        policy.adapter_id = adapter;
        let network_class = policy.required_network_class();
        manifest
            .workflow
            .execution_profiles
            .iter_mut()
            .find(|profile| profile.profile_id == preparation_profile_id)
            .expect("host preparation profile")
            .network_class = network_class;
        manifest.validate().expect("adapted project manifest");
        manifest
    }

    fn preparation_fixture_for_adapter(
        leased_at_ms: i64,
        expires_at_ms: i64,
        adapter: WorkflowHostPreparationAdapterV1,
    ) -> PreparationFixture {
        let directory = tempdir().expect("temp directory");
        let store_root = directory.path().join("preparation");
        fs::create_dir(&store_root).expect("create preparation root");
        fs::set_permissions(&store_root, fs::Permissions::from_mode(0o700))
            .expect("protect preparation root");
        let store_metadata = fs::metadata(&store_root).expect("preparation root metadata");
        let store =
            open_test_preparation_store(&store_root, store_metadata.uid(), 2 * 1024 * 1024 * 1024)
                .expect("open test preparation store");

        let source_root = directory.path().join("source-exports");
        fs::create_dir(&source_root).expect("create source export root");
        fs::set_permissions(&source_root, fs::Permissions::from_mode(0o2750))
            .expect("protect source export root");
        let source_metadata = fs::metadata(&source_root).expect("source export metadata");
        let publisher = SourceArchivePublisherV1::open(
            &source_root,
            source_metadata.uid(),
            source_metadata.gid(),
        )
        .expect("open source publisher");
        let manifest = manifest_for_adapter(adapter);
        let workflow_policy_digest = manifest.workflow_policy_digest().expect("workflow digest");
        let source_sha = GitCommitId::from_str(&"a".repeat(40)).expect("source SHA");
        let source_attestation_digest = EvidenceDigest::sha256("source attestation");
        let cargo_archive = (adapter == WorkflowHostPreparationAdapterV1::CargoCratesIoV1)
            .then(test_cargo_crate_archive);
        publisher
            .publish(
                SourceArchiveInputV1 {
                    project_id: manifest.project_id.clone(),
                    head: source_sha.clone(),
                    sequence: 7,
                    source_attestation_digest: source_attestation_digest.clone(),
                    installed_policy: InstalledPolicyIdentity {
                        digest: workflow_policy_digest.clone(),
                        version: 1,
                    },
                    repository_identity: EvidenceDigest::sha256("repository identity"),
                    exported_at_ms: 100,
                },
                |output| write_source_tar(output, cargo_archive.as_deref()),
            )
            .expect("publish exact source archive");
        let source_reader =
            SourceArchiveReaderV1::open(&source_root, source_metadata.uid(), source_metadata.gid())
                .expect("open source reader");
        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .expect("host preparation node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("host preparation profile");
        let lease = WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            manifest.project_id,
            source_sha,
            7,
            source_attestation_digest.clone(),
            workflow_policy_digest,
            EvidenceDigest::sha256("scheduler preparation key"),
            node,
            profile,
            manifest.host_preparation,
            vec![WorkflowLeaseInputV1 {
                node_id: "source".parse().expect("source node ID"),
                artifact_kind: WorkflowArtifactKindV1::SourceSnapshot,
                output_digest: source_attestation_digest,
            }],
            EvidenceDigest::sha256("expected input"),
            "shared-vps-worker".to_owned(),
            "production-vps".to_owned(),
            leased_at_ms,
            expires_at_ms,
        )
        .expect("host preparation lease");
        PreparationFixture {
            directory,
            preparer: WorkflowHostPreparerV1::new(store, source_reader),
            lease,
            cargo_archive,
        }
    }

    fn write_source_tar(output: &mut File, cargo_archive: Option<&[u8]>) -> Result<(), io::Error> {
        let mut archive = tar::Builder::new(output);
        append_tar_directory(&mut archive, "bin/", 0o755)?;
        append_tar_file(&mut archive, "bin/ci", b"#!/bin/sh\nexit 0\n", 0o755)?;
        let cargo_lock = cargo_archive.map_or_else(
            || b"version = 4\n".to_vec(),
            |bytes| {
                format!(
                    "version = 4\n[[package]]\nname = \"demo-crate\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
                    EvidenceDigest::sha256(bytes)
                )
                .into_bytes()
            },
        );
        append_tar_file(&mut archive, "Cargo.lock", &cargo_lock, 0o644)?;
        append_tar_file(
            &mut archive,
            PREPARED_RUN_COMPOSITION_FILE,
            b"repository-owned bytes\n",
            0o644,
        )?;
        archive.finish()
    }

    fn test_cargo_crate_archive() -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        append_tar_directory(&mut archive, "demo-crate-1.2.3/", 0o755).expect("append crate root");
        append_tar_file(
            &mut archive,
            "demo-crate-1.2.3/Cargo.toml",
            b"[package]\nname = \"demo-crate\"\nversion = \"1.2.3\"\n",
            0o644,
        )
        .expect("append crate manifest");
        append_tar_file(
            &mut archive,
            "demo-crate-1.2.3/src/lib.rs",
            b"pub fn exact() {}\n",
            0o644,
        )
        .expect("append crate source");
        archive
            .into_inner()
            .expect("finish crate tar")
            .finish()
            .expect("finish crate gzip")
    }

    fn append_tar_directory<W: Write>(
        archive: &mut tar::Builder<W>,
        path: &str,
        mode: u32,
    ) -> Result<(), io::Error> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_mode(mode);
        header.set_size(0);
        header.set_cksum();
        archive.append_data(&mut header, path, io::empty())
    }

    fn append_tar_file<W: Write>(
        archive: &mut tar::Builder<W>,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), io::Error> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(mode);
        header.set_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        header.set_cksum();
        archive.append_data(&mut header, path, Cursor::new(bytes))
    }

    struct FakeGateway {
        assignments: Mutex<VecDeque<WorkflowWorkerAssignmentV1>>,
        node_receipts: Mutex<Vec<WorkflowNodeReceiptV1>>,
        cleanup_receipts: Mutex<Vec<WorkflowCleanupReceiptV1>>,
        renewal_count: AtomicUsize,
        completed: Notify,
    }

    impl FakeGateway {
        fn with_assignment(assignment: WorkflowWorkerAssignmentV1) -> Self {
            Self {
                assignments: Mutex::new(VecDeque::from([assignment])),
                node_receipts: Mutex::new(Vec::new()),
                cleanup_receipts: Mutex::new(Vec::new()),
                renewal_count: AtomicUsize::new(0),
                completed: Notify::new(),
            }
        }
    }

    impl WorkflowWorkerGatewayClientV1 for FakeGateway {
        fn poll(
            &self,
        ) -> BoxFuture<'_, Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError>> {
            Box::pin(async move {
                Ok(self
                    .assignments
                    .lock()
                    .expect("assignment lock")
                    .pop_front()
                    .unwrap_or(WorkflowWorkerAssignmentV1::Idle))
            })
        }

        fn renew_lease(
            &self,
            lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError>> {
            Box::pin(async move {
                self.renewal_count.fetch_add(1, Ordering::SeqCst);
                let renewed = lease
                    .renewed(lease.expires_at_ms.saturating_add(5_000))
                    .expect("renew fake lease");
                Ok(WorkflowWorkerLeaseGrantV1 {
                    lease: renewed,
                    execution_grant: "renewed-grant".to_owned(),
                })
            })
        }

        fn complete_node(
            &self,
            receipt: WorkflowNodeReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async move {
                self.node_receipts
                    .lock()
                    .expect("node receipt lock")
                    .push(receipt);
                self.completed.notify_one();
                Ok(())
            })
        }

        fn complete_cleanup(
            &self,
            receipt: WorkflowCleanupReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async move {
                self.cleanup_receipts
                    .lock()
                    .expect("cleanup receipt lock")
                    .push(receipt);
                self.completed.notify_one();
                Ok(())
            })
        }
    }

    struct NonRetryableGateway;

    impl WorkflowWorkerGatewayClientV1 for NonRetryableGateway {
        fn poll(
            &self,
        ) -> BoxFuture<'_, Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError>> {
            Box::pin(async {
                Err(WorkflowWorkerClientError::Rejected {
                    code: WorkflowWorkerRejectionCodeV1::WorkerBindingMismatch,
                    retryable: false,
                })
            })
        }

        fn renew_lease(
            &self,
            _lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError>> {
            Box::pin(async { panic!("a rejected registration cannot renew a lease") })
        }

        fn complete_node(
            &self,
            _receipt: WorkflowNodeReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async { panic!("a rejected registration cannot complete a node") })
        }

        fn complete_cleanup(
            &self,
            _receipt: WorkflowCleanupReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async { panic!("a rejected registration cannot complete cleanup") })
        }
    }

    struct RenewalFailGateway;

    impl WorkflowWorkerGatewayClientV1 for RenewalFailGateway {
        fn poll(
            &self,
        ) -> BoxFuture<'_, Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError>> {
            Box::pin(async { panic!("direct terminal test does not poll") })
        }

        fn renew_lease(
            &self,
            _lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError>> {
            Box::pin(async { Err(WorkflowWorkerClientError::DeadlineExceeded) })
        }

        fn complete_node(
            &self,
            _receipt: WorkflowNodeReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async { panic!("failed renewal cannot submit a node receipt") })
        }

        fn complete_cleanup(
            &self,
            _receipt: WorkflowCleanupReceiptV1,
        ) -> BoxFuture<'_, Result<(), WorkflowWorkerClientError>> {
            Box::pin(async { panic!("direct terminal test does not complete cleanup") })
        }
    }

    struct BlockingDependencyFetcher {
        started: Arc<Notify>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    struct FetchDropSignal(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for FetchDropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl WorkflowDependencyFetcherV1 for BlockingDependencyFetcher {
        fn fetch<'a>(
            &'a self,
            _package: &'a CargoRegistryPackageV1,
        ) -> BoxFuture<'a, Result<Vec<u8>, DependencyFetchClientError>> {
            let started = Arc::clone(&self.started);
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                let _drop_signal = FetchDropSignal(dropped);
                started.notify_one();
                std::future::pending::<Result<Vec<u8>, DependencyFetchClientError>>().await
            })
        }
    }

    struct PanicLauncher;

    impl WorkflowWorkerLauncherClientV1 for PanicLauncher {
        fn launch(
            &self,
            _lease: WorkflowLeaseV1,
            _execution_grant: String,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async { panic!("host preparation must not reach the root launcher") })
        }

        fn observe(
            &self,
            _lease_id: Uuid,
            _lease_generation: u32,
        ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>
        {
            Box::pin(async { panic!("host preparation must not observe the root launcher") })
        }

        fn cleanup(
            &self,
            _lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async { panic!("host preparation must not clean the root launcher") })
        }
    }

    struct SuccessfulLauncher {
        cleanup_calls: AtomicUsize,
    }

    impl SuccessfulLauncher {
        const fn new() -> Self {
            Self {
                cleanup_calls: AtomicUsize::new(0),
            }
        }
    }

    impl WorkflowWorkerLauncherClientV1 for SuccessfulLauncher {
        fn launch(
            &self,
            lease: WorkflowLeaseV1,
            _execution_grant: String,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(
                async move { Ok(test_launch_status(&lease, WorkflowLaunchStateV1::Succeeded)) },
            )
        }

        fn observe(
            &self,
            _lease_id: Uuid,
            _lease_generation: u32,
        ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>
        {
            Box::pin(async { panic!("immediate terminal launch must not require observation") })
        }

        fn cleanup(
            &self,
            lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(test_launch_status(&lease, WorkflowLaunchStateV1::Cleaned)) })
        }
    }

    struct UnusableOperationStateLauncher;

    impl WorkflowWorkerLauncherClientV1 for UnusableOperationStateLauncher {
        fn launch(
            &self,
            lease: WorkflowLeaseV1,
            _execution_grant: String,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(
                async move { Ok(test_launch_status(&lease, WorkflowLaunchStateV1::Succeeded)) },
            )
        }

        fn observe(
            &self,
            _lease_id: Uuid,
            _lease_generation: u32,
        ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>
        {
            Box::pin(async { panic!("immediate terminal launch must not require observation") })
        }

        fn cleanup(
            &self,
            lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async move {
                Ok(test_launch_status_with_state_reuse(
                    &lease,
                    WorkflowLaunchStateV1::Cleaned,
                    false,
                ))
            })
        }
    }

    struct RunningLauncher {
        cleanup_calls: AtomicUsize,
        launched: Notify,
    }

    impl RunningLauncher {
        const fn new() -> Self {
            Self {
                cleanup_calls: AtomicUsize::new(0),
                launched: Notify::const_new(),
            }
        }
    }

    impl WorkflowWorkerLauncherClientV1 for RunningLauncher {
        fn launch(
            &self,
            lease: WorkflowLeaseV1,
            _execution_grant: String,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async move {
                self.launched.notify_one();
                Ok(test_launch_status(&lease, WorkflowLaunchStateV1::Running))
            })
        }

        fn observe(
            &self,
            _lease_id: Uuid,
            _lease_generation: u32,
        ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>
        {
            Box::pin(async { panic!("shutdown must interrupt before another observation") })
        }

        fn cleanup(
            &self,
            lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(test_launch_status(&lease, WorkflowLaunchStateV1::Cleaned)) })
        }
    }

    struct StartAndCleanupFailLauncher;

    impl WorkflowWorkerLauncherClientV1 for StartAndCleanupFailLauncher {
        fn launch(
            &self,
            _lease: WorkflowLeaseV1,
            _execution_grant: String,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async { Err(WorkflowLauncherClientError::DeadlineExceeded) })
        }

        fn observe(
            &self,
            _lease_id: Uuid,
            _lease_generation: u32,
        ) -> BoxFuture<'_, Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError>>
        {
            Box::pin(async { panic!("a rejected launch cannot be observed") })
        }

        fn cleanup(
            &self,
            _lease: WorkflowLeaseV1,
        ) -> BoxFuture<'_, Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError>> {
            Box::pin(async { Err(WorkflowLauncherClientError::DeadlineExceeded) })
        }
    }

    fn test_launch_status(
        lease: &WorkflowLeaseV1,
        state: WorkflowLaunchStateV1,
    ) -> WorkflowLaunchStatusV1 {
        test_launch_status_with_state_reuse(lease, state, true)
    }

    fn test_launch_status_with_state_reuse(
        lease: &WorkflowLeaseV1,
        state: WorkflowLaunchStateV1,
        operation_state_reusable: bool,
    ) -> WorkflowLaunchStatusV1 {
        let completed_at_ms = current_time_ms().expect("test time");
        let terminal = matches!(
            state,
            WorkflowLaunchStateV1::Succeeded | WorkflowLaunchStateV1::Cleaned
        )
        .then(|| WorkflowLaunchTerminalV1 {
            kind: WorkflowLaunchTerminalKindV1::ProcessExit,
            succeeded: true,
            exit_code: Some(0),
            signal: None,
            failure_digest: None,
            output_digest: None,
            completed_at_ms,
            evidence_digest: EvidenceDigest::sha256("test terminal evidence"),
        });
        let cleanup = (state == WorkflowLaunchStateV1::Cleaned).then(|| {
            let operation_state = lease.operation_state.as_ref().map(|_| {
                let disposition = if operation_state_reusable {
                    WorkflowOperationStateDispositionV1::RemovedAfterSuccess
                } else {
                    WorkflowOperationStateDispositionV1::RemovedAfterLimit
                };
                WorkflowOperationStateReleaseV1::from_manager(
                    lease,
                    disposition,
                    operation_state_reusable,
                    0,
                    0,
                    completed_at_ms,
                    Some(EvidenceDigest::sha256("test operation release")),
                )
                .expect("test operation release")
            });
            WorkflowLaunchCleanupV1 {
                unit_was_loaded: true,
                operation_state,
                completed_at_ms,
                evidence_digest: EvidenceDigest::sha256("test cleanup evidence"),
            }
        });
        WorkflowLaunchStatusV1 {
            lease_digest: lease.lease_digest.clone(),
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            unit_name: format!("test-{}", lease.lease_id),
            state,
            terminal,
            cleanup,
            record_digest: EvidenceDigest::sha256("test launch record"),
        }
    }

    fn test_runtime_config() -> WorkflowWorkerRuntimeConfigV1 {
        WorkflowWorkerRuntimeConfigV1 {
            slots: 2,
            idle_poll_interval: Duration::from_millis(5),
            operation_poll_interval: Duration::from_millis(5),
            retry_interval: Duration::from_millis(5),
            renewal_margin: Duration::from_millis(100),
        }
    }

    fn registration(lease: &WorkflowLeaseV1) -> WorkflowWorkerRegistrationV1 {
        WorkflowWorkerRegistrationV1 {
            worker_id: lease.worker_id.clone(),
            host_id: lease.host_id.clone(),
            pools: BTreeSet::from([
                crate::domain::WorkflowWorkerPoolV1::VpsRequired,
                crate::domain::WorkflowWorkerPoolV1::BuildCompute,
            ]),
        }
    }

    fn prepare_verification_lease(
        fixture: &PreparationFixture,
        leased_at_ms: i64,
        expires_at_ms: i64,
    ) -> (WorkflowLeaseV1, WorkflowHostPreparationResultV1) {
        let prepared = fixture
            .preparer
            .prepare_source_tree(&fixture.lease, leased_at_ms)
            .expect("prepare source before verification");
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("decode project manifest");
        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::Verification)
            .expect("verification node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("verification profile");
        let source_identity = fixture
            .lease
            .required_source_identity()
            .expect("source identity")
            .clone();
        let lease = WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            fixture.lease.request_id,
            fixture.lease.attempt_id,
            fixture.lease.project_id.clone(),
            fixture.lease.source_sha.clone(),
            source_identity.sequence,
            source_identity.attestation_digest,
            fixture.lease.workflow_policy_digest.clone(),
            fixture.lease.preparation_key.clone(),
            node,
            profile,
            None,
            vec![WorkflowLeaseInputV1 {
                node_id: "prepare".parse().expect("prepare node ID"),
                artifact_kind: WorkflowArtifactKindV1::PreparedRun,
                output_digest: prepared.prepared_run_key.clone(),
            }],
            EvidenceDigest::sha256("verification input"),
            fixture.lease.worker_id.clone(),
            fixture.lease.host_id.clone(),
            leased_at_ms,
            expires_at_ms,
        )
        .expect("verification lease");
        (lease, prepared)
    }

    #[test]
    fn source_tree_preparation_is_exact_sealed_and_replayable() {
        let fixture = preparation_fixture(100, 15_100);
        let first = fixture
            .preparer
            .prepare_source_tree(&fixture.lease, 200)
            .expect("prepare exact source tree");
        let replayed = fixture
            .preparer
            .prepare_source_tree(&fixture.lease, 201)
            .expect("replay exact source tree");
        assert_eq!(replayed, first);
        let prepared = fixture
            .preparer
            .store()
            .open_pinned(
                PreparationObjectKindV1::PreparedRun,
                &first.prepared_run_key,
                Uuid::new_v4(),
                1_000,
                300,
            )
            .expect("open prepared run");
        let composition = prepared
            .prepared_run_composition()
            .expect("decode sealed prepared-run composition");
        assert_eq!(composition.prepared_run_key, first.prepared_run_key);
        assert_eq!(composition.source_snapshot_key, first.source_snapshot_key);
        assert_eq!(
            composition.dependency_snapshot_key,
            first.dependency_snapshot_key
        );
        assert_eq!(
            composition.workflow_policy_digest,
            fixture.lease.workflow_policy_digest
        );
        let prepared_source = prepared.payload_path().join(PREPARED_RUN_SOURCE_DIRECTORY);
        assert_eq!(
            fs::read(prepared_source.join("Cargo.lock")).expect("read Cargo.lock"),
            b"version = 4\n"
        );
        assert_eq!(
            fs::metadata(prepared_source.join("Cargo.lock"))
                .expect("Cargo.lock metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(
            fs::metadata(prepared_source.join("bin/ci"))
                .expect("bin/ci metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            fs::metadata(prepared.payload_path().join(PREPARED_RUN_COMPOSITION_FILE))
                .expect("prepared composition metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(
            fs::read(prepared_source.join(PREPARED_RUN_COMPOSITION_FILE))
                .expect("read repository-owned file with the reserved basename"),
            b"repository-owned bytes\n"
        );
        assert_ne!(
            first
                .execution_receipt_digest(&fixture.lease)
                .expect("execution evidence"),
            host_preparation_cleanup_digest(&fixture.lease).expect("cleanup evidence")
        );
    }

    #[test]
    fn cargo_preparation_fetches_once_and_publishes_one_sealed_vendor_snapshot() {
        let fixture = preparation_fixture_for_adapter(
            100,
            15_100,
            WorkflowHostPreparationAdapterV1::CargoCratesIoV1,
        );
        let archive = fixture
            .cargo_archive
            .clone()
            .expect("Cargo fixture archive");
        let fetches = AtomicUsize::new(0);
        let first = fixture
            .preparer
            .prepare_cargo_crates_io(&fixture.lease, 200, |package| {
                fetches.fetch_add(1, Ordering::SeqCst);
                assert_eq!(package.name, "demo-crate");
                assert_eq!(package.version, "1.2.3");
                Ok::<_, io::Error>(archive.clone())
            })
            .expect("prepare Cargo dependencies");
        let replayed = fixture
            .preparer
            .prepare_cargo_crates_io(&fixture.lease, 201, |_| {
                Err::<Vec<u8>, _>(io::Error::other(
                    "sealed dependency snapshot must bypass the network fetcher",
                ))
            })
            .expect("replay Cargo dependencies");
        assert_eq!(first, replayed);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        let dependency = fixture
            .preparer
            .store()
            .open_pinned(
                PreparationObjectKindV1::DependencySnapshot,
                &first.dependency_snapshot_key,
                Uuid::new_v4(),
                1_000,
                300,
            )
            .expect("open dependency snapshot");
        let payload = dependency.payload_path();
        assert!(
            payload
                .join(crate::cargo_prefetch::CARGO_DEPENDENCY_MANIFEST_FILE)
                .is_file()
        );
        assert_eq!(
            fs::read(payload.join("vendor/demo-crate-1.2.3/src/lib.rs"))
                .expect("vendored crate source"),
            b"pub fn exact() {}\n"
        );
        assert_eq!(
            fs::metadata(payload.join("vendor/demo-crate-1.2.3/src/lib.rs"))
                .expect("vendored crate metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
    }

    #[test]
    fn matching_host_preparations_join_one_sealed_publication() {
        let fixture = preparation_fixture(100, 15_100);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let preparer = fixture.preparer.clone();
            let lease = fixture.lease.clone();
            let start = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                start.wait();
                preparer
                    .prepare_source_tree(&lease, 200)
                    .expect("join matching preparation")
            }));
        }
        barrier.wait();
        let first = threads.remove(0).join().expect("first preparation thread");
        let second = threads.remove(0).join().expect("second preparation thread");
        assert_eq!(first, second);

        let preparation_root = fixture.directory.path().join("preparation");
        assert_eq!(
            fs::read_dir(preparation_root.join("objects/prepared-run"))
                .expect("read prepared-run objects")
                .count(),
            1
        );
        assert!(
            fs::read_dir(preparation_root.join("staging"))
                .expect("read staging")
                .next()
                .is_none(),
            "single-flight leaves no duplicate staging tree"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn generic_runtime_prepares_source_and_commits_a_terminal_receipt() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(fixture.lease.clone()),
                execution_grant: "unused-host-preparation-grant".to_owned(),
            },
        ));
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&fixture.lease),
            gateway.clone(),
            Arc::new(PanicLauncher),
            Arc::new(fixture.preparer.clone()),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run host-preparation assignment");

        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Succeeded);
        assert_eq!(
            receipts[0].cleanup_result,
            WorkflowCleanupResultV1::Complete
        );
        assert!(receipts[0].output_digest.is_some());
        assert!(
            gateway
                .cleanup_receipts
                .lock()
                .expect("cleanup receipt lock")
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn worker_shutdown_cancels_network_prefetch_and_removes_partial_staging() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture_for_adapter(
            now_ms,
            now_ms + 15_000,
            WorkflowHostPreparationAdapterV1::CargoCratesIoV1,
        );
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(fixture.lease.clone()),
                execution_grant: "unused-host-preparation-grant".to_owned(),
            },
        ));
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fetcher = Arc::new(BlockingDependencyFetcher {
            started: Arc::clone(&started),
            dropped: Arc::clone(&dropped),
        });
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&fixture.lease),
            gateway.clone(),
            Arc::new(PanicLauncher),
            Arc::new(fixture.preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime")
        .with_dependency_fetcher(fetcher);
        tokio::time::timeout(
            Duration::from_secs(2),
            runtime.run_until(started.notified()),
        )
        .await
        .expect("worker shutdown deadline")
        .expect("worker shutdown");

        assert!(dropped.load(Ordering::SeqCst));
        assert!(
            gateway
                .node_receipts
                .lock()
                .expect("node receipt lock")
                .is_empty()
        );
        let staging = fixture.directory.path().join("preparation/staging");
        assert!(
            fs::read_dir(staging)
                .expect("read staging")
                .next()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_retryable_gateway_rejection_stops_the_worker_service() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&fixture.lease),
            Arc::new(NonRetryableGateway),
            Arc::new(PanicLauncher),
            Arc::new(fixture.preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");

        let result = runtime.run_until(std::future::pending::<()>()).await;
        assert!(matches!(
            result,
            Err(WorkflowWorkerError::Gateway(
                WorkflowWorkerClientError::Rejected {
                    code: WorkflowWorkerRejectionCodeV1::WorkerBindingMismatch,
                    retryable: false,
                }
            ))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preparation_renews_a_short_lease_before_committing_its_receipt() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 100);
        let original_digest = fixture.lease.lease_digest.clone();
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(fixture.lease.clone()),
                execution_grant: "initial-grant".to_owned(),
            },
        ));
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&fixture.lease),
            gateway.clone(),
            Arc::new(PanicLauncher),
            Arc::new(fixture.preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run renewable host-preparation assignment");

        assert!(gateway.renewal_count.load(Ordering::SeqCst) >= 1);
        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_ne!(receipts[0].lease_digest, original_digest);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Succeeded);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unsupported_preparation_fails_with_complete_cleanup_instead_of_expiring() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("decode project manifest");
        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .expect("host preparation node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("host preparation profile");
        let source_identity = fixture
            .lease
            .required_source_identity()
            .expect("source identity")
            .clone();
        let unsupported = WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            fixture.lease.request_id,
            fixture.lease.attempt_id,
            fixture.lease.project_id.clone(),
            fixture.lease.source_sha.clone(),
            source_identity.sequence,
            source_identity.attestation_digest.clone(),
            fixture.lease.workflow_policy_digest.clone(),
            fixture.lease.preparation_key.clone(),
            node,
            profile,
            None,
            vec![WorkflowLeaseInputV1 {
                node_id: "source".parse().expect("source node ID"),
                artifact_kind: WorkflowArtifactKindV1::SourceSnapshot,
                output_digest: source_identity.attestation_digest,
            }],
            EvidenceDigest::sha256("unsupported preparation input"),
            fixture.lease.worker_id.clone(),
            fixture.lease.host_id.clone(),
            now_ms,
            now_ms + 15_000,
        )
        .expect("legacy-compatible lease");
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(unsupported.clone()),
                execution_grant: "unused-host-preparation-grant".to_owned(),
            },
        ));
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&unsupported),
            gateway.clone(),
            Arc::new(PanicLauncher),
            Arc::new(fixture.preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run unsupported host-preparation assignment");

        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Failed);
        assert_eq!(
            receipts[0].cleanup_result,
            WorkflowCleanupResultV1::Complete
        );
        assert!(receipts[0].output_digest.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn generic_runtime_pins_launches_cleans_and_unpins_bare_ci() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 15_000);
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(verification_lease.clone()),
                execution_grant: "signed-execution-grant".to_owned(),
            },
        ));
        let launcher = Arc::new(SuccessfulLauncher::new());
        let shared_preparer = Arc::new(fixture.preparer.clone());
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            gateway.clone(),
            launcher.clone(),
            Arc::clone(&shared_preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run bare bin/ci assignment");

        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Succeeded);
        assert_eq!(
            receipts[0].output_digest,
            Some(EvidenceDigest::sha256("test terminal evidence"))
        );
        assert_eq!(launcher.cleanup_calls.load(Ordering::SeqCst), 1);
        assert!(
            !shared_preparer
                .store()
                .unpin_if_present(verification_lease.lease_id, &prepared.prepared_run_key)
                .expect("verify pin was released")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn successful_process_with_unusable_operation_state_commits_failure() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, _prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 15_000);
        let operation_state = crate::domain::WorkflowOperationStateV1::new(
            verification_lease.attempt_id,
            &verification_lease.project_id,
            &verification_lease.source_sha,
            &verification_lease.workflow_policy_digest,
            &verification_lease.preparation_key,
            &verification_lease.worker_id,
            &verification_lease.host_id,
            vec![verification_lease.node_id.clone()],
            1024 * 1024,
            4_096,
        )
        .expect("operation state");
        let verification_lease = verification_lease
            .with_operation_state(operation_state)
            .expect("state-bound verification lease");
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(verification_lease.clone()),
                execution_grant: "signed-execution-grant".to_owned(),
            },
        ));
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            gateway.clone(),
            Arc::new(UnusableOperationStateLauncher),
            Arc::new(fixture.preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run state-limit assignment");

        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Failed);
        assert!(receipts[0].output_digest.is_none());
        assert_eq!(
            receipts[0].execution_receipt_digest,
            worker_failure_digest(&verification_lease, "operation_state_unusable")
                .expect("operation-state failure evidence")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_cleans_an_active_launcher_job_before_the_worker_stops() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 15_000);
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(verification_lease.clone()),
                execution_grant: "signed-execution-grant".to_owned(),
            },
        ));
        let launcher = Arc::new(RunningLauncher::new());
        let shared_preparer = Arc::new(fixture.preparer.clone());
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            gateway.clone(),
            launcher.clone(),
            Arc::clone(&shared_preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let shutdown_launcher = launcher.clone();
        runtime
            .run_until(async move {
                shutdown_launcher.launched.notified().await;
            })
            .await
            .expect("stop worker after cleaning active launch");

        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Failed);
        assert_eq!(
            receipts[0].cleanup_result,
            WorkflowCleanupResultV1::Complete
        );
        assert_eq!(launcher.cleanup_calls.load(Ordering::SeqCst), 1);
        assert!(
            !shared_preparer
                .store()
                .unpin_if_present(verification_lease.lease_id, &prepared.prepared_run_key)
                .expect("verify shutdown released the prepared-run pin")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pending_cleanup_evidence_binds_the_renewed_receipt_lease() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 100);
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Lease {
                lease: Box::new(verification_lease.clone()),
                execution_grant: "signed-execution-grant".to_owned(),
            },
        ));
        let shared_preparer = Arc::new(fixture.preparer.clone());
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            gateway.clone(),
            Arc::new(StartAndCleanupFailLauncher),
            Arc::clone(&shared_preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("commit pending-cleanup receipt");

        assert_eq!(gateway.renewal_count.load(Ordering::SeqCst), 1);
        let renewed = verification_lease
            .renewed(verification_lease.expires_at_ms + 5_000)
            .expect("derive fake renewed lease");
        let receipts = gateway.node_receipts.lock().expect("node receipt lock");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, WorkflowNodeOutcomeV1::Failed);
        assert_eq!(receipts[0].cleanup_result, WorkflowCleanupResultV1::Pending);
        assert_eq!(receipts[0].lease_digest, renewed.lease_digest);
        assert_eq!(
            receipts[0].cleanup_receipt_digest,
            pending_cleanup_digest(&renewed, "launcher_start_failed")
                .expect("renewed cleanup evidence")
        );
        assert!(
            shared_preparer
                .store()
                .unpin_if_present(verification_lease.lease_id, &prepared.prepared_run_key)
                .expect("pending cleanup retains the prepared-run pin")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn terminal_cleanup_and_unpin_finish_before_a_failed_receipt_renewal() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 100);
        let launcher = Arc::new(SuccessfulLauncher::new());
        let shared_preparer = Arc::new(fixture.preparer.clone());
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            Arc::new(RenewalFailGateway),
            launcher.clone(),
            Arc::clone(&shared_preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        runtime
            .pin_prepared_run(&verification_lease, &prepared.prepared_run_key)
            .await
            .expect("pin prepared run");
        let terminal = test_launch_status(&verification_lease, WorkflowLaunchStateV1::Succeeded);

        let result = runtime
            .finish_launcher_terminal(
                verification_lease.clone(),
                &prepared.prepared_run_key,
                terminal,
            )
            .await;
        assert!(matches!(
            result,
            Err(WorkflowWorkerError::Gateway(
                WorkflowWorkerClientError::DeadlineExceeded
            ))
        ));
        assert_eq!(launcher.cleanup_calls.load(Ordering::SeqCst), 1);
        assert!(
            !shared_preparer
                .store()
                .unpin_if_present(verification_lease.lease_id, &prepared.prepared_run_key)
                .expect("failed renewal cannot retain a cleaned job pin")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cleanup_obligation_reconciles_launcher_and_releases_prepared_run_pin() {
        let now_ms = current_time_ms().expect("test clock");
        let fixture = preparation_fixture(now_ms, now_ms + 15_000);
        let (verification_lease, prepared) =
            prepare_verification_lease(&fixture, now_ms, now_ms + 15_000);
        fixture
            .preparer
            .store()
            .open_pinned(
                PreparationObjectKindV1::PreparedRun,
                &prepared.prepared_run_key,
                verification_lease.lease_id,
                verification_lease.expires_at_ms,
                now_ms,
            )
            .expect("pin prepared run before simulated restart");
        let gateway = Arc::new(FakeGateway::with_assignment(
            WorkflowWorkerAssignmentV1::Cleanup {
                obligation: Box::new(WorkflowCleanupObligationV1 {
                    lease: verification_lease.clone(),
                    terminal_receipt: None,
                    reason: WorkflowCleanupReasonV1::LeaseExpired,
                }),
            },
        ));
        let launcher = Arc::new(SuccessfulLauncher::new());
        let shared_preparer = Arc::new(fixture.preparer.clone());
        let runtime = WorkflowWorkerRuntimeV1::new(
            registration(&verification_lease),
            gateway.clone(),
            launcher.clone(),
            Arc::clone(&shared_preparer),
            test_runtime_config(),
        )
        .expect("build generic worker runtime");
        let completion = gateway.clone();
        runtime
            .run_until(async move {
                completion.completed.notified().await;
            })
            .await
            .expect("run cleanup obligation");

        assert!(
            gateway
                .node_receipts
                .lock()
                .expect("node receipt lock")
                .is_empty()
        );
        let cleanup_receipts = gateway
            .cleanup_receipts
            .lock()
            .expect("cleanup receipt lock");
        assert_eq!(cleanup_receipts.len(), 1);
        assert_eq!(cleanup_receipts[0].lease_id, verification_lease.lease_id);
        assert_eq!(launcher.cleanup_calls.load(Ordering::SeqCst), 1);
        assert!(
            !shared_preparer
                .store()
                .unpin_if_present(verification_lease.lease_id, &prepared.prepared_run_key)
                .expect("verify recovery pin was released")
        );
    }

    #[test]
    fn source_archive_rejects_links_unsafe_paths_and_declared_overflow() {
        assert!(matches!(
            decode_tar_path(b"../escape", false),
            Err(WorkflowWorkerError::InvalidSourcePath)
        ));
        assert!(matches!(
            decode_tar_path(b"/absolute", false),
            Err(WorkflowWorkerError::InvalidSourcePath)
        ));
        assert_eq!(
            decode_tar_path(b"bin/", true).expect("normalize Git archive directory"),
            PathBuf::from("bin")
        );
        assert!(matches!(
            decode_tar_path(b"bin/", false),
            Err(WorkflowWorkerError::InvalidSourcePath)
        ));

        let directory = tempdir().expect("temp directory");
        let archive_path = directory.path().join("links.tar");
        let output = File::create(&archive_path).expect("create tar");
        let mut archive = tar::Builder::new(output);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header
            .set_link_name("/etc/passwd")
            .expect("set link target");
        header.set_cksum();
        archive
            .append_data(&mut header, "link", io::empty())
            .expect("append link");
        archive.finish().expect("finish tar");
        assert!(matches!(
            SourceTarInventoryV1::inspect(&archive_path, 1_024, 10),
            Err(WorkflowWorkerError::UnsupportedSourceEntry)
        ));

        let regular_path = directory.path().join("regular.tar");
        let mut output = File::create(&regular_path).expect("create regular tar");
        write_source_tar(&mut output, None).expect("write regular tar");
        assert!(matches!(
            SourceTarInventoryV1::inspect(&regular_path, 1, 10),
            Err(WorkflowWorkerError::SourcePayloadTooLarge)
        ));
    }
}
