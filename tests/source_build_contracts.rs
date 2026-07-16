use std::{
    str::FromStr,
    sync::{Arc, Mutex, mpsc},
};

use rdashboard::{
    build::{
        AuthorizedReleaseIdentityInputV1, AuthorizedReleaseIdentityV1, BaseRegistryAllowlistV1,
        BaseRegistryHost, BuildContextFreezeRequest, BuildContextFreezer, BuildContractError,
        BuildPath, CiGateEvidenceV1, ExportedFileKind, ExportedFileV1, FrozenBuildContextV1,
        GeneratedFileEvidenceV1, ImageBuildEvidenceV1, ImmutableSourceExportV1,
        InstalledKamalPolicyInputV1, InstalledKamalPolicyV1, JobLimitsV1, KamalClearEnvironmentV1,
        KamalContainerPath, KamalDeploymentPlanV1, KamalEnvironmentKey, KamalEnvironmentValue,
        KamalHostPath, KamalImageName, KamalLoggingDriverV1, KamalLoggingPolicyV1,
        KamalMountAccessV1, KamalMountV1, KamalNetworkAlias, KamalNetworkName, KamalPortBindingV1,
        KamalPortProtocolV1, KamalSecretBindingV1, KamalSecretName, KamalServiceName, KamalSshUser,
        KamalTargetHost, KamalUnixIdentityV1, OciDigest, PrefetchEvidenceV1, RegistryHost,
        ReleaseBundleReader, ReleaseBundleStore, ReleaseBundleStoreError, ReleaseBundleV1,
        ReleaseRollbackContractV1, ReleaseRuntimeContractV1, ResolvedBaseV1,
        ResourceReservationEvidenceV1, validate_repository_dockerfile,
    },
    controller::DurableController,
    domain::{
        ArtifactContractError, DiskReservation, EvidenceDigest, GitCommitId,
        InstalledPolicyIdentity, OperationPhase, PhaseArtifacts, ProjectId, ReleaseClass,
    },
    source::{
        CommitRelationship, DeterministicSourceRepository, DurableSourceBroker,
        InstalledSourceProjectPolicy, LiveSourceGate, SourceChannel, SourceError, SourceGateError,
        SourceIngressOutcome, SourceProjectState, SourceRepository, SourceStore,
    },
    store::ControlStore,
};
use tempfile::tempdir;
use uuid::Uuid;

fn project() -> ProjectId {
    ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"))
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40))
        .unwrap_or_else(|error| panic!("commit fixture: {error}"))
}

fn digest(label: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn release_identity(head: GitCommitId) -> AuthorizedReleaseIdentityV1 {
    AuthorizedReleaseIdentityV1::new(AuthorizedReleaseIdentityInputV1 {
        attempt_id: Uuid::from_u128(1),
        project_id: project(),
        source_head: head,
        source_sequence: 1,
        source_attestation_digest: digest("source attestation"),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v1"),
            version: 1,
        },
        executor_authorization_digest: digest("operation"),
    })
    .unwrap_or_else(|error| panic!("release identity: {error}"))
}

fn source_policy(version: u64) -> InstalledSourceProjectPolicy {
    InstalledSourceProjectPolicy {
        project_id: project(),
        repository_identity: digest("canonical repository"),
        installed_policy: InstalledPolicyIdentity {
            digest: digest(&format!("source policy v{version}")),
            version,
        },
        auto_deploy: true,
        maximum_attempts: 2,
        release_class: ReleaseClass::CodeOnlyCompatible,
    }
}

fn deterministic_repository() -> DeterministicSourceRepository {
    let repository = DeterministicSourceRepository::default();
    repository
        .set_repository_identity(&project(), digest("canonical repository"))
        .unwrap_or_else(|error| panic!("set repository identity: {error}"));
    repository
}

fn source_broker<R: SourceRepository>(
    store: SourceStore,
    repository: R,
    policy: InstalledSourceProjectPolicy,
    started_at_ms: i64,
) -> DurableSourceBroker<R> {
    source_broker_with_ttl(store, repository, policy, 60_000, started_at_ms)
}

fn source_broker_with_ttl<R: SourceRepository>(
    store: SourceStore,
    repository: R,
    policy: InstalledSourceProjectPolicy,
    attestation_ttl_ms: i64,
    started_at_ms: i64,
) -> DurableSourceBroker<R> {
    DurableSourceBroker::new(
        store,
        repository,
        "source-contract-key",
        ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]),
        attestation_ttl_ms,
        vec![policy],
        started_at_ms,
    )
    .unwrap_or_else(|error| panic!("source broker fixture: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CasFailure {
    Never,
    BeforeMutation,
    AfterMutation,
    ConcurrentMutation,
}

#[derive(Clone, Debug)]
struct FailingCasRepository {
    inner: DeterministicSourceRepository,
    failure: Arc<Mutex<CasFailure>>,
}

impl FailingCasRepository {
    fn new(inner: DeterministicSourceRepository, failure: CasFailure) -> Self {
        Self {
            inner,
            failure: Arc::new(Mutex::new(failure)),
        }
    }
}

impl SourceRepository for FailingCasRepository {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError> {
        self.inner.repository_identity(project_id)
    }

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError> {
        self.inner.fetch_remote_main(project_id)
    }

    fn contains_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError> {
        self.inner.contains_commit(project_id, commit)
    }

    fn relationship(
        &self,
        project_id: &ProjectId,
        current: &GitCommitId,
        candidate: &GitCommitId,
    ) -> Result<CommitRelationship, SourceError> {
        self.inner.relationship(project_id, current, candidate)
    }

    fn accepted_head(&self, project_id: &ProjectId) -> Result<Option<GitCommitId>, SourceError> {
        self.inner.accepted_head(project_id)
    }

    fn compare_and_swap_accepted_head(
        &self,
        project_id: &ProjectId,
        expected: Option<&GitCommitId>,
        candidate: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let failure = {
            let mut state = self.failure.lock().map_err(|_| SourceError::LockPoisoned)?;
            std::mem::replace(&mut *state, CasFailure::Never)
        };
        if failure == CasFailure::BeforeMutation {
            return Err(SourceError::Repository(
                "injected crash before source ref mutation".to_owned(),
            ));
        }
        if failure == CasFailure::ConcurrentMutation {
            if !self
                .inner
                .compare_and_swap_accepted_head(project_id, expected, &commit('c'))?
            {
                return Err(SourceError::Repository(
                    "injected concurrent source ref mutation lost its race".to_owned(),
                ));
            }
            return Ok(false);
        }
        let changed = self
            .inner
            .compare_and_swap_accepted_head(project_id, expected, candidate)?;
        if failure == CasFailure::AfterMutation {
            return Err(SourceError::Repository(
                "injected crash after source ref mutation".to_owned(),
            ));
        }
        Ok(changed)
    }
}

#[derive(Clone, Debug)]
struct BlockingAcceptedHeadRepository {
    inner: DeterministicSourceRepository,
    next_gate: Arc<Mutex<Option<AcceptedHeadGate>>>,
}

type AcceptedHeadGate = (mpsc::SyncSender<()>, mpsc::Receiver<()>);

impl BlockingAcceptedHeadRepository {
    fn new(inner: DeterministicSourceRepository) -> Self {
        Self {
            inner,
            next_gate: Arc::new(Mutex::new(None)),
        }
    }

    fn block_next_accepted_head(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::channel();
        let mut next_gate = self
            .next_gate
            .lock()
            .unwrap_or_else(|_| panic!("accepted-head gate lock poisoned"));
        assert!(next_gate.is_none(), "accepted-head gate already installed");
        *next_gate = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }
}

impl SourceRepository for BlockingAcceptedHeadRepository {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError> {
        self.inner.repository_identity(project_id)
    }

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError> {
        self.inner.fetch_remote_main(project_id)
    }

    fn contains_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError> {
        self.inner.contains_commit(project_id, commit)
    }

    fn relationship(
        &self,
        project_id: &ProjectId,
        current: &GitCommitId,
        candidate: &GitCommitId,
    ) -> Result<CommitRelationship, SourceError> {
        self.inner.relationship(project_id, current, candidate)
    }

    fn accepted_head(&self, project_id: &ProjectId) -> Result<Option<GitCommitId>, SourceError> {
        let gate = self
            .next_gate
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .take();
        if let Some((entered, release)) = gate {
            entered.send(()).map_err(|_| {
                SourceError::Repository("accepted-head gate observer disappeared".to_owned())
            })?;
            release.recv().map_err(|_| {
                SourceError::Repository("accepted-head gate releaser disappeared".to_owned())
            })?;
        }
        self.inner.accepted_head(project_id)
    }

    fn compare_and_swap_accepted_head(
        &self,
        project_id: &ProjectId,
        expected: Option<&GitCommitId>,
        candidate: &GitCommitId,
    ) -> Result<bool, SourceError> {
        self.inner
            .compare_and_swap_accepted_head(project_id, expected, candidate)
    }
}

#[test]
fn source_broker_rejects_repository_identity_substitution() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let repository = deterministic_repository();
    let mut substituted_policy = source_policy(1);
    substituted_policy.repository_identity = digest("different repository");
    assert!(matches!(
        DurableSourceBroker::new(
            SourceStore::open(directory.path().join("source.sqlite"))
                .unwrap_or_else(|error| panic!("source store: {error}")),
            repository,
            "source-contract-key",
            ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]),
            60_000,
            vec![substituted_policy],
            100,
        ),
        Err(SourceError::RepositoryIdentityMismatch)
    ));
}

#[test]
fn owner_resolution_verifies_the_ref_clears_the_journal_and_preserves_audit() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let store =
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert canonical commit: {error}"));
    repository
        .insert_commit(&project(), &commit('b'), Some(commit('a')))
        .unwrap_or_else(|error| panic!("insert candidate commit: {error}"));
    repository
        .insert_commit(&project(), &commit('c'), None)
        .unwrap_or_else(|error| panic!("insert concurrent commit: {error}"));
    let initial = source_broker(store.clone(), repository.clone(), source_policy(1), 100);
    initial
        .process_direct_push(
            &project(),
            "accept-a",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept canonical head: {error}"));
    drop(initial);

    let failing = FailingCasRepository::new(repository.clone(), CasFailure::ConcurrentMutation);
    let broker = source_broker(store.clone(), failing, source_policy(1), 102);
    assert_eq!(
        broker
            .process_direct_push(
                &project(),
                "race-b",
                "refs/heads/main",
                Some(&commit('a')),
                commit('b'),
                103,
            )
            .unwrap_or_else(|error| panic!("record ref race: {error}")),
        SourceIngressOutcome::SourceDivergedNeedsOwner
    );
    let diverged = broker
        .store()
        .snapshot(&project())
        .unwrap_or_else(|error| panic!("diverged snapshot: {error}"));
    assert_eq!(diverged.divergent_candidate, Some(commit('c')));
    let divergence_evidence = diverged
        .divergence_evidence_digest
        .unwrap_or_else(|| panic!("divergence evidence is missing"));
    assert!(matches!(
        broker.resolve_divergence_keep_canonical(
            &project(),
            Some(&commit('a')),
            &divergence_evidence,
            104,
        ),
        Err(SourceError::OwnerResolutionMismatch)
    ));

    assert!(
        repository
            .compare_and_swap_accepted_head(&project(), Some(&commit('c')), &commit('a'))
            .unwrap_or_else(|error| panic!("repair accepted ref: {error}"))
    );
    broker
        .resolve_divergence_keep_canonical(
            &project(),
            Some(&commit('a')),
            &divergence_evidence,
            105,
        )
        .unwrap_or_else(|error| panic!("resolve divergence: {error}"));
    drop(broker);

    assert_divergence_audit_resolved(&source_path, &divergence_evidence);

    let recovered = source_broker(store, repository, source_policy(1), 106);
    assert!(matches!(
        recovered
            .process_direct_push(
                &project(),
                "accept-b-after-resolution",
                "refs/heads/main",
                Some(&commit('a')),
                commit('b'),
                107,
            )
            .unwrap_or_else(|error| panic!("accept after owner resolution: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
}

fn assert_divergence_audit_resolved(
    source_path: &std::path::Path,
    divergence_evidence: &EvidenceDigest,
) {
    let connection = rusqlite::Connection::open(source_path)
        .unwrap_or_else(|error| panic!("inspect source audit: {error}"));
    let pending: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM source_ref_update_journal",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count pending refs: {error}"));
    let resolved: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM source_divergence_events
             WHERE project_id = ?1 AND evidence_digest = ?2
               AND resolution = 'keep_canonical_head' AND resolved_at_ms = 105",
            rusqlite::params![project().as_str(), divergence_evidence.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count resolved divergence: {error}"));
    assert_eq!(pending, 0);
    assert_eq!(resolved, 1);
}

#[test]
fn source_ref_journal_recovers_every_git_sqlite_crash_window() {
    for (index, failure) in [
        CasFailure::BeforeMutation,
        CasFailure::AfterMutation,
        CasFailure::AfterMutation,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
        let source_path = directory.path().join("source.sqlite");
        let store =
            SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}"));
        let repository = deterministic_repository();
        repository
            .insert_commit(&project(), &commit('a'), None)
            .unwrap_or_else(|error| panic!("insert commit: {error}"));
        let failing = FailingCasRepository::new(repository.clone(), failure);
        let broker = source_broker(store.clone(), failing, source_policy(1), 100);
        assert!(matches!(
            broker.process_direct_push(
                &project(),
                "crash-delivery",
                "refs/heads/main",
                None,
                commit('a'),
                101,
            ),
            Err(SourceError::Repository(_))
        ));
        if index == 2 {
            rusqlite::Connection::open(&source_path)
                .and_then(|connection| {
                    connection.execute(
                        "UPDATE source_ref_update_journal SET state = 'ref_updated'",
                        [],
                    )
                })
                .unwrap_or_else(|error| panic!("inject ref receipt crash: {error}"));
        }
        drop(broker);
        let recovered = source_broker(store, repository.clone(), source_policy(1), 200);
        let snapshot = recovered
            .store()
            .snapshot(&project())
            .unwrap_or_else(|error| panic!("recovered snapshot: {error}"));
        assert_eq!(snapshot.head, Some(commit('a')));
        assert_eq!(snapshot.sequence, 1);
        assert_eq!(snapshot.state, SourceProjectState::Ready);
        assert_eq!(
            repository
                .accepted_head(&project())
                .unwrap_or_else(|error| panic!("accepted ref: {error}")),
            Some(commit('a'))
        );
        assert!(matches!(
            recovered
                .process_direct_push(
                    &project(),
                    "crash-delivery",
                    "refs/heads/main",
                    None,
                    commit('a'),
                    201,
                )
                .unwrap_or_else(|error| panic!("replay recovered delivery: {error}")),
            SourceIngressOutcome::Deployable(_)
        ));
    }
}

#[test]
fn startup_ref_mismatch_and_remote_rewind_fail_closed_without_guessing() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert first commit: {error}"));
    repository
        .insert_commit(&project(), &commit('b'), Some(commit('a')))
        .unwrap_or_else(|error| panic!("insert second commit: {error}"));
    let broker = source_broker(store.clone(), repository.clone(), source_policy(1), 100);
    broker
        .process_direct_push(
            &project(),
            "accept-b",
            "refs/heads/main",
            None,
            commit('b'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept b: {error}"));
    assert!(matches!(
        broker
            .process_direct_push(
                &project(),
                "stale-a",
                "refs/heads/main",
                Some(&commit('a')),
                commit('a'),
                102,
            )
            .unwrap_or_else(|error| panic!("classify stale push: {error}")),
        SourceIngressOutcome::StaleNoop { .. }
    ));

    repository
        .insert_commit(&project(), &commit('c'), None)
        .unwrap_or_else(|error| panic!("insert unrelated commit: {error}"));
    assert!(
        repository
            .compare_and_swap_accepted_head(&project(), Some(&commit('b')), &commit('c'))
            .unwrap_or_else(|error| panic!("tamper accepted ref: {error}"))
    );
    drop(broker);
    let recovered = source_broker(store, repository, source_policy(1), 200);
    let snapshot = recovered
        .store()
        .snapshot(&project())
        .unwrap_or_else(|error| panic!("diverged snapshot: {error}"));
    assert_eq!(snapshot.state, SourceProjectState::SourceDivergedNeedsOwner);
    assert_eq!(snapshot.divergent_candidate, Some(commit('c')));
    assert!(snapshot.divergence_evidence_digest.is_some());
}

#[test]
fn direct_force_push_from_the_current_head_requires_owner_resolution() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .and_then(|()| repository.insert_commit(&project(), &commit('b'), Some(commit('a'))))
        .unwrap_or_else(|error| panic!("insert source history: {error}"));
    let broker = source_broker(store, repository, source_policy(1), 100);
    broker
        .process_direct_push(
            &project(),
            "accept-b-before-force",
            "refs/heads/main",
            None,
            commit('b'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept b: {error}"));

    assert_eq!(
        broker
            .process_direct_push(
                &project(),
                "force-b-to-a",
                "refs/heads/main",
                Some(&commit('b')),
                commit('a'),
                102,
            )
            .unwrap_or_else(|error| panic!("classify force push: {error}")),
        SourceIngressOutcome::SourceDivergedNeedsOwner
    );
}

#[test]
fn source_broker_singleton_lock_and_epoch_fence_duplicate_processes() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let repository = deterministic_repository();
    let first = source_broker(
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}")),
        repository.clone(),
        source_policy(1),
        100,
    );
    assert_eq!(first.broker_epoch(), 1);
    assert!(matches!(
        DurableSourceBroker::new(
            SourceStore::open(&source_path)
                .unwrap_or_else(|error| panic!("competing source store: {error}")),
            repository.clone(),
            "source-contract-key",
            ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]),
            60_000,
            vec![source_policy(1)],
            101,
        ),
        Err(SourceError::BrokerAlreadyRunning)
    ));

    let lock_path = source_path.with_extension("broker.lock");
    std::fs::remove_file(&lock_path)
        .unwrap_or_else(|error| panic!("replace broker lock inode fixture: {error}"));
    let replacement = source_broker(
        SourceStore::open(&source_path)
            .unwrap_or_else(|error| panic!("replacement source store: {error}")),
        repository,
        source_policy(1),
        102,
    );
    assert_eq!(replacement.broker_epoch(), 2);
    assert!(matches!(
        first.reconcile_remote_main(&project(), 103),
        Err(SourceError::BrokerLeaseSuperseded)
    ));
}

#[test]
fn superseded_broker_cannot_commit_after_passing_its_initial_lease_check() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let inner = deterministic_repository();
    inner
        .insert_commit(&project(), &commit('a'), None)
        .and_then(|()| inner.insert_commit(&project(), &commit('c'), None))
        .unwrap_or_else(|error| panic!("insert source history: {error}"));
    let repository = BlockingAcceptedHeadRepository::new(inner);
    let first_store =
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}"));
    let replacement_store = first_store.clone();
    let first = Arc::new(source_broker(
        first_store,
        repository.clone(),
        source_policy(1),
        100,
    ));
    first
        .process_direct_push(
            &project(),
            "epoch-race-a",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept source: {error}"));
    assert_eq!(
        first
            .process_direct_push(
                &project(),
                "epoch-race-c",
                "refs/heads/main",
                Some(&commit('a')),
                commit('c'),
                102,
            )
            .unwrap_or_else(|error| panic!("record divergence: {error}")),
        SourceIngressOutcome::SourceDivergedNeedsOwner
    );
    let diverged = first
        .store()
        .snapshot(&project())
        .unwrap_or_else(|error| panic!("diverged snapshot: {error}"));
    let divergence_evidence = diverged
        .divergence_evidence_digest
        .unwrap_or_else(|| panic!("divergence evidence is missing"));

    let (entered, release) = repository.block_next_accepted_head();
    let stale = Arc::clone(&first);
    let stale_evidence = divergence_evidence.clone();
    let stale_attempt = std::thread::spawn(move || {
        stale.resolve_divergence_keep_canonical(
            &project(),
            Some(&commit('a')),
            &stale_evidence,
            103,
        )
    });
    entered
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("stale broker did not reach repository read: {error}"));

    let lock_path = source_path.with_extension("broker.lock");
    std::fs::remove_file(&lock_path)
        .unwrap_or_else(|error| panic!("replace broker lock inode fixture: {error}"));
    let replacement = source_broker(replacement_store, repository, source_policy(1), 104);
    assert_eq!(replacement.broker_epoch(), 2);
    release
        .send(())
        .unwrap_or_else(|error| panic!("release stale broker: {error}"));
    let stale_result = stale_attempt
        .join()
        .unwrap_or_else(|_| panic!("stale broker thread panicked"));
    assert!(matches!(
        stale_result,
        Err(SourceError::BrokerLeaseSuperseded)
    ));

    let after = replacement
        .store()
        .snapshot(&project())
        .unwrap_or_else(|error| panic!("replacement snapshot: {error}"));
    assert_eq!(after.state, SourceProjectState::SourceDivergedNeedsOwner);
    assert_eq!(after.divergence_evidence_digest, Some(divergence_evidence));
}

#[test]
fn newer_policy_sequence_creates_a_new_generation_and_supersedes_live_admission() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert commit: {error}"));
    let first_broker = source_broker(store.clone(), repository.clone(), source_policy(1), 100);
    first_broker
        .process_direct_push(
            &project(),
            "policy-v1",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept policy v1: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let first = first_broker
        .admit_recorded_deploy(
            &controller,
            &project(),
            SourceChannel::DirectPush,
            "policy-v1",
            102,
        )
        .unwrap_or_else(|error| panic!("admit policy v1: {error}"));

    drop(first_broker);
    let second_broker = source_broker(store, repository, source_policy(2), 103);
    second_broker
        .process_direct_push(
            &project(),
            "policy-v2",
            "refs/heads/main",
            Some(&commit('a')),
            commit('a'),
            104,
        )
        .unwrap_or_else(|error| panic!("reattest policy v2: {error}"));
    let second = second_broker
        .admit_recorded_deploy(
            &controller,
            &project(),
            SourceChannel::DirectPush,
            "policy-v2",
            105,
        )
        .unwrap_or_else(|error| panic!("admit policy v2: {error}"));
    assert!(second.created());
    assert_eq!(second.operation().request_id, first.operation().request_id);
    assert_eq!(second.operation().attempt_number, 2);
    assert_eq!(second.operation().evidence.source_sequence, Some(2));
    assert!(matches!(
        second_broker.check_live(first.operation(), 106),
        Err(SourceGateError::HeadSuperseded)
    ));
}

#[test]
fn expired_same_head_attestations_are_renewed_for_direct_and_reconciled_ingress() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert commit: {error}"));
    repository
        .set_remote_head(&project(), commit('a'))
        .unwrap_or_else(|error| panic!("set remote head: {error}"));
    let broker = source_broker_with_ttl(store, repository, source_policy(1), 10_000, 100);
    broker
        .process_direct_push(
            &project(),
            "ttl-initial",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("initial source head: {error}"));
    assert!(matches!(
        broker
            .process_direct_push(
                &project(),
                "ttl-direct-renewal",
                "refs/heads/main",
                Some(&commit('a')),
                commit('a'),
                10_101,
            )
            .unwrap_or_else(|error| panic!("direct renewal: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
    assert_eq!(
        broker
            .store()
            .snapshot(&project())
            .unwrap_or_else(|error| panic!("direct snapshot: {error}"))
            .sequence,
        2
    );
    assert!(matches!(
        broker
            .reconcile_remote_main(&project(), 20_101)
            .unwrap_or_else(|error| panic!("reconciled renewal: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
    assert_eq!(
        broker
            .store()
            .snapshot(&project())
            .unwrap_or_else(|error| panic!("reconciled snapshot: {error}"))
            .sequence,
        3
    );
}

#[test]
fn reconciliation_reevaluates_controls_and_historical_rewinds() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .and_then(|()| repository.insert_commit(&project(), &commit('b'), Some(commit('a'))))
        .unwrap_or_else(|error| panic!("insert source history: {error}"));
    repository
        .set_remote_head(&project(), commit('a'))
        .unwrap_or_else(|error| panic!("set initial remote: {error}"));
    let broker = source_broker(store.clone(), repository.clone(), source_policy(1), 100);
    broker
        .process_direct_push(
            &project(),
            "controls-initial",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("initial source: {error}"));
    broker
        .set_controls(&project(), Some(&commit('a')), None, 110)
        .unwrap_or_else(|error| panic!("block source: {error}"));
    assert!(matches!(
        broker.reconcile_remote_main(&project(), 111),
        Ok(SourceIngressOutcome::BlockedSha { .. })
    ));
    broker
        .set_controls(&project(), None, Some(200), 112)
        .unwrap_or_else(|error| panic!("pause source: {error}"));
    assert_eq!(
        broker
            .reconcile_remote_main(&project(), 150)
            .unwrap_or_else(|error| panic!("paused reconciliation: {error}")),
        SourceIngressOutcome::ReconciliationPaused
    );
    assert!(matches!(
        broker
            .reconcile_remote_main(&project(), 201)
            .unwrap_or_else(|error| panic!("expired pause reconciliation: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
    repository
        .set_remote_head(&project(), commit('b'))
        .unwrap_or_else(|error| panic!("advance remote: {error}"));
    assert!(matches!(
        broker
            .reconcile_remote_main(&project(), 202)
            .unwrap_or_else(|error| panic!("advance reconciliation: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
    repository
        .set_remote_head(&project(), commit('a'))
        .unwrap_or_else(|error| panic!("rewind remote: {error}"));
    assert_eq!(
        broker
            .reconcile_remote_main(&project(), 203)
            .unwrap_or_else(|error| panic!("rewind reconciliation: {error}")),
        SourceIngressOutcome::SourceDivergedNeedsOwner
    );
}

#[test]
fn live_mutation_ticket_blocks_source_changes_until_reconciliation_completion() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = SourceStore::open(directory.path().join("source.sqlite"))
        .unwrap_or_else(|error| panic!("source store: {error}"));
    let repository = deterministic_repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .and_then(|()| repository.insert_commit(&project(), &commit('b'), Some(commit('a'))))
        .unwrap_or_else(|error| panic!("insert source history: {error}"));
    let broker = source_broker(store, repository, source_policy(1), 100);
    broker
        .process_direct_push(
            &project(),
            "ticket-a",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept source: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let admission = broker
        .admit_recorded_deploy(
            &controller,
            &project(),
            SourceChannel::DirectPush,
            "ticket-a",
            102,
        )
        .unwrap_or_else(|error| panic!("admit source: {error}"));
    let mut operation = admission.operation().clone();
    operation.state.phase = OperationPhase::Deploying;
    broker
        .set_controls(&project(), None, Some(104), 102)
        .unwrap_or_else(|error| panic!("pause source reconciliation: {error}"));
    assert!(matches!(
        broker.check_live(&operation, 103),
        Err(SourceGateError::Paused)
    ));
    broker
        .set_controls(&project(), None, None, 104)
        .unwrap_or_else(|error| panic!("resume source reconciliation: {error}"));
    broker
        .check_live(&operation, 105)
        .unwrap_or_else(|error| panic!("acquire mutation ticket: {error}"));
    assert!(matches!(
        broker.process_direct_push(
            &project(),
            "ticket-b",
            "refs/heads/main",
            Some(&commit('a')),
            commit('b'),
            106,
        ),
        Err(SourceError::MutationAdmissionBusy)
    ));
    let mut wrong_attempt = operation.clone();
    wrong_attempt.attempt_id = Uuid::from_u128(9_999);
    wrong_attempt.state.phase = OperationPhase::Reconciliation;
    assert!(matches!(
        broker.complete_live(&wrong_attempt),
        Err(SourceGateError::Unavailable)
    ));
    let mut wrong_source = operation.clone();
    wrong_source.evidence.source_sequence = Some(2);
    wrong_source.state.phase = OperationPhase::Reconciliation;
    assert!(matches!(
        broker.complete_live(&wrong_source),
        Err(SourceGateError::Unavailable)
    ));
    assert!(matches!(
        broker.process_direct_push(
            &project(),
            "ticket-b",
            "refs/heads/main",
            Some(&commit('a')),
            commit('b'),
            107,
        ),
        Err(SourceError::MutationAdmissionBusy)
    ));
    operation.state.phase = OperationPhase::Reconciliation;
    broker
        .complete_live(&operation)
        .unwrap_or_else(|error| panic!("complete mutation ticket: {error}"));
    assert!(matches!(
        broker
            .process_direct_push(
                &project(),
                "ticket-b",
                "refs/heads/main",
                Some(&commit('a')),
                commit('b'),
                108,
            )
            .unwrap_or_else(|error| panic!("accept source after ticket: {error}")),
        SourceIngressOutcome::Deployable(_)
    ));
}

fn exported(path: &str, contents: &str) -> ExportedFileV1 {
    ExportedFileV1 {
        path: BuildPath::from_str(path).unwrap_or_else(|error| panic!("build path: {error}")),
        kind: ExportedFileKind::Regular,
        bytes: u64::try_from(contents.len()).unwrap_or(u64::MAX),
        digest: digest(contents),
    }
}

struct OciBaseDocuments {
    requested: String,
    platform: String,
    registry_document: Vec<u8>,
    platform_manifest_document: Vec<u8>,
    platform_configuration_document: Vec<u8>,
}

impl OciBaseDocuments {
    fn resolve(&self, stage: &str) -> Result<ResolvedBaseV1, BuildContractError> {
        ResolvedBaseV1::from_registry_documents(
            stage,
            self.requested.clone(),
            self.platform.clone(),
            &self.registry_document,
            &self.platform_manifest_document,
            &self.platform_configuration_document,
        )
    }
}

fn resolved_base(stage: &str, repository: &str) -> (String, ResolvedBaseV1) {
    let documents = oci_base_documents(repository, "linux/amd64");
    let requested = documents.requested.clone();
    let resolved = documents
        .resolve(stage)
        .unwrap_or_else(|error| panic!("resolved base: {error}"));
    (requested, resolved)
}

fn oci_base_documents(repository: &str, platform: &str) -> OciBaseDocuments {
    let (architecture, variant) = match platform {
        "linux/amd64" => ("amd64", None),
        "linux/arm64" => ("arm64", Some("v8")),
        _ => panic!("unsupported test platform {platform}"),
    };
    let mut configuration = serde_json::json!({
        "architecture": architecture,
        "os": "linux",
        "config": {},
        "rootfs": { "type": "layers", "diff_ids": [] }
    });
    let mut descriptor_platform = serde_json::json!({
        "architecture": architecture,
        "os": "linux"
    });
    if let Some(variant) = variant {
        configuration["variant"] = serde_json::json!(variant);
        descriptor_platform["variant"] = serde_json::json!(variant);
    }
    let platform_configuration_document = serde_json::to_vec(&configuration)
        .unwrap_or_else(|error| panic!("serialize OCI configuration: {error}"));
    let configuration_digest = oci_document_digest(&platform_configuration_document);
    let platform_manifest_document = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": configuration_digest,
            "size": platform_configuration_document.len()
        },
        "layers": []
    }))
    .unwrap_or_else(|error| panic!("serialize OCI manifest: {error}"));
    let platform_manifest_digest = oci_document_digest(&platform_manifest_document);
    let unrelated_platform = if architecture == "amd64" {
        serde_json::json!({
            "architecture": "arm64",
            "os": "linux",
            "variant": "v8"
        })
    } else {
        serde_json::json!({
            "architecture": "amd64",
            "os": "linux"
        })
    };
    let registry_document = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": platform_manifest_digest,
                "size": platform_manifest_document.len(),
                "platform": descriptor_platform
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{}", "f".repeat(64)),
                "size": 1,
                "platform": unrelated_platform
            }
        ]
    }))
    .unwrap_or_else(|error| panic!("serialize OCI index: {error}"));
    let requested = format!("{repository}@{}", oci_document_digest(&registry_document));
    OciBaseDocuments {
        requested,
        platform: platform.to_owned(),
        registry_document,
        platform_manifest_document,
        platform_configuration_document,
    }
}

fn oci_document_digest(document: &[u8]) -> String {
    format!("sha256:{}", EvidenceDigest::sha256(document).as_str())
}

fn base_registry_allowlist(hosts: &[&str]) -> BaseRegistryAllowlistV1 {
    BaseRegistryAllowlistV1::new(
        hosts
            .iter()
            .map(|host| {
                BaseRegistryHost::parse(host)
                    .unwrap_or_else(|error| panic!("base registry host: {error}"))
            })
            .collect(),
    )
    .unwrap_or_else(|error| panic!("base registry allowlist: {error}"))
}

fn rootless_build_plan_digest(context: &FrozenBuildContextV1) -> EvidenceDigest {
    let image = ImageBuildEvidenceV1::rootless(
        context,
        OciDigest::from_str(&format!("sha256:{}", "c".repeat(64)))
            .unwrap_or_else(|error| panic!("registry digest: {error}")),
        OciDigest::from_str(&format!("sha256:{}", "d".repeat(64)))
            .unwrap_or_else(|error| panic!("image ID: {error}")),
        digest("OCI archive"),
    )
    .unwrap_or_else(|error| panic!("image evidence: {error}"));
    image
        .phase_artifacts(context)
        .unwrap_or_else(|error| panic!("build artifacts: {error}"))
        .build_plan_digest
        .unwrap_or_else(|| panic!("rootless image evidence must emit a build plan digest"))
}

fn frozen_context() -> (
    FrozenBuildContextV1,
    ResourceReservationEvidenceV1,
    CiGateEvidenceV1,
) {
    let (base_reference, base) = resolved_base("runtime", "docker.io/library/debian");
    let dockerfile = format!("FROM {base_reference} AS runtime");
    let source = ImmutableSourceExportV1::new(
        release_identity(commit('d')),
        vec![
            exported("src/main.rs", "fn main() {}"),
            exported("Dockerfile", &dockerfile),
            exported("Cargo.lock", "version = 4"),
        ],
    )
    .unwrap_or_else(|error| panic!("source export: {error}"));
    let prefetch = PrefetchEvidenceV1::cargo_locked(
        &source,
        digest("verified cargo cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("registry host: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("prefetch evidence: {error}"));
    let base_registries = base_registry_allowlist(&["docker.io"]);
    let context = BuildContextFreezer::freeze(
        &source,
        BuildContextFreezeRequest::new(
            &BuildPath::from_str("Dockerfile")
                .unwrap_or_else(|error| panic!("dockerfile path: {error}")),
            &dockerfile,
            &prefetch,
            &base_registries,
            vec![GeneratedFileEvidenceV1 {
                path: BuildPath::from_str("web/assets.js")
                    .unwrap_or_else(|error| panic!("generated path: {error}")),
                kind: ExportedFileKind::Regular,
                bytes: 16,
                digest: digest("generated asset"),
            }],
            &[BuildPath::from_str("web/assets.js")
                .unwrap_or_else(|error| panic!("declared generated path: {error}"))],
            vec![base],
        ),
    )
    .unwrap_or_else(|error| panic!("freeze context: {error}"));
    let reservation = ResourceReservationEvidenceV1::reserve(
        digest("operation"),
        DiskReservation {
            filesystem_identity: digest("build test filesystem"),
            filesystem_total_bytes: 100 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 90 * 1024 * 1024 * 1024,
            observed_at_ms: 1_700_000_000_000,
            backup_staging_bytes: 1024 * 1024 * 1024,
            build_peak_bytes: 2 * 1024 * 1024 * 1024,
            registry_peak_bytes: 1024 * 1024 * 1024,
            last_known_good_bytes: 2 * 1024 * 1024 * 1024,
            projected_hot_store_growth_bytes: 1024 * 1024 * 1024,
        },
    )
    .unwrap_or_else(|error| panic!("resource reservation: {error}"));
    let ci = CiGateEvidenceV1::passed(
        &context,
        JobLimitsV1 {
            wall_time_seconds: 900,
            memory_max_bytes: 2 * 1024 * 1024 * 1024,
            tasks_max: 128,
            scratch_max_bytes: 1024 * 1024 * 1024,
            cache_max_bytes: 1024 * 1024 * 1024,
            output_max_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap_or_else(|error| panic!("CI evidence: {error}"));
    (context, reservation, ci)
}

#[test]
fn frozen_context_requires_the_exact_exported_dockerfile_and_base_set() {
    let (base_reference, exact_base) = resolved_base("runtime", "docker.io/library/debian");
    let dockerfile = format!("FROM {base_reference} AS runtime");
    let source = ImmutableSourceExportV1::new(
        release_identity(commit('e')),
        vec![
            exported("Cargo.lock", "version = 4"),
            exported("Dockerfile", &dockerfile),
        ],
    )
    .unwrap_or_else(|error| panic!("source export: {error}"));
    let prefetch = PrefetchEvidenceV1::cargo_locked(
        &source,
        digest("cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("registry: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("prefetch: {error}"));
    let path = BuildPath::from_str("Dockerfile")
        .unwrap_or_else(|error| panic!("dockerfile path: {error}"));
    let base_registries = base_registry_allowlist(&["docker.io", "example.test"]);
    assert!(matches!(
        BuildContextFreezer::freeze(
            &source,
            BuildContextFreezeRequest::new(
                &path,
                "FROM scratch",
                &prefetch,
                &base_registries,
                vec![],
                &[],
                vec![exact_base.clone()],
            ),
        ),
        Err(BuildContractError::DockerfileEvidenceMismatch)
    ));
    let (_, unrelated) = resolved_base("runtime", "example.test/other");
    assert!(matches!(
        BuildContextFreezer::freeze(
            &source,
            BuildContextFreezeRequest::new(
                &path,
                &dockerfile,
                &prefetch,
                &base_registries,
                vec![],
                &[],
                vec![unrelated],
            ),
        ),
        Err(BuildContractError::ResolvedBaseMismatch)
    ));
}

#[test]
fn frozen_context_rejects_prefetch_evidence_replayed_across_source_exports() {
    let (base_reference, base) = resolved_base("runtime", "docker.io/library/debian");
    let dockerfile = format!("FROM {base_reference} AS runtime");
    let original = ImmutableSourceExportV1::new(
        release_identity(commit('1')),
        vec![
            exported("Cargo.lock", "version = 4\noriginal = true"),
            exported("Dockerfile", &dockerfile),
            exported("src/main.rs", "fn main() {}"),
        ],
    )
    .unwrap_or_else(|error| panic!("original source export: {error}"));
    let prefetch = PrefetchEvidenceV1::cargo_locked(
        &original,
        digest("original dependency cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("registry: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("original prefetch: {error}"));
    let changed_lockfile = ImmutableSourceExportV1::new(
        release_identity(commit('2')),
        vec![
            exported("Cargo.lock", "version = 4\nchanged = true"),
            exported("Dockerfile", &dockerfile),
            exported("src/main.rs", "fn main() {}"),
        ],
    )
    .unwrap_or_else(|error| panic!("changed-lockfile source export: {error}"));
    let same_lockfile_different_export = ImmutableSourceExportV1::new(
        release_identity(commit('3')),
        vec![
            exported("Cargo.lock", "version = 4\noriginal = true"),
            exported("Dockerfile", &dockerfile),
            exported("src/main.rs", "fn main() { println!(\"changed\"); }"),
        ],
    )
    .unwrap_or_else(|error| panic!("same-lockfile source export: {error}"));
    let path = BuildPath::from_str("Dockerfile")
        .unwrap_or_else(|error| panic!("dockerfile path: {error}"));
    let base_registries = base_registry_allowlist(&["docker.io"]);

    for replayed_source in [&changed_lockfile, &same_lockfile_different_export] {
        assert!(matches!(
            BuildContextFreezer::freeze(
                replayed_source,
                BuildContextFreezeRequest::new(
                    &path,
                    &dockerfile,
                    &prefetch,
                    &base_registries,
                    vec![],
                    &[],
                    vec![base.clone()],
                ),
            ),
            Err(BuildContractError::PrefetchEvidenceMismatch)
        ));
    }
}

#[test]
fn resolved_base_verifies_the_registry_platform_and_configuration_digest_chain() {
    let amd64 = oci_base_documents("docker.io/library/debian", "linux/amd64");
    amd64
        .resolve("runtime")
        .unwrap_or_else(|error| panic!("resolve amd64 from multi-platform index: {error}"));
    let arm64 = oci_base_documents("docker.io/library/debian", "linux/arm64");
    arm64
        .resolve("runtime")
        .unwrap_or_else(|error| panic!("resolve arm64 from multi-platform index: {error}"));

    let mut substituted_manifest = amd64.platform_manifest_document.clone();
    substituted_manifest.push(b' ');
    assert!(matches!(
        ResolvedBaseV1::from_registry_documents(
            "runtime",
            amd64.requested.clone(),
            amd64.platform.clone(),
            &amd64.registry_document,
            &substituted_manifest,
            &amd64.platform_configuration_document,
        ),
        Err(BuildContractError::InvalidBaseImage)
    ));

    let mut substituted_configuration = amd64.platform_configuration_document.clone();
    substituted_configuration.push(b' ');
    assert!(matches!(
        ResolvedBaseV1::from_registry_documents(
            "runtime",
            amd64.requested.clone(),
            amd64.platform.clone(),
            &amd64.registry_document,
            &amd64.platform_manifest_document,
            &substituted_configuration,
        ),
        Err(BuildContractError::InvalidBaseImage)
    ));

    assert!(matches!(
        ResolvedBaseV1::from_registry_documents(
            "runtime",
            arm64.requested,
            "linux/amd64",
            &arm64.registry_document,
            &arm64.platform_manifest_document,
            &arm64.platform_configuration_document,
        ),
        Err(BuildContractError::InvalidBaseImage)
    ));
}

#[test]
fn frozen_context_and_build_plan_bind_dockerfile_path_and_base_registry_policy() {
    let (base_reference, base) = resolved_base("runtime", "docker.io/library/debian");
    let dockerfile = format!("FROM {base_reference} AS runtime");
    let source = ImmutableSourceExportV1::new(
        release_identity(commit('c')),
        vec![
            exported("Cargo.lock", "version = 4"),
            exported("Dockerfile", &dockerfile),
            exported("Dockerfile.dockerignore", "target\n"),
            exported("docker/build.Dockerfile", &dockerfile),
            exported("docker/build.Dockerfile.dockerignore", ".git\n"),
        ],
    )
    .unwrap_or_else(|error| panic!("source export: {error}"));
    let prefetch = PrefetchEvidenceV1::cargo_locked(
        &source,
        digest("path-bound cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("registry: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("prefetch: {error}"));
    let docker_registries = base_registry_allowlist(&["docker.io"]);
    let broader_registries = base_registry_allowlist(&["docker.io", "ghcr.io"]);
    let dockerfile_path = BuildPath::from_str("Dockerfile")
        .unwrap_or_else(|error| panic!("root Dockerfile path: {error}"));
    let nested_dockerfile_path = BuildPath::from_str("docker/build.Dockerfile")
        .unwrap_or_else(|error| panic!("nested Dockerfile path: {error}"));
    let base = || base.clone();
    let root_context = BuildContextFreezer::freeze(
        &source,
        BuildContextFreezeRequest::new(
            &dockerfile_path,
            &dockerfile,
            &prefetch,
            &docker_registries,
            vec![],
            &[],
            vec![base()],
        ),
    )
    .unwrap_or_else(|error| panic!("root Dockerfile context: {error}"));
    let nested_context = BuildContextFreezer::freeze(
        &source,
        BuildContextFreezeRequest::new(
            &nested_dockerfile_path,
            &dockerfile,
            &prefetch,
            &docker_registries,
            vec![],
            &[],
            vec![base()],
        ),
    )
    .unwrap_or_else(|error| panic!("nested Dockerfile context: {error}"));
    let broader_policy_context = BuildContextFreezer::freeze(
        &source,
        BuildContextFreezeRequest::new(
            &dockerfile_path,
            &dockerfile,
            &prefetch,
            &broader_registries,
            vec![],
            &[],
            vec![base()],
        ),
    )
    .unwrap_or_else(|error| panic!("broader registry policy context: {error}"));

    assert_eq!(root_context.dockerfile_path(), &dockerfile_path);
    assert_eq!(nested_context.dockerfile_path(), &nested_dockerfile_path);
    assert_ne!(root_context.digest(), nested_context.digest());
    assert_ne!(root_context.digest(), broader_policy_context.digest());
    assert_eq!(
        root_context.base_registry_allowlist().digest(),
        docker_registries.digest()
    );

    assert_ne!(
        rootless_build_plan_digest(&root_context),
        rootless_build_plan_digest(&nested_context)
    );
    assert_ne!(
        rootless_build_plan_digest(&root_context),
        rootless_build_plan_digest(&broader_policy_context)
    );
}

#[test]
fn frozen_context_enforces_the_installed_base_registry_allowlist() {
    let (docker_reference, docker_base) = resolved_base("runtime", "debian");
    let dockerfile = format!("FROM {docker_reference} AS runtime");
    let source = ImmutableSourceExportV1::new(
        release_identity(commit('b')),
        vec![
            exported("Cargo.lock", "version = 4"),
            exported("Dockerfile", &dockerfile),
        ],
    )
    .unwrap_or_else(|error| panic!("source export: {error}"));
    let prefetch = PrefetchEvidenceV1::cargo_locked(
        &source,
        digest("base-registry cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("registry: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("prefetch: {error}"));
    let path = BuildPath::from_str("Dockerfile")
        .unwrap_or_else(|error| panic!("Dockerfile path: {error}"));
    let docker_registries = base_registry_allowlist(&["docker.io"]);
    BuildContextFreezer::freeze(
        &source,
        BuildContextFreezeRequest::new(
            &path,
            &dockerfile,
            &prefetch,
            &docker_registries,
            vec![],
            &[],
            vec![docker_base],
        ),
    )
    .unwrap_or_else(|error| panic!("default Docker Hub registry: {error}"));

    let (ghcr_reference, ghcr_base) = resolved_base("runtime", "ghcr.io/acme/base");
    let ghcr_digest = ghcr_reference.rsplit_once('@').map_or_else(
        || panic!("GHCR fixture is not digest-pinned"),
        |(_, digest)| digest,
    );
    let ghcr_dockerfile = format!("FROM {ghcr_reference} AS runtime");
    let ghcr_source = ImmutableSourceExportV1::new(
        release_identity(commit('a')),
        vec![
            exported("Cargo.lock", "version = 4"),
            exported("Dockerfile", &ghcr_dockerfile),
        ],
    )
    .unwrap_or_else(|error| panic!("GHCR source export: {error}"));
    let ghcr_prefetch = PrefetchEvidenceV1::cargo_locked(
        &ghcr_source,
        digest("GHCR cache"),
        vec![
            RegistryHost::parse("index.crates.io")
                .unwrap_or_else(|error| panic!("GHCR registry: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("GHCR prefetch: {error}"));
    assert!(matches!(
        BuildContextFreezer::freeze(
            &ghcr_source,
            BuildContextFreezeRequest::new(
                &path,
                &ghcr_dockerfile,
                &ghcr_prefetch,
                &docker_registries,
                vec![],
                &[],
                vec![ghcr_base],
            ),
        ),
        Err(BuildContractError::BaseRegistryNotAllowed(registry)) if registry == "ghcr.io"
    ));

    for reference in [
        format!("localhost:5555/acme/base@sha256:{ghcr_digest}"),
        format!("registry.localhost/acme/base@sha256:{ghcr_digest}"),
        format!("127.0.0.1/acme/base@sha256:{ghcr_digest}"),
        format!("GHCR.io/acme/base@sha256:{ghcr_digest}"),
        format!("https://ghcr.io/acme/base@sha256:{ghcr_digest}"),
        format!("bad..example/acme/base@sha256:{ghcr_digest}"),
    ] {
        assert!(
            validate_repository_dockerfile(&format!("FROM {reference} AS runtime")).is_err(),
            "accepted invalid or private base registry reference {reference}"
        );
    }
}

#[test]
fn immutable_context_ci_image_and_kamal_plan_share_one_identity() {
    let (context, reservation, ci) = frozen_context();
    let testing_artifacts = BuildContextFreezer::testing_artifacts(&context, &ci, &reservation)
        .unwrap_or_else(|error| panic!("testing evidence: {error}"));
    testing_artifacts
        .validate_for_phase(OperationPhase::Testing)
        .unwrap_or_else(|error| panic!("testing artifact contract: {error}"));
    let mut phase_poisoned_artifacts = testing_artifacts.clone();
    phase_poisoned_artifacts.release_bundle_digest = Some(digest("future release bundle"));
    assert!(matches!(
        phase_poisoned_artifacts.validate_for_phase(OperationPhase::Testing),
        Err(ArtifactContractError::UnexpectedEvidence {
            phase: OperationPhase::Testing
        })
    ));
    let image = ImageBuildEvidenceV1::rootless(
        &context,
        OciDigest::from_str(&format!("sha256:{}", "c".repeat(64)))
            .unwrap_or_else(|error| panic!("image digest: {error}")),
        OciDigest::from_str(&format!("sha256:{}", "d".repeat(64)))
            .unwrap_or_else(|error| panic!("image ID: {error}")),
        digest("OCI archive"),
    )
    .unwrap_or_else(|error| panic!("image evidence: {error}"));
    let build_artifacts = image
        .phase_artifacts(&context)
        .unwrap_or_else(|error| panic!("build evidence: {error}"));
    build_artifacts
        .validate_for_phase(OperationPhase::Building)
        .unwrap_or_else(|error| panic!("build artifact contract: {error}"));
    let mut future_phase_build_artifacts = build_artifacts.clone();
    future_phase_build_artifacts.release_bundle_digest = Some(digest("future release bundle"));
    assert!(matches!(
        future_phase_build_artifacts.validate_for_phase(OperationPhase::Building),
        Err(ArtifactContractError::UnexpectedEvidence {
            phase: OperationPhase::Building
        })
    ));
    assert!(matches!(
        PhaseArtifacts::default().validate_for_phase(OperationPhase::HealthChecking),
        Err(ArtifactContractError::MissingRequiredEvidence {
            phase: OperationPhase::HealthChecking
        })
    ));
    let policy = kamal_policy();
    let plan =
        KamalDeploymentPlanV1::generate(&policy, &context, &image, digest("sanitized Kamal diff"))
            .unwrap_or_else(|error| panic!("Kamal plan: {error}"));
    assert!(
        plan.has_valid_digest()
            .unwrap_or_else(|error| panic!("Kamal plan digest: {error}"))
    );
    let bundle = ReleaseBundleV1::seal(
        &context,
        &ci,
        &reservation,
        &image,
        &plan,
        ReleaseRuntimeContractV1 {
            application_schema_version: "rimg-schema-v1".to_owned(),
            rollback: ReleaseRollbackContractV1::BootstrapUnavailable,
        },
    )
    .unwrap_or_else(|error| panic!("release bundle: {error}"));
    assert_eq!(bundle.project_id(), &project());
    assert_ne!(bundle.digest(), plan.digest());
    let encoded = bundle
        .encode_canonical_json()
        .unwrap_or_else(|error| panic!("encode release bundle: {error}"));
    assert_eq!(
        ReleaseBundleV1::decode_canonical_json(&encoded)
            .unwrap_or_else(|error| panic!("decode release bundle: {error}")),
        bundle
    );
    let mut document: serde_json::Value = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("parse bundle document: {error}"));
    let pretty = serde_json::to_vec_pretty(&document)
        .unwrap_or_else(|error| panic!("pretty bundle fixture: {error}"));
    assert!(matches!(
        ReleaseBundleV1::decode_canonical_json(&pretty),
        Err(BuildContractError::NonCanonicalReleaseBundle)
    ));
    document["source_export_digest"] = serde_json::json!(digest("substituted source export"));
    let tampered = serde_jcs::to_vec(&document)
        .unwrap_or_else(|error| panic!("canonical tampered bundle fixture: {error}"));
    assert!(matches!(
        ReleaseBundleV1::decode_canonical_json(&tampered),
        Err(BuildContractError::ReleaseBundleDigestMismatch)
    ));
    bundle
        .phase_artifacts()
        .validate_for_phase(OperationPhase::Deploying)
        .unwrap_or_else(|error| panic!("deploy evidence: {error}"));
}

#[cfg(unix)]
struct ReleaseBundleStoreFixture {
    parent: tempfile::TempDir,
    root: std::path::PathBuf,
    store: ReleaseBundleStore,
    bundle: ReleaseBundleV1,
    project_directory: std::path::PathBuf,
    owner_uid: u32,
}

#[cfg(unix)]
fn release_bundle_store_fixture() -> ReleaseBundleStoreFixture {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let (context, reservation, ci) = frozen_context();
    let image = ImageBuildEvidenceV1::rootless(
        &context,
        OciDigest::from_str(&format!("sha256:{}", "c".repeat(64)))
            .unwrap_or_else(|error| panic!("image digest: {error}")),
        OciDigest::from_str(&format!("sha256:{}", "d".repeat(64)))
            .unwrap_or_else(|error| panic!("image ID: {error}")),
        digest("OCI archive"),
    )
    .unwrap_or_else(|error| panic!("image evidence: {error}"));
    let plan = KamalDeploymentPlanV1::generate(
        &kamal_policy(),
        &context,
        &image,
        digest("sanitized Kamal diff"),
    )
    .unwrap_or_else(|error| panic!("Kamal plan: {error}"));
    let bundle = ReleaseBundleV1::seal(
        &context,
        &ci,
        &reservation,
        &image,
        &plan,
        ReleaseRuntimeContractV1 {
            application_schema_version: "rimg-schema-v1".to_owned(),
            rollback: ReleaseRollbackContractV1::BootstrapUnavailable,
        },
    )
    .unwrap_or_else(|error| panic!("release bundle: {error}"));
    let parent = tempdir().unwrap_or_else(|error| panic!("store parent: {error}"));
    let root = parent.path().join("release-bundles");
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create store root: {error}"));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("protect store root: {error}"));
    let owner_uid = std::fs::metadata(&root)
        .unwrap_or_else(|error| panic!("store root metadata: {error}"))
        .uid();
    let store = ReleaseBundleStore::open_for_owner(&root, owner_uid)
        .unwrap_or_else(|error| panic!("open release bundle store: {error}"));
    let project_directory = root.join(project().as_str());
    std::fs::create_dir(&project_directory)
        .unwrap_or_else(|error| panic!("create project bundle directory: {error}"));
    std::fs::set_permissions(&project_directory, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("protect project bundle directory: {error}"));
    ReleaseBundleStoreFixture {
        parent,
        root,
        store,
        bundle,
        project_directory,
        owner_uid,
    }
}

#[cfg(unix)]
#[test]
fn release_bundle_store_is_atomic_owner_only_and_recovers_post_link() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let fixture = release_bundle_store_fixture();
    let ReleaseBundleStoreFixture {
        parent,
        root,
        store,
        bundle,
        project_directory,
        owner_uid,
    } = fixture;
    let stale_temporary_path = project_directory.join(format!(
        ".{}.{}.tmp",
        bundle.digest().as_str(),
        Uuid::from_u128(10)
    ));
    std::fs::write(&stale_temporary_path, b"interrupted pre-link write")
        .unwrap_or_else(|error| panic!("create stale bundle temporary file: {error}"));
    std::fs::set_permissions(
        &stale_temporary_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap_or_else(|error| panic!("protect stale bundle temporary file: {error}"));
    let path = store
        .persist(&project(), &bundle)
        .unwrap_or_else(|error| panic!("persist release bundle: {error}"));
    assert!(!stale_temporary_path.exists());
    assert_eq!(
        store
            .persist(&project(), &bundle)
            .unwrap_or_else(|error| panic!("idempotent bundle persist: {error}")),
        path
    );
    let metadata = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("persisted bundle metadata: {error}"));
    assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    assert_eq!(metadata.nlink(), 1);
    let linked_temporary_path = project_directory.join(format!(
        ".{}.{}.tmp",
        bundle.digest().as_str(),
        Uuid::from_u128(11)
    ));
    std::fs::hard_link(&path, &linked_temporary_path)
        .unwrap_or_else(|error| panic!("recreate post-link crash window: {error}"));
    assert_eq!(
        std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("linked bundle metadata: {error}"))
            .nlink(),
        2
    );
    assert_eq!(
        store
            .load(&project(), bundle.digest())
            .unwrap_or_else(|error| panic!("load release bundle: {error}")),
        bundle
    );
    assert!(!linked_temporary_path.exists());
    assert_eq!(
        std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("reconciled bundle metadata: {error}"))
            .nlink(),
        1
    );

    let alias = parent.path().join("release-bundles-alias");
    symlink(&root, &alias).unwrap_or_else(|error| panic!("create root alias: {error}"));
    assert!(matches!(
        ReleaseBundleStore::open_for_owner(&alias, owner_uid),
        Err(ReleaseBundleStoreError::UntrustedRoot)
    ));
}

#[cfg(unix)]
#[test]
fn release_bundle_reader_loads_without_locking_or_mutating_the_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = release_bundle_store_fixture();
    let path = fixture
        .store
        .persist(&project(), &fixture.bundle)
        .unwrap_or_else(|error| panic!("persist release bundle: {error}"));
    let orphan = fixture.project_directory.join(format!(
        ".{}.{}.tmp",
        digest("unrelated interrupted writer").as_str(),
        Uuid::from_u128(12)
    ));
    std::fs::write(&orphan, b"active writer state")
        .unwrap_or_else(|error| panic!("create active writer state: {error}"));
    std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("protect active writer state: {error}"));

    let reader = ReleaseBundleReader::open_for_owner(&fixture.root, fixture.owner_uid)
        .unwrap_or_else(|error| panic!("open release bundle reader: {error}"));
    assert_eq!(
        reader
            .load(&project(), fixture.bundle.digest())
            .unwrap_or_else(|error| panic!("read release bundle: {error}")),
        fixture.bundle
    );
    assert!(path.exists());
    assert!(orphan.exists());
}

#[cfg(unix)]
#[test]
fn release_bundle_reader_requires_exact_owner_group_read_handoff() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let fixture = release_bundle_store_fixture();
    let path = fixture
        .store
        .persist(&project(), &fixture.bundle)
        .unwrap_or_else(|error| panic!("persist shared release bundle: {error}"));
    let reader_gid = std::fs::metadata(&fixture.root)
        .unwrap_or_else(|error| panic!("shared root metadata: {error}"))
        .gid();
    drop(fixture.store);
    for directory in [&fixture.root, &fixture.project_directory] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o750))
            .unwrap_or_else(|error| panic!("share {}: {error}", directory.display()));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o440))
        .unwrap_or_else(|error| panic!("share bundle: {error}"));

    let reader =
        ReleaseBundleReader::open_for_owner_and_group(&fixture.root, fixture.owner_uid, reader_gid)
            .unwrap_or_else(|error| panic!("open shared release bundle reader: {error}"));
    assert_eq!(
        reader
            .load(&project(), fixture.bundle.digest())
            .unwrap_or_else(|error| panic!("read shared release bundle: {error}")),
        fixture.bundle
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("remove group access: {error}"));
    assert!(matches!(
        reader.load(&project(), fixture.bundle.digest()),
        Err(ReleaseBundleStoreError::UntrustedBundleFile)
    ));
}

#[cfg(unix)]
#[test]
fn release_bundle_store_sweeps_orphans_only_after_acquiring_the_root_lock() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = tempdir().unwrap_or_else(|error| panic!("store parent: {error}"));
    let root = parent.path().join("release-bundles");
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create store root: {error}"));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("protect store root: {error}"));
    let owner_uid = std::fs::metadata(&root)
        .unwrap_or_else(|error| panic!("store root metadata: {error}"))
        .uid();
    let project_directory = root.join(project().as_str());
    std::fs::create_dir(&project_directory)
        .unwrap_or_else(|error| panic!("create project bundle directory: {error}"));
    std::fs::set_permissions(&project_directory, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("protect project bundle directory: {error}"));

    let orphan_digest = digest("older interrupted release bundle");
    let orphan_path = project_directory.join(format!(
        ".{}.{}.tmp",
        orphan_digest.as_str(),
        Uuid::from_u128(21)
    ));
    std::fs::write(&orphan_path, b"interrupted pre-link release bundle")
        .unwrap_or_else(|error| panic!("create orphan bundle temporary file: {error}"));
    std::fs::set_permissions(&orphan_path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("protect orphan bundle temporary file: {error}"));

    let store = ReleaseBundleStore::open_for_owner(&root, owner_uid)
        .unwrap_or_else(|error| panic!("open and sweep release bundle store: {error}"));
    assert!(!orphan_path.exists());

    let active_digest = digest("active writer release bundle");
    let active_path = project_directory.join(format!(
        ".{}.{}.tmp",
        active_digest.as_str(),
        Uuid::from_u128(22)
    ));
    std::fs::write(&active_path, b"active writer pre-link release bundle")
        .unwrap_or_else(|error| panic!("create active bundle temporary file: {error}"));
    std::fs::set_permissions(&active_path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("protect active bundle temporary file: {error}"));

    assert!(matches!(
        ReleaseBundleStore::open_for_owner(&root, owner_uid),
        Err(ReleaseBundleStoreError::StoreAlreadyOpen)
    ));
    assert!(active_path.exists());

    drop(store);
    let _reopened = ReleaseBundleStore::open_for_owner(&root, owner_uid)
        .unwrap_or_else(|error| panic!("reopen and sweep release bundle store: {error}"));
    assert!(!active_path.exists());
}

#[cfg(unix)]
#[test]
fn release_bundle_store_is_namespace_bound_and_tamper_evident() {
    use std::os::unix::fs::PermissionsExt as _;

    let ReleaseBundleStoreFixture {
        parent: _parent,
        root,
        store,
        bundle,
        ..
    } = release_bundle_store_fixture();
    let path = store
        .persist(&project(), &bundle)
        .unwrap_or_else(|error| panic!("persist release bundle: {error}"));

    let other_project = ProjectId::from_str("keyroom")
        .unwrap_or_else(|error| panic!("other project fixture: {error}"));
    assert!(matches!(
        store.persist(&other_project, &bundle),
        Err(ReleaseBundleStoreError::BundleProjectMismatch)
    ));
    let other_project_directory = root.join(other_project.as_str());
    std::fs::create_dir(&other_project_directory)
        .unwrap_or_else(|error| panic!("create other project directory: {error}"));
    std::fs::set_permissions(
        &other_project_directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap_or_else(|error| panic!("protect other project directory: {error}"));
    let misplaced_path = other_project_directory.join(bundle.digest().as_str());
    std::fs::copy(&path, &misplaced_path)
        .unwrap_or_else(|error| panic!("misplace release bundle fixture: {error}"));
    std::fs::set_permissions(&misplaced_path, std::fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("protect misplaced release bundle fixture: {error}"));
    assert!(matches!(
        store.load(&other_project, bundle.digest()),
        Err(ReleaseBundleStoreError::BundleProjectMismatch)
    ));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("make tamper fixture writable: {error}"));
    std::fs::write(&path, b"{}")
        .unwrap_or_else(|error| panic!("tamper release bundle fixture: {error}"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("restore bundle mode: {error}"));
    assert!(store.load(&project(), bundle.digest()).is_err());
}

#[test]
fn identical_source_bytes_cannot_cross_authorization_or_policy_generations() {
    let head = commit('d');
    let first_identity = release_identity(head.clone());
    let second_identity = AuthorizedReleaseIdentityV1::new(AuthorizedReleaseIdentityInputV1 {
        attempt_id: Uuid::from_u128(2),
        project_id: project(),
        source_head: head,
        source_sequence: 2,
        source_attestation_digest: digest("source attestation v2"),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v2"),
            version: 2,
        },
        executor_authorization_digest: digest("operation-v2"),
    })
    .unwrap_or_else(|error| panic!("second release identity: {error}"));
    let files = vec![exported("Cargo.lock", "version = 4")];
    let first = ImmutableSourceExportV1::new(first_identity.clone(), files.clone())
        .unwrap_or_else(|error| panic!("first export: {error}"));
    let second = ImmutableSourceExportV1::new(second_identity.clone(), files)
        .unwrap_or_else(|error| panic!("second export: {error}"));
    assert_ne!(first_identity.digest(), second_identity.digest());
    assert_ne!(first.digest(), second.digest());
    assert!(matches!(
        AuthorizedReleaseIdentityV1::new(AuthorizedReleaseIdentityInputV1 {
            source_sequence: 0,
            ..AuthorizedReleaseIdentityInputV1 {
                attempt_id: Uuid::from_u128(3),
                project_id: project(),
                source_head: commit('d'),
                source_sequence: 1,
                source_attestation_digest: digest("invalid source attestation"),
                installed_policy: InstalledPolicyIdentity {
                    digest: digest("policy-v3"),
                    version: 3,
                },
                executor_authorization_digest: digest("operation-v3"),
            }
        }),
        Err(BuildContractError::InvalidReleaseIdentity)
    ));
}

fn kamal_policy() -> InstalledKamalPolicyV1 {
    InstalledKamalPolicyV1::new(InstalledKamalPolicyInputV1 {
        project_id: project(),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v1"),
            version: 1,
        },
        service: KamalServiceName::from_str("rimg")
            .unwrap_or_else(|error| panic!("service: {error}")),
        image: KamalImageName::from_str("mrdenai/rimg")
            .unwrap_or_else(|error| panic!("image: {error}")),
        target_host: KamalTargetHost::from_str("45.151.142.168")
            .unwrap_or_else(|error| panic!("target host: {error}")),
        ssh_user: KamalSshUser::from_str("deploy")
            .unwrap_or_else(|error| panic!("SSH user: {error}")),
        ssh_port: 22,
        network: KamalNetworkName::from_str("kamal")
            .unwrap_or_else(|error| panic!("network: {error}")),
        network_alias: KamalNetworkAlias::from_str("rimg")
            .unwrap_or_else(|error| panic!("network alias: {error}")),
        run_as: KamalUnixIdentityV1 {
            uid: 10_001,
            gid: 10_001,
        },
        allowed_host_roots: vec![
            KamalHostPath::from_str("/srv/rimg")
                .unwrap_or_else(|error| panic!("host root: {error}")),
        ],
        mounts: vec![KamalMountV1 {
            host_path: KamalHostPath::from_str("/srv/rimg/data")
                .unwrap_or_else(|error| panic!("host path: {error}")),
            container_path: KamalContainerPath::from_str("/app/data")
                .unwrap_or_else(|error| panic!("container path: {error}")),
            access: KamalMountAccessV1::ReadWrite,
        }],
        ports: vec![KamalPortBindingV1 {
            host_port: 8080,
            container_port: 3000,
            protocol: KamalPortProtocolV1::Tcp,
        }],
        clear_environment: vec![KamalClearEnvironmentV1 {
            key: KamalEnvironmentKey::from_str("RUST_LOG")
                .unwrap_or_else(|error| panic!("environment key: {error}")),
            value: KamalEnvironmentValue::from_str("info")
                .unwrap_or_else(|error| panic!("environment value: {error}")),
        }],
        secret_bindings: vec![KamalSecretBindingV1 {
            environment_key: KamalEnvironmentKey::from_str("RIMG_DATABASE_KEY")
                .unwrap_or_else(|error| panic!("secret environment key: {error}")),
            secret_name: KamalSecretName::from_str("RIMG_DATABASE_KEY")
                .unwrap_or_else(|error| panic!("secret name: {error}")),
            credential_version: 1,
        }],
        logging: KamalLoggingPolicyV1 {
            driver: KamalLoggingDriverV1::Local,
            max_size_bytes: 16 * 1024 * 1024,
            max_files: 4,
        },
        template_digest: digest("root-owned Kamal template"),
    })
    .unwrap_or_else(|error| panic!("installed Kamal policy: {error}"))
}

#[test]
fn repository_dockerfile_parser_and_instruction_bypasses_are_rejected() {
    for (dockerfile, reason) in [
        (
            "# syntax=docker/dockerfile:1\nFROM scratch".to_owned(),
            "syntax",
        ),
        (
            "#syntax=docker/dockerfile:1\nFROM scratch".to_owned(),
            "syntax without whitespace",
        ),
        (
            "#\tsyntax = docker/dockerfile:1\nFROM scratch".to_owned(),
            "syntax with tab and spaced equals",
        ),
        (
            "# escape = `\nFROM scratch".to_owned(),
            "escape with spaced equals",
        ),
        (
            format!(
                "# syntax=example.test/frontend@sha256:{}\nFROM scratch",
                "f".repeat(64)
            ),
            "repository syntax frontend",
        ),
        ("FROM alpine:latest".to_owned(), "mutable base"),
        (
            "FROM scratch\nADD https://example.test/x /x".to_owned(),
            "remote ADD",
        ),
        (
            "FROM scratch\nADD git@example.test:x/y.git /x".to_owned(),
            "remote Git ADD",
        ),
        (
            "FROM scratch\nADD\thttps://example.test/x /x".to_owned(),
            "ADD separated with a tab",
        ),
        (
            "FROM scratch\nRUN --mount=type=secret true".to_owned(),
            "secret mount",
        ),
        (
            "FROM scratch\nRUN --mount=type=bind,from=docker.io/library/busybox:latest,target=/mnt true"
                .to_owned(),
            "external image RUN mount",
        ),
        (
            "FROM scratch\nRUN --mount=type=cache,target=/cache true".to_owned(),
            "repository cache mount",
        ),
        (
            "FROM scratch\nVOLUME /var/lib/application".to_owned(),
            "anonymous host-backed volume",
        ),
        (
            "FROM scratch\nRUN echo \\   \ntrue".to_owned(),
            "continuation escape followed by whitespace",
        ),
        (
            "FROM scratch\nRUN echo \x01hidden".to_owned(),
            "control byte in instruction arguments",
        ),
    ] {
        assert!(
            validate_repository_dockerfile(&dockerfile).is_err(),
            "accepted {reason}"
        );
    }
}

#[test]
fn repository_dockerfile_external_sources_and_from_options_are_rejected() {
    for (dockerfile, reason) in [
        (
            "FROM scratch\nCOPY --from=alpine:latest /x /x".to_owned(),
            "external COPY",
        ),
        (
            format!(
                "FROM scratch AS source\nCOPY --from=example.test/x@sha256:{} /x /x",
                "a".repeat(64)
            ),
            "pinned external COPY",
        ),
        (
            concat!(
                "FROM scratch\n",
                "COPY \\\n",
                "# hidden from the continued instruction by the policy parser\n",
                "--from=docker.io/library/busybox:latest /bin/busybox /busybox",
            )
            .to_owned(),
            "external COPY hidden behind a continuation comment",
        ),
        (
            format!(
                "FROM --platform=linux/arm64 docker.io/library/debian@sha256:{} AS runtime",
                "a".repeat(64)
            ),
            "fixed FROM platform override",
        ),
        (
            format!(
                "FROM --platform=$BUILDPLATFORM docker.io/library/debian@sha256:{} AS runtime",
                "a".repeat(64)
            ),
            "dynamic FROM platform override",
        ),
        (
            format!(
                "FROM docker.io/library/debian@sha256:{} AS runtime unexpected",
                "a".repeat(64)
            ),
            "extra FROM grammar",
        ),
    ] {
        assert!(
            validate_repository_dockerfile(&dockerfile).is_err(),
            "accepted {reason}"
        );
    }
    assert!(
        validate_repository_dockerfile(concat!(
            "FROM scratch AS source\n",
            "FROM scratch\n",
            "COPY \\\n",
            "  --from=source \\\n",
            "  /artifact /artifact\n",
            "RUN --network=none true",
        ))
        .is_ok()
    );
}

#[test]
fn malicious_build_and_repository_execution_inputs_are_rejected() {
    assert!(serde_json::from_str::<BuildPath>("\"../secret\"").is_err());
    assert!(serde_json::from_str::<RegistryHost>("\"127.0.0.1\"").is_err());
    assert!(serde_json::from_str::<OciDigest>("\"sha256:not-a-digest\"").is_err());

    let mut input = kamal_policy_input();
    input.mounts[0].host_path = KamalHostPath::from_str("/etc")
        .unwrap_or_else(|error| panic!("outside host path fixture: {error}"));
    assert!(matches!(
        InstalledKamalPolicyV1::new(input),
        Err(BuildContractError::HostPathNotAllowlisted)
    ));
    let mut reserved_port = kamal_policy_input();
    reserved_port.ports[0].host_port = 5555;
    assert!(matches!(
        InstalledKamalPolicyV1::new(reserved_port),
        Err(BuildContractError::InvalidKamalPort)
    ));
    let mut substituted_network = kamal_policy_input();
    substituted_network.network = KamalNetworkName::from_str("repository-network")
        .unwrap_or_else(|error| panic!("substituted network fixture: {error}"));
    assert!(matches!(
        InstalledKamalPolicyV1::new(substituted_network),
        Err(BuildContractError::InvalidKamalNetwork)
    ));
    let (context, _, _) = frozen_context();
    let image = ImageBuildEvidenceV1::rootless(
        &context,
        OciDigest::from_str(&format!("sha256:{}", "e".repeat(64)))
            .unwrap_or_else(|error| panic!("registry digest: {error}")),
        OciDigest::from_str(&format!("sha256:{}", "f".repeat(64)))
            .unwrap_or_else(|error| panic!("image ID: {error}")),
        digest("substituted OCI archive"),
    )
    .unwrap_or_else(|error| panic!("image evidence: {error}"));
    let mut substituted_policy = kamal_policy_input();
    substituted_policy.installed_policy = InstalledPolicyIdentity {
        digest: digest("substituted policy"),
        version: 2,
    };
    let substituted_policy = InstalledKamalPolicyV1::new(substituted_policy)
        .unwrap_or_else(|error| panic!("substituted policy fixture: {error}"));
    assert!(matches!(
        KamalDeploymentPlanV1::generate(
            &substituted_policy,
            &context,
            &image,
            digest("sanitized diff")
        ),
        Err(BuildContractError::ContextIdentityMismatch)
    ));
}

fn kamal_policy_input() -> InstalledKamalPolicyInputV1 {
    InstalledKamalPolicyInputV1 {
        project_id: project(),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v1"),
            version: 1,
        },
        service: KamalServiceName::from_str("rimg")
            .unwrap_or_else(|error| panic!("service: {error}")),
        image: KamalImageName::from_str("mrdenai/rimg")
            .unwrap_or_else(|error| panic!("image: {error}")),
        target_host: KamalTargetHost::from_str("45.151.142.168")
            .unwrap_or_else(|error| panic!("target: {error}")),
        ssh_user: KamalSshUser::from_str("deploy")
            .unwrap_or_else(|error| panic!("SSH user: {error}")),
        ssh_port: 22,
        network: KamalNetworkName::from_str("kamal")
            .unwrap_or_else(|error| panic!("network: {error}")),
        network_alias: KamalNetworkAlias::from_str("rimg")
            .unwrap_or_else(|error| panic!("network alias: {error}")),
        run_as: KamalUnixIdentityV1 {
            uid: 10_001,
            gid: 10_001,
        },
        allowed_host_roots: vec![
            KamalHostPath::from_str("/srv/rimg").unwrap_or_else(|error| panic!("root: {error}")),
        ],
        mounts: vec![KamalMountV1 {
            host_path: KamalHostPath::from_str("/srv/rimg/data")
                .unwrap_or_else(|error| panic!("mount: {error}")),
            container_path: KamalContainerPath::from_str("/app/data")
                .unwrap_or_else(|error| panic!("container: {error}")),
            access: KamalMountAccessV1::ReadOnly,
        }],
        ports: vec![KamalPortBindingV1 {
            host_port: 8080,
            container_port: 3000,
            protocol: KamalPortProtocolV1::Tcp,
        }],
        clear_environment: vec![],
        secret_bindings: vec![],
        logging: KamalLoggingPolicyV1 {
            driver: KamalLoggingDriverV1::Local,
            max_size_bytes: 16 * 1024 * 1024,
            max_files: 4,
        },
        template_digest: digest("template"),
    }
}
