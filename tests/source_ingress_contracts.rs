#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, ProjectId, ReleaseClass, RemoteUrl,
    },
    installed_source::{
        InstalledSourceConfigInputV1, InstalledSourceConfigV1, InstalledSourceGithubWebhookV1,
        InstalledSourceProjectInputV1, InstalledSourceProjectV1, SourceWebhookSecretsV1,
    },
    source::{
        CommitRelationship, DeterministicSourceRepository, DurableSourceBroker,
        GitSourceProjectConfig, GithubWebhookAdmissionV1, InstalledSourceProjectPolicy,
        SOURCE_GITHUB_WEBHOOK_BATCH_MAX, SourceError, SourceRepository, SourceStore,
        verify_github_hmac,
    },
    source_ingress_socket::{
        BoundSourceIngressSocketV1, BrokerSourceIngressHandlerV1, SOURCE_INGRESS_BODY_MAX_BYTES,
        SOURCE_INGRESS_FRAME_MAX_BYTES, SOURCE_INGRESS_PROTOCOL_VERSION, SourceIngressClientError,
        SourceIngressClientV1, SourceIngressClockError, SourceIngressClockV1,
        SourceIngressRequestEnvelopeV1, SourceIngressRequestV1, SourceIngressServerConfigV1,
        SourceIngressSocketError, serve_source_ingress_connection, serve_source_ingress_until,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use tokio::{net::UnixStream, sync::oneshot};
use uuid::Uuid;

const WEBHOOK_SECRET: &[u8] = b"project-specific-webhook-secret";

fn project() -> ProjectId {
    ProjectId::from_str("ralert").expect("project")
}

fn remote() -> RemoteUrl {
    RemoteUrl::from_str("https://github.com/mrDenai/ralert.git").expect("remote")
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40)).expect("commit")
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[83_u8; 32])
}

fn source_config(
    signing_key: &SigningKey,
    source_uid: u32,
    ingress_uid: u32,
) -> InstalledSourceConfigV1 {
    let project_id = project();
    let remote_url = remote();
    let webhook = InstalledSourceGithubWebhookV1::new(
        &project_id,
        &remote_url,
        EvidenceDigest::sha256(WEBHOOK_SECRET),
    )
    .expect("webhook binding");
    let installed_project = InstalledSourceProjectV1::new(InstalledSourceProjectInputV1 {
        project_id,
        remote_url,
        git_ssh: None,
        github_webhook: webhook,
        installed_policy: InstalledPolicyIdentity {
            digest: EvidenceDigest::sha256("installed workflow policy"),
            version: 1,
        },
        auto_deploy: true,
        maximum_attempts: 3,
        release_class: ReleaseClass::StatefulCompatible,
    })
    .expect("installed source project");
    InstalledSourceConfigV1::new(InstalledSourceConfigInputV1 {
        source_uid,
        ingress_uid,
        ingress_gid: ingress_uid,
        controller_uid: ingress_uid.saturating_add(1),
        controller_gid: ingress_uid.saturating_add(1),
        build_reader_gid: ingress_uid.saturating_add(2),
        max_connections: 8,
        request_timeout_ms: 2_000,
        reconcile_interval_ms: 30_000,
        attestation_ttl_ms: 120_000,
        attestation_key_id: "source-ingress-test".to_owned(),
        attestation_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        projects: vec![installed_project],
    })
    .expect("installed source config")
}

fn repository() -> DeterministicSourceRepository {
    let repository = DeterministicSourceRepository::default();
    let identity = GitSourceProjectConfig {
        project_id: project(),
        remote_url: remote(),
        ssh_transport: None,
    }
    .repository_identity();
    repository
        .set_repository_identity(&project(), identity)
        .expect("repository identity");
    repository
}

fn webhook_body(head: &GitCommitId, repository: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "ref": "refs/heads/main",
        "after": head.as_str(),
        "repository": {"full_name": repository}
    }))
    .expect("webhook body")
}

fn github_signature(secret: &[u8], body: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if secret.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        normalized[..secret.len()].copy_from_slice(secret);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for ((inner, outer), byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(normalized)
    {
        *inner ^= byte;
        *outer ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(body);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    let digest = outer.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256={encoded}")
}

#[test]
fn github_hmac_matches_the_published_sha256_example() {
    verify_github_hmac(
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        b"It's a Secret to Everybody",
        b"Hello, World!",
    )
    .expect("known GitHub webhook HMAC");
}

fn broker<R: SourceRepository>(
    path: &Path,
    repository: R,
    config: &InstalledSourceConfigV1,
    signing_key: &SigningKey,
    started_at_ms: i64,
) -> DurableSourceBroker<R> {
    DurableSourceBroker::new(
        SourceStore::open(path).expect("source store"),
        repository,
        config.attestation_key_id.clone(),
        signing_key.clone(),
        config.attestation_ttl_ms().expect("attestation TTL"),
        config.source_policies(),
        started_at_ms,
    )
    .expect("source broker")
}

#[derive(Clone, Debug)]
struct BlockingFetchRepository {
    inner: DeterministicSourceRepository,
    next_fetch: SharedFetchGate,
    fetches: Arc<AtomicUsize>,
    priority_generation: Arc<AtomicU64>,
}

type FetchGate = (mpsc::Sender<()>, mpsc::Receiver<()>);
type SharedFetchGate = Arc<Mutex<Option<FetchGate>>>;

impl BlockingFetchRepository {
    fn new(inner: DeterministicSourceRepository) -> Self {
        Self {
            inner,
            next_fetch: Arc::new(Mutex::new(None)),
            fetches: Arc::new(AtomicUsize::new(0)),
            priority_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    fn block_next_fetch(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *self.next_fetch.lock().expect("fetch gate") = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }
}

impl SourceRepository for BlockingFetchRepository {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError> {
        self.inner.repository_identity(project_id)
    }

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        if let Some((entered, release)) = self.next_fetch.lock().expect("fetch gate").take() {
            entered
                .send(())
                .map_err(|_| SourceError::Repository("fetch observer disappeared".to_owned()))?;
            release
                .recv()
                .map_err(|_| SourceError::Repository("fetch releaser disappeared".to_owned()))?;
        }
        self.inner.fetch_remote_main(project_id)
    }

    fn fetch_remote_main_reconciliation(
        &self,
        project_id: &ProjectId,
    ) -> Result<GitCommitId, SourceError> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let priority_generation = self.priority_generation.load(Ordering::Acquire);
        if let Some((entered, release)) = self.next_fetch.lock().expect("fetch gate").take() {
            entered
                .send(())
                .map_err(|_| SourceError::Repository("fetch observer disappeared".to_owned()))?;
            loop {
                match release.recv_timeout(Duration::from_millis(10)) {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Timeout)
                        if self.priority_generation.load(Ordering::Acquire)
                            != priority_generation =>
                    {
                        return Err(SourceError::ReconciliationDeferred);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(SourceError::Repository(
                            "fetch releaser disappeared".to_owned(),
                        ));
                    }
                }
            }
        }
        self.inner.fetch_remote_main(project_id)
    }

    fn notify_priority_fetch(&self, project_id: &ProjectId) -> Result<(), SourceError> {
        self.inner.repository_identity(project_id)?;
        self.priority_generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
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
        self.inner
            .compare_and_swap_accepted_head(project_id, expected, candidate)
    }
}

#[test]
fn full_project_webhook_burst_reuses_one_remote_fetch() {
    let directory = tempdir().expect("temp dir");
    let signing_key = signing_key();
    let config = source_config(&signing_key, 991, 992);
    let inner = repository();
    inner
        .insert_commit(&project(), &commit('a'), None)
        .expect("insert commit");
    inner
        .set_remote_head(&project(), commit('a'))
        .expect("remote head");
    let repository = BlockingFetchRepository::new(inner);
    let broker = broker(
        &directory.path().join("source.sqlite"),
        repository.clone(),
        &config,
        &signing_key,
        100,
    );
    let body = webhook_body(&commit('a'), "mrDenai/ralert");
    let signature = github_signature(WEBHOOK_SECRET, &body);
    for index in 0..SOURCE_GITHUB_WEBHOOK_BATCH_MAX {
        broker
            .enqueue_github_push(
                &project(),
                &format!("burst-{index}"),
                &signature,
                WEBHOOK_SECRET,
                &body,
                101,
            )
            .expect("queue project burst");
    }
    assert!(matches!(
        broker.enqueue_github_push(
            &project(),
            "burst-overflow",
            &signature,
            WEBHOOK_SECRET,
            &body,
            101,
        ),
        Err(SourceError::WebhookQueueFull)
    ));

    let drained = broker
        .process_pending_github_pushes(&project(), SOURCE_GITHUB_WEBHOOK_BATCH_MAX, 102)
        .expect("drain project burst");
    assert_eq!(drained.completed, SOURCE_GITHUB_WEBHOOK_BATCH_MAX);
    assert_eq!(repository.fetch_count(), 1);
}

#[test]
fn restart_retires_webhook_wakeups_for_a_removed_project() {
    let directory = tempdir().expect("temp dir");
    let database = directory.path().join("source.sqlite");
    let signing_key = signing_key();
    let config = source_config(&signing_key, 991, 992);
    let repository = repository();
    let removed_project = ProjectId::from_str("rimg").expect("removed project");
    let removed_remote =
        RemoteUrl::from_str("https://github.com/mrDenai/rimg.git").expect("removed remote");
    let removed_identity = GitSourceProjectConfig {
        project_id: removed_project.clone(),
        remote_url: removed_remote,
        ssh_transport: None,
    }
    .repository_identity();
    repository
        .set_repository_identity(&removed_project, removed_identity.clone())
        .expect("removed repository identity");
    let mut initial_policies = config.source_policies();
    initial_policies.push(InstalledSourceProjectPolicy {
        project_id: removed_project.clone(),
        repository_identity: removed_identity,
        github_repository: "mrDenai/rimg".to_owned(),
        installed_policy: InstalledPolicyIdentity {
            digest: EvidenceDigest::sha256("removed project policy"),
            version: 1,
        },
        auto_deploy: false,
        maximum_attempts: 3,
        release_class: ReleaseClass::CodeOnlyCompatible,
    });
    {
        let initial = DurableSourceBroker::new(
            SourceStore::open(&database).expect("source store"),
            repository.clone(),
            config.attestation_key_id.clone(),
            signing_key.clone(),
            config.attestation_ttl_ms().expect("attestation TTL"),
            initial_policies,
            100,
        )
        .expect("initial broker");
        let body = webhook_body(&commit('a'), "mrDenai/rimg");
        initial
            .enqueue_github_push(
                &removed_project,
                "removed-project-delivery",
                &github_signature(WEBHOOK_SECRET, &body),
                WEBHOOK_SECRET,
                &body,
                101,
            )
            .expect("queue removed project webhook");
    }

    let _restarted = broker(&database, repository, &config, &signing_key, 102);
    let connection = rusqlite::Connection::open(&database).expect("inspect source database");
    let wakeups: i64 = connection
        .query_row("SELECT COUNT(*) FROM source_github_wakeups", [], |row| {
            row.get(0)
        })
        .expect("count webhook wake-ups");
    assert_eq!(wakeups, 0);
}

#[test]
fn webhook_acceptance_preempts_a_held_periodic_fetch() {
    let directory = tempdir().expect("temp dir");
    let signing_key = signing_key();
    let config = source_config(&signing_key, 991, 992);
    let inner = repository();
    inner
        .insert_commit(&project(), &commit('a'), None)
        .expect("insert commit");
    inner
        .set_remote_head(&project(), commit('a'))
        .expect("remote head");
    let repository = BlockingFetchRepository::new(inner);
    let broker = Arc::new(broker(
        &directory.path().join("source.sqlite"),
        repository.clone(),
        &config,
        &signing_key,
        100,
    ));
    let (entered, _release) = repository.block_next_fetch();
    let reconcile_broker = Arc::clone(&broker);
    let reconcile =
        std::thread::spawn(move || reconcile_broker.reconcile_remote_main(&project(), 101));
    entered
        .recv_timeout(Duration::from_secs(1))
        .expect("reconcile entered fetch");

    let started = Instant::now();
    let body = webhook_body(&commit('a'), "mrDenai/ralert");
    let signature = github_signature(WEBHOOK_SECRET, &body);
    let admission_broker = Arc::clone(&broker);
    let (admitted_tx, admitted_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = admission_broker.enqueue_github_push(
            &project(),
            "delivery-held-reconcile",
            &signature,
            WEBHOOK_SECRET,
            &body,
            102,
        );
        let _ = admitted_tx.send(result);
    });
    let admission = admitted_rx
        .recv_timeout(Duration::from_millis(250))
        .expect("durable webhook acknowledgement must not wait for reconcile")
        .expect("enqueue webhook");
    assert_eq!(
        admission,
        GithubWebhookAdmissionV1::Queued { wakeup_sequence: 1 }
    );
    assert!(matches!(
        reconcile.join().expect("reconcile thread"),
        Err(SourceError::ReconciliationDeferred)
    ));

    let drained = broker
        .process_pending_github_pushes(&project(), 32, 103)
        .expect("drain webhook");
    assert_eq!(drained.completed, 1);
    assert!(!drained.deferred_until_remote_catches_up);
    assert_eq!(
        broker
            .store()
            .snapshot(&project())
            .expect("accepted source snapshot")
            .head,
        Some(commit('a'))
    );
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(
        broker
            .pending_github_wakeups(&project(), 32)
            .expect("pending wake-ups")
            .is_empty()
    );
}

#[test]
fn ingress_frame_preserves_the_maximum_raw_body_without_json_byte_array_expansion() {
    let raw_body = vec![b'x'; SOURCE_INGRESS_BODY_MAX_BYTES];
    let envelope = SourceIngressRequestEnvelopeV1 {
        version: SOURCE_INGRESS_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        request: SourceIngressRequestV1::GithubPush {
            project_id: project(),
            delivery_id: "maximum-body".to_owned(),
            signature_header:
                "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            raw_body: raw_body.clone(),
        },
    };
    let encoded = rdashboard::protocol::encode_frame(&envelope, SOURCE_INGRESS_FRAME_MAX_BYTES)
        .expect("maximum body frame");
    let decoded: SourceIngressRequestEnvelopeV1 =
        rdashboard::protocol::decode_single_frame(&encoded, SOURCE_INGRESS_FRAME_MAX_BYTES)
            .expect("decode maximum body frame");
    let SourceIngressRequestV1::GithubPush {
        raw_body: decoded_body,
        ..
    } = decoded.request
    else {
        panic!("decoded request kind");
    };
    assert_eq!(decoded_body, raw_body);
}

fn linear_repository() -> DeterministicSourceRepository {
    let repository = repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .expect("insert a");
    repository
        .insert_commit(&project(), &commit('b'), Some(commit('a')))
        .expect("insert b");
    repository
        .insert_commit(&project(), &commit('c'), Some(commit('b')))
        .expect("insert c");
    repository
}

fn enqueue_webhook<R: SourceRepository>(
    broker: &DurableSourceBroker<R>,
    delivery_id: &str,
    head: &GitCommitId,
    repository_name: &str,
    received_at_ms: i64,
) -> Result<GithubWebhookAdmissionV1, SourceError> {
    let body = webhook_body(head, repository_name);
    broker.enqueue_github_push(
        &project(),
        delivery_id,
        &github_signature(WEBHOOK_SECRET, &body),
        WEBHOOK_SECRET,
        &body,
        received_at_ms,
    )
}

fn assert_webhook_queue_excludes_secret_material(connection: &rusqlite::Connection) {
    let columns = connection
        .prepare("PRAGMA table_info(source_github_wakeups)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()
        })
        .expect("webhook queue columns");
    assert!(!columns.iter().any(|column| column == "raw_body"));
    assert!(!columns.iter().any(|column| column == "signature_header"));
}

#[test]
fn webhook_restart_replays_reordered_events_and_preserves_retained_delivery_binding() {
    let directory = tempdir().expect("temp dir");
    let database = directory.path().join("source.sqlite");
    let signing_key = signing_key();
    let config = source_config(&signing_key, 991, 992);
    let repository = linear_repository();
    repository
        .set_remote_head(&project(), commit('c'))
        .expect("remote c");
    {
        let first = broker(&database, repository.clone(), &config, &signing_key, 100);
        for (delivery, head, received_at_ms) in [
            ("delivery-c", commit('c'), 101),
            ("delivery-a-late", commit('a'), 102),
        ] {
            enqueue_webhook(&first, delivery, &head, "mrDenai/ralert", received_at_ms)
                .expect("queue webhook");
        }
    }

    let restarted = broker(&database, repository.clone(), &config, &signing_key, 103);
    let drained = restarted
        .process_pending_github_pushes(&project(), 32, 104)
        .expect("replay webhook queue");
    assert_eq!(drained.completed, 2);
    assert_eq!(
        restarted
            .store()
            .snapshot(&project())
            .expect("source snapshot")
            .head,
        Some(commit('c'))
    );
    assert_eq!(
        enqueue_webhook(
            &restarted,
            "delivery-c",
            &commit('c'),
            "mrDenai/ralert",
            105,
        )
        .expect("duplicate completed webhook"),
        GithubWebhookAdmissionV1::Duplicate {
            wakeup_sequence: 1,
            completed: true,
        }
    );

    assert!(matches!(
        enqueue_webhook(
            &restarted,
            "delivery-c",
            &commit('b'),
            "mrDenai/ralert",
            106,
        ),
        Err(SourceError::DeliveryConflict)
    ));

    let connection = rusqlite::Connection::open(&database).expect("inspect source database");
    connection
        .execute(
            "DELETE FROM source_github_wakeups
             WHERE project_id = ?1 AND delivery_id = 'delivery-c'",
            [project().as_str()],
        )
        .expect("simulate settled wake-up retention");
    assert!(matches!(
        enqueue_webhook(
            &restarted,
            "delivery-c",
            &commit('b'),
            "mrDenai/ralert",
            107,
        ),
        Err(SourceError::DeliveryConflict)
    ));
    assert!(matches!(
        enqueue_webhook(
            &restarted,
            "delivery-c",
            &commit('c'),
            "mrDenai/ralert",
            107,
        )
        .expect("retained delivery restores a matching wake-up"),
        GithubWebhookAdmissionV1::Queued { .. }
    ));
    assert_eq!(
        restarted
            .process_pending_github_pushes(&project(), 32, 108)
            .expect("replay retained delivery")
            .completed,
        1
    );

    assert_webhook_queue_excludes_secret_material(&connection);
}

#[test]
fn webhook_rejects_substitution_and_waits_for_remote_visibility() {
    let directory = tempdir().expect("temp dir");
    let signing_key = signing_key();
    let config = source_config(&signing_key, 991, 992);
    let repository = linear_repository();
    repository
        .set_remote_head(&project(), commit('c'))
        .expect("remote c");
    let broker = broker(
        &directory.path().join("source.sqlite"),
        repository.clone(),
        &config,
        &signing_key,
        100,
    );
    broker
        .reconcile_remote_main(&project(), 101)
        .expect("establish canonical head");

    assert!(matches!(
        enqueue_webhook(
            &broker,
            "delivery-substitution",
            &commit('c'),
            "mrDenai/other",
            102,
        ),
        Err(SourceError::GithubRepositoryMismatch)
    ));
    let body_c = webhook_body(&commit('c'), "mrDenai/ralert");
    assert!(matches!(
        broker.enqueue_github_push(
            &project(),
            "delivery-bad-signature",
            &github_signature(b"different webhook secret", &body_c),
            WEBHOOK_SECRET,
            &body_c,
            103,
        ),
        Err(SourceError::InvalidWebhookSignature)
    ));

    repository
        .set_remote_head(&project(), commit('b'))
        .expect("remote b");
    enqueue_webhook(
        &broker,
        "delivery-before-visible",
        &commit('c'),
        "mrDenai/ralert",
        104,
    )
    .expect("queue future webhook");
    let deferred = broker
        .process_pending_github_pushes(&project(), 32, 105)
        .expect("defer future webhook");
    assert_eq!(deferred.completed, 0);
    assert!(deferred.deferred_until_remote_catches_up);
    repository
        .set_remote_head(&project(), commit('c'))
        .expect("remote catches up");
    assert_eq!(
        broker
            .process_pending_github_pushes(&project(), 32, 106)
            .expect("process visible webhook")
            .completed,
        1
    );
}

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl SourceIngressClockV1 for FixedClock {
    fn now_ms(&self) -> Result<i64, SourceIngressClockError> {
        Ok(self.0)
    }
}

fn protected_socket_identity(path: &Path) -> (u32, u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o2750))
        .expect("protect socket directory");
    let metadata = fs::metadata(path).expect("socket directory metadata");
    assert_ne!(metadata.uid(), 0, "socket contract must run as non-root");
    assert_ne!(
        metadata.gid(),
        0,
        "socket contract requires a non-root group"
    );
    (metadata.uid(), metadata.gid())
}

type TestBroker = DurableSourceBroker<DeterministicSourceRepository>;

fn socket_fixture(
    directory: &Path,
    source_owner: u32,
    ingress_uid: u32,
) -> (
    InstalledSourceConfigV1,
    Arc<TestBroker>,
    Arc<SourceWebhookSecretsV1>,
) {
    let signing_key = signing_key();
    let config = source_config(&signing_key, source_owner, ingress_uid);
    let repository = repository();
    repository
        .insert_commit(&project(), &commit('a'), None)
        .expect("insert a");
    repository
        .set_remote_head(&project(), commit('a'))
        .expect("remote a");
    let broker = Arc::new(broker(
        &directory.join("source.sqlite"),
        repository,
        &config,
        &signing_key,
        100,
    ));
    let secrets = Arc::new(
        SourceWebhookSecretsV1::from_project_secrets(
            &config,
            BTreeMap::from([(project(), WEBHOOK_SECRET.to_vec())]),
        )
        .expect("webhook secrets"),
    );
    (config, broker, secrets)
}

async fn assert_oversized_body_is_rejected(client: &SourceIngressClientV1) {
    let oversized = vec![b'x'; SOURCE_INGRESS_BODY_MAX_BYTES + 1];
    assert!(matches!(
        client
            .github_push(
                project(),
                "oversized".to_owned(),
                "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                oversized,
            )
            .await,
        Err(SourceIngressClientError::InvalidRequest)
    ));
}

#[tokio::test]
async fn ingress_socket_authenticates_peers_and_preserves_exact_webhook_bytes() {
    let directory = tempdir().expect("temp dir");
    let (source_owner, ingress_group) = protected_socket_identity(directory.path());
    let ingress_uid = source_owner.saturating_add(1);
    let (config, broker, secrets) = socket_fixture(directory.path(), source_owner, ingress_uid);

    let socket_path = directory.path().join("ingress.sock");
    let mut bound = BoundSourceIngressSocketV1::bind(&socket_path, source_owner, ingress_group)
        .expect("bind ingress socket");
    let listener = bound.take_listener();
    let handler = Arc::new(BrokerSourceIngressHandlerV1::new(
        ArcBroker(Arc::clone(&broker)),
        secrets,
        FixedClock(101),
    ));
    let server_config = SourceIngressServerConfigV1::new(source_owner, 4, Duration::from_secs(2))
        .expect("server config");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_source_ingress_until(
        listener,
        handler,
        server_config,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    let client = SourceIngressClientV1::new(&socket_path, source_owner, Duration::from_secs(2))
        .expect("ingress client");
    let body = webhook_body(&commit('a'), "mrDenai/ralert");
    assert_eq!(
        client
            .github_push(
                project(),
                "socket-delivery".to_owned(),
                github_signature(WEBHOOK_SECRET, &body),
                body,
            )
            .await
            .expect("submit through socket"),
        GithubWebhookAdmissionV1::Queued { wakeup_sequence: 1 }
    );
    assert_eq!(
        broker
            .pending_github_wakeups(&project(), 32)
            .expect("pending wakeups")
            .len(),
        1
    );

    let wrong_server = SourceIngressClientV1::new(
        &socket_path,
        source_owner.saturating_add(1),
        Duration::from_secs(2),
    )
    .expect("wrong server client");
    let body = webhook_body(&commit('a'), "mrDenai/ralert");
    assert!(matches!(
        wrong_server
            .github_push(
                project(),
                "wrong-server".to_owned(),
                github_signature(WEBHOOK_SECRET, &body),
                body,
            )
            .await,
        Err(SourceIngressClientError::UnauthorizedServer { .. })
    ));
    assert_oversized_body_is_rejected(&client).await;

    let _ = shutdown_tx.send(());
    server.await.expect("server task").expect("server result");
    drop(bound);

    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let unauthorized_config =
        SourceIngressServerConfigV1::new(source_owner.saturating_add(1), 1, Duration::from_secs(1))
            .expect("unauthorized config");
    let unauthorized_handler = Arc::new(BrokerSourceIngressHandlerV1::new(
        ArcBroker(broker),
        Arc::new(
            SourceWebhookSecretsV1::from_project_secrets(
                &config,
                BTreeMap::from([(project(), WEBHOOK_SECRET.to_vec())]),
            )
            .expect("webhook secrets"),
        ),
        FixedClock(102),
    ));
    let unauthorized =
        serve_source_ingress_connection(server_stream, unauthorized_handler, &unauthorized_config)
            .await;
    drop(client_stream);
    assert!(matches!(
        unauthorized,
        Err(SourceIngressSocketError::UnauthorizedPeer { .. })
    ));
}

#[derive(Clone, Debug)]
struct ArcBroker<R: SourceRepository>(Arc<DurableSourceBroker<R>>);

impl<R: SourceRepository> rdashboard::source_ingress_socket::GithubWebhookAcceptorV1
    for ArcBroker<R>
{
    fn enqueue_github_push(
        &self,
        project_id: &ProjectId,
        delivery_id: &str,
        signature_header: &str,
        webhook_secret: &[u8],
        raw_body: &[u8],
        received_at_ms: i64,
    ) -> Result<GithubWebhookAdmissionV1, SourceError> {
        self.0.enqueue_github_push(
            project_id,
            delivery_id,
            signature_header,
            webhook_secret,
            raw_body,
            received_at_ms,
        )
    }
}
