#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, ProjectManifestV2, ReleaseClass,
    },
    installed_source::{
        InstalledSourceConfigInputV1, InstalledSourceConfigV1, InstalledSourceProjectV1,
    },
    installed_workflow::InstalledWorkflowCatalogV1,
    scheduler::DurableWorkflowScheduler,
    source::{
        DeterministicSourceRepository, DurableSourceBroker, GitSourceProjectConfig,
        InstalledSourceProjectPolicy, SourceAttestationError, SourceError, SourceStore,
    },
    source_delivery::{SourceWorkflowAdmitterV1, SourceWorkflowDeliveryError},
    source_delivery_socket::{
        BoundSourceDeliverySocketV1, BrokerSourceDeliveryHandlerV1, SourceDeliveryClientError,
        SourceDeliveryClientV1, SourceDeliveryServerConfigV1, SourceDeliverySocketError,
        serve_source_delivery_connection, serve_source_delivery_until,
    },
    store::ControlStore,
};
use tempfile::tempdir;
use tokio::{net::UnixStream, sync::oneshot};

fn manifest() -> ProjectManifestV2 {
    serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
        .unwrap_or_else(|error| panic!("decode workflow manifest: {error}"))
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40))
        .unwrap_or_else(|error| panic!("commit fixture: {error}"))
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[73_u8; 32])
}

fn source_config(
    manifest: &ProjectManifestV2,
    signing_key: &SigningKey,
    auto_deploy: bool,
) -> InstalledSourceConfigV1 {
    let workflow_policy_digest = manifest
        .workflow_policy_digest()
        .unwrap_or_else(|error| panic!("workflow policy digest: {error}"));
    let project = InstalledSourceProjectV1::new(
        manifest.project_id.clone(),
        manifest.source.remote_url.clone(),
        None,
        InstalledPolicyIdentity {
            digest: workflow_policy_digest,
            version: 1,
        },
        auto_deploy,
        3,
        ReleaseClass::StatefulCompatible,
    )
    .unwrap_or_else(|error| panic!("installed source project: {error}"));
    InstalledSourceConfigV1::new(InstalledSourceConfigInputV1 {
        source_uid: 991,
        controller_uid: 992,
        controller_gid: 992,
        build_reader_gid: 993,
        max_connections: 8,
        request_timeout_ms: 2_000,
        reconcile_interval_ms: 30_000,
        attestation_ttl_ms: 120_000,
        attestation_key_id: "source-delivery-test".to_owned(),
        attestation_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        projects: vec![project],
    })
    .unwrap_or_else(|error| panic!("installed source config: {error}"))
}

fn repository(manifest: &ProjectManifestV2) -> DeterministicSourceRepository {
    let repository = DeterministicSourceRepository::default();
    let identity = GitSourceProjectConfig {
        project_id: manifest.project_id.clone(),
        remote_url: manifest.source.remote_url.clone(),
        ssh_transport: None,
    }
    .repository_identity();
    repository
        .set_repository_identity(&manifest.project_id, identity)
        .unwrap_or_else(|error| panic!("repository identity: {error}"));
    repository
}

fn broker(
    store: SourceStore,
    repository: DeterministicSourceRepository,
    policy: InstalledSourceProjectPolicy,
    signing_key: &SigningKey,
    started_at_ms: i64,
) -> DurableSourceBroker<DeterministicSourceRepository> {
    DurableSourceBroker::new(
        store,
        repository,
        "source-delivery-test",
        signing_key.clone(),
        120_000,
        vec![policy],
        started_at_ms,
    )
    .unwrap_or_else(|error| panic!("source broker: {error}"))
}

fn workflow_admitter(
    control_path: &Path,
    manifest: ProjectManifestV2,
    config: InstalledSourceConfigV1,
) -> SourceWorkflowAdmitterV1 {
    SourceWorkflowAdmitterV1::new(
        DurableWorkflowScheduler::new(
            ControlStore::open(control_path)
                .unwrap_or_else(|error| panic!("control store: {error}")),
        ),
        InstalledWorkflowCatalogV1::from_manifests([manifest])
            .unwrap_or_else(|error| panic!("workflow catalog: {error}")),
        config,
    )
    .unwrap_or_else(|error| panic!("source workflow admitter: {error}"))
}

fn protected_socket_identity(path: &Path) -> (u32, u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o2750))
        .unwrap_or_else(|error| panic!("protect socket directory: {error}"));
    let metadata =
        fs::metadata(path).unwrap_or_else(|error| panic!("socket directory metadata: {error}"));
    assert_ne!(metadata.uid(), 0, "socket contract must run as non-root");
    assert_ne!(
        metadata.gid(),
        0,
        "socket contract requires a non-root group"
    );
    (metadata.uid(), metadata.gid())
}

fn outbox_statuses(path: &Path) -> Vec<String> {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("inspect source outbox: {error}"));
    connection
        .prepare("SELECT status FROM source_outbox ORDER BY outbox_sequence")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_else(|error| panic!("source outbox statuses: {error}"))
}

#[test]
fn durable_outbox_replays_lost_ack_and_supersedes_older_pending_head() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let manifest = manifest();
    let signing_key = signing_key();
    let config = source_config(&manifest, &signing_key, true);
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .and_then(|()| {
            repository.insert_commit(&manifest.project_id, &commit('b'), Some(commit('a')))
        })
        .unwrap_or_else(|error| panic!("insert source history: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let broker = broker(
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}")),
        repository.clone(),
        config.projects[0].source_policy(),
        &signing_key,
        100,
    );
    broker
        .process_direct_push(
            &manifest.project_id,
            "delivery-a",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept first source: {error}"));
    let first = broker
        .pending_outbox(32)
        .unwrap_or_else(|error| panic!("first pending outbox: {error}"));
    assert_eq!(first.len(), 1);
    repository
        .set_remote_head(&manifest.project_id, commit('a'))
        .unwrap_or_else(|error| panic!("set same remote head: {error}"));
    broker
        .reconcile_remote_main(&manifest.project_id, 102)
        .unwrap_or_else(|error| panic!("reconcile same accepted head: {error}"));
    assert_eq!(
        broker
            .pending_outbox(32)
            .unwrap_or_else(|error| panic!("same-head outbox replay: {error}")),
        first,
        "observing one accepted head through another channel must not duplicate or corrupt it"
    );
    broker
        .process_direct_push(
            &manifest.project_id,
            "delivery-b",
            "refs/heads/main",
            Some(&commit('a')),
            commit('b'),
            103,
        )
        .unwrap_or_else(|error| panic!("accept newer source: {error}"));
    let pending = broker
        .pending_outbox(32)
        .unwrap_or_else(|error| panic!("newer pending outbox: {error}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attestation.payload.head, commit('b'));
    assert!(pending[0].outbox_sequence > first[0].outbox_sequence);

    let admitter = workflow_admitter(&directory.path().join("control.sqlite"), manifest, config);
    let created = admitter
        .admit(&pending[0], 104)
        .unwrap_or_else(|error| panic!("first scheduler admission: {error}"));
    assert!(created.created());
    let replayed = admitter
        .admit(&pending[0], 105)
        .unwrap_or_else(|error| panic!("lost-ack scheduler replay: {error}"));
    assert!(!replayed.created());
    assert_eq!(replayed.attempt().attempt_id, created.attempt().attempt_id);

    broker
        .acknowledge_outbox(
            pending[0].outbox_sequence,
            &pending[0].attestation_digest,
            106,
        )
        .unwrap_or_else(|error| panic!("acknowledge outbox: {error}"));
    broker
        .acknowledge_outbox(
            pending[0].outbox_sequence,
            &pending[0].attestation_digest,
            107,
        )
        .unwrap_or_else(|error| panic!("replay acknowledgement: {error}"));
    assert!(
        broker
            .pending_outbox(32)
            .unwrap_or_else(|error| panic!("empty pending outbox: {error}"))
            .is_empty()
    );

    assert_eq!(
        outbox_statuses(&source_path),
        vec!["superseded".to_owned(), "delivered".to_owned()]
    );
}

#[test]
fn controller_outage_and_disabled_to_enabled_policy_cannot_lose_current_head() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let manifest = manifest();
    let signing_key = signing_key();
    let disabled = source_config(&manifest, &signing_key, false);
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .and_then(|()| repository.set_remote_head(&manifest.project_id, commit('a')))
        .unwrap_or_else(|error| panic!("prepare remote head: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let first = broker(
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}")),
        repository.clone(),
        disabled.projects[0].source_policy(),
        &signing_key,
        100,
    );
    first
        .reconcile_remote_main(&manifest.project_id, 101)
        .unwrap_or_else(|error| panic!("disabled reconciliation: {error}"));
    assert!(
        first
            .pending_outbox(32)
            .unwrap_or_else(|error| panic!("disabled outbox: {error}"))
            .is_empty()
    );
    drop(first);

    let enabled = source_config(&manifest, &signing_key, true);
    let reopened = broker(
        SourceStore::open(&source_path)
            .unwrap_or_else(|error| panic!("reopen source store: {error}")),
        repository.clone(),
        enabled.projects[0].source_policy(),
        &signing_key,
        102,
    );
    reopened
        .reconcile_remote_main(&manifest.project_id, 103)
        .unwrap_or_else(|error| panic!("enabled reconciliation: {error}"));
    let pending = reopened
        .pending_outbox(32)
        .unwrap_or_else(|error| panic!("replayed current head: {error}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attestation.payload.head, commit('a'));
    assert_eq!(pending[0].source_sequence, 1);

    drop(reopened);
    let restarted = broker(
        SourceStore::open(&source_path)
            .unwrap_or_else(|error| panic!("second reopen source store: {error}")),
        repository,
        enabled.projects[0].source_policy(),
        &signing_key,
        200_000,
    );
    let after_restart = restarted
        .pending_outbox(32)
        .unwrap_or_else(|error| panic!("pending after source restart: {error}"));
    assert_eq!(after_restart, pending);

    let admitter = workflow_admitter(
        &directory.path().join("control.sqlite"),
        manifest.clone(),
        enabled,
    );
    assert!(matches!(
        admitter.admit(&after_restart[0], 200_000),
        Err(SourceWorkflowDeliveryError::Attestation(
            SourceAttestationError::Expired
        ))
    ));
    restarted
        .reconcile_remote_main(&manifest.project_id, 200_001)
        .unwrap_or_else(|error| panic!("refresh expired current head: {error}"));
    let refreshed = restarted
        .pending_outbox(32)
        .unwrap_or_else(|error| panic!("refreshed current head: {error}"));
    assert_eq!(refreshed.len(), 1);
    assert_eq!(refreshed[0].source_sequence, 2);
    assert_eq!(refreshed[0].attestation.payload.head, commit('a'));
    assert!(
        admitter
            .admit(&refreshed[0], 200_002)
            .unwrap_or_else(|error| panic!("admit refreshed current head: {error}"))
            .created()
    );
}

#[test]
fn disabling_auto_deploy_revokes_pending_delivery_before_socket_bind() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let manifest = manifest();
    let signing_key = signing_key();
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .and_then(|()| repository.set_remote_head(&manifest.project_id, commit('a')))
        .unwrap_or_else(|error| panic!("prepare source head: {error}"));
    let source_path = directory.path().join("source.sqlite");
    let enabled = source_config(&manifest, &signing_key, true);
    let first = broker(
        SourceStore::open(&source_path).unwrap_or_else(|error| panic!("source store: {error}")),
        repository.clone(),
        enabled.projects[0].source_policy(),
        &signing_key,
        100,
    );
    first
        .process_direct_push(
            &manifest.project_id,
            "enabled-source",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept enabled source: {error}"));
    assert_eq!(
        first
            .pending_outbox(1)
            .unwrap_or_else(|error| panic!("enabled outbox: {error}"))
            .len(),
        1
    );
    drop(first);

    let disabled = source_config(&manifest, &signing_key, false);
    let disabled_broker = broker(
        SourceStore::open(&source_path)
            .unwrap_or_else(|error| panic!("disabled source store: {error}")),
        repository.clone(),
        disabled.projects[0].source_policy(),
        &signing_key,
        102,
    );
    assert!(
        disabled_broker
            .pending_outbox(1)
            .unwrap_or_else(|error| panic!("revoked outbox: {error}"))
            .is_empty()
    );
    drop(disabled_broker);

    let reenabled = broker(
        SourceStore::open(&source_path)
            .unwrap_or_else(|error| panic!("re-enabled source store: {error}")),
        repository,
        enabled.projects[0].source_policy(),
        &signing_key,
        103,
    );
    reenabled
        .reconcile_remote_main(&manifest.project_id, 104)
        .unwrap_or_else(|error| panic!("re-enable current source: {error}"));
    let replayed = reenabled
        .pending_outbox(1)
        .unwrap_or_else(|error| panic!("re-enabled outbox: {error}"));
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].source_sequence, 1);
    assert_eq!(replayed[0].attestation.payload.head, commit('a'));
}

#[test]
fn scheduler_admission_rejects_signature_policy_and_repository_substitution() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let manifest = manifest();
    let signing_key = signing_key();
    let config = source_config(&manifest, &signing_key, true);
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert source commit: {error}"));
    let broker = broker(
        SourceStore::open(directory.path().join("source.sqlite"))
            .unwrap_or_else(|error| panic!("source store: {error}")),
        repository,
        config.projects[0].source_policy(),
        &signing_key,
        100,
    );
    broker
        .process_direct_push(
            &manifest.project_id,
            "signed-source",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept source: {error}"));
    let mut entry = broker
        .pending_outbox(1)
        .unwrap_or_else(|error| panic!("pending source: {error}"))
        .remove(0);
    entry.attestation.payload.head = commit('b');
    entry.attestation_digest = entry
        .attestation
        .digest()
        .unwrap_or_else(|error| panic!("tampered digest: {error}"));
    let scheduler = DurableWorkflowScheduler::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let admitter = SourceWorkflowAdmitterV1::new(
        scheduler,
        InstalledWorkflowCatalogV1::from_manifests([manifest.clone()])
            .unwrap_or_else(|error| panic!("workflow catalog: {error}")),
        config.clone(),
    )
    .unwrap_or_else(|error| panic!("source workflow admitter: {error}"));
    assert!(matches!(
        admitter.admit(&entry, 102),
        Err(SourceWorkflowDeliveryError::Attestation(
            SourceAttestationError::SignatureVerification(_)
        ))
    ));

    let mut mismatched_manifest = manifest;
    mismatched_manifest.source.remote_url =
        rdashboard::domain::RemoteUrl::from_str("https://github.com/example/substitution.git")
            .unwrap_or_else(|error| panic!("substituted remote: {error}"));
    assert!(matches!(
        SourceWorkflowAdmitterV1::new(
            DurableWorkflowScheduler::new(
                ControlStore::open(directory.path().join("other-control.sqlite"))
                    .unwrap_or_else(|error| panic!("other control store: {error}")),
            ),
            InstalledWorkflowCatalogV1::from_manifests([mismatched_manifest])
                .unwrap_or_else(|error| panic!("mismatched catalog: {error}")),
            config,
        ),
        Err(SourceWorkflowDeliveryError::InstalledPolicyMismatch(_)
            | SourceWorkflowDeliveryError::RepositoryIdentityMismatch(_))
    ));
}

#[test]
fn source_schema_v2_reopens_with_an_empty_v3_outbox() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("source.sqlite");
    drop(SourceStore::open(&path).unwrap_or_else(|error| panic!("new source store: {error}")));
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open migration fixture: {error}"));
    connection
        .execute_batch(
            "DROP TABLE source_outbox;
             UPDATE source_meta SET integer_value = 2 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade migration fixture: {error}"));
    drop(connection);

    drop(SourceStore::open(&path).unwrap_or_else(|error| panic!("migrate source store: {error}")));
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("inspect migrated source store: {error}"));
    let version: i64 = connection
        .query_row(
            "SELECT integer_value FROM source_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("source schema version: {error}"));
    let outbox_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM source_outbox", [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("source outbox count: {error}"));
    assert_eq!(version, 3);
    assert_eq!(outbox_rows, 0);
}

#[tokio::test]
async fn source_delivery_socket_authenticates_both_peers_and_round_trips_ack() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let (source_owner, controller_group) = protected_socket_identity(directory.path());

    let manifest = manifest();
    let signing_key = signing_key();
    let config = source_config(&manifest, &signing_key, true);
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert source commit: {error}"));
    let broker = broker(
        SourceStore::open(directory.path().join("source.sqlite"))
            .unwrap_or_else(|error| panic!("source store: {error}")),
        repository,
        config.projects[0].source_policy(),
        &signing_key,
        100,
    );
    broker
        .process_direct_push(
            &manifest.project_id,
            "socket-source",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept socket source: {error}"));

    let socket_path = directory.path().join("delivery.sock");
    let mut bound = BoundSourceDeliverySocketV1::bind(&socket_path, source_owner, controller_group)
        .unwrap_or_else(|error| panic!("bind delivery socket: {error}"));
    let listener = bound.take_listener();
    let handler = Arc::new(BrokerSourceDeliveryHandlerV1::system(broker.clone()));
    let server_config = SourceDeliveryServerConfigV1::new(source_owner, 4, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("source delivery server config: {error}"));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_source_delivery_until(
        listener,
        handler,
        server_config,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    let client = SourceDeliveryClientV1::new(&socket_path, source_owner, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("source delivery client: {error}"));
    let entries = client
        .pending(8)
        .await
        .unwrap_or_else(|error| panic!("pending through socket: {error}"));
    assert_eq!(entries.len(), 1);
    client
        .acknowledge(&entries[0])
        .await
        .unwrap_or_else(|error| panic!("ack through socket: {error}"));
    assert!(
        client
            .pending(8)
            .await
            .unwrap_or_else(|error| panic!("empty socket poll: {error}"))
            .is_empty()
    );

    let wrong_server = SourceDeliveryClientV1::new(
        &socket_path,
        source_owner.saturating_add(1),
        Duration::from_secs(2),
    )
    .unwrap_or_else(|error| panic!("wrong-server client: {error}"));
    assert!(matches!(
        wrong_server.pending(1).await,
        Err(SourceDeliveryClientError::UnauthorizedServer { .. })
    ));
    shutdown_tx
        .send(())
        .unwrap_or_else(|()| panic!("source delivery server already stopped"));
    server
        .await
        .unwrap_or_else(|error| panic!("source delivery server task: {error}"))
        .unwrap_or_else(|error| panic!("source delivery server: {error}"));

    let (server_stream, _client_stream) =
        UnixStream::pair().unwrap_or_else(|error| panic!("unauthorized peer socket pair: {error}"));
    let wrong_uid = source_owner.saturating_add(1);
    let error = serve_source_delivery_connection(
        server_stream,
        Arc::new(BrokerSourceDeliveryHandlerV1::system(broker)),
        &SourceDeliveryServerConfigV1::new(wrong_uid, 1, Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("wrong-UID server config: {error}")),
    )
    .await
    .expect_err("unauthorized client UID must fail before decoding");
    assert!(matches!(
        error,
        SourceDeliverySocketError::UnauthorizedPeer { .. }
    ));
}

#[test]
fn outbox_rejects_invalid_bounds_and_ack_binding() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let manifest = manifest();
    let signing_key = signing_key();
    let config = source_config(&manifest, &signing_key, true);
    let repository = repository(&manifest);
    repository
        .insert_commit(&manifest.project_id, &commit('a'), None)
        .unwrap_or_else(|error| panic!("insert source commit: {error}"));
    let broker = broker(
        SourceStore::open(directory.path().join("source.sqlite"))
            .unwrap_or_else(|error| panic!("source store: {error}")),
        repository,
        config.projects[0].source_policy(),
        &signing_key,
        100,
    );
    assert!(matches!(
        broker.pending_outbox(0),
        Err(SourceError::InvalidOutboxLimit)
    ));
    assert!(matches!(
        broker.pending_outbox(65),
        Err(SourceError::InvalidOutboxLimit)
    ));
    broker
        .process_direct_push(
            &manifest.project_id,
            "ack-binding",
            "refs/heads/main",
            None,
            commit('a'),
            101,
        )
        .unwrap_or_else(|error| panic!("accept source: {error}"));
    let entry = broker
        .pending_outbox(1)
        .unwrap_or_else(|error| panic!("pending entry: {error}"))
        .remove(0);
    assert!(matches!(
        broker.acknowledge_outbox(
            entry.outbox_sequence,
            &EvidenceDigest::sha256("substituted attestation"),
            102,
        ),
        Err(SourceError::OutboxAcknowledgementConflict)
    ));
    assert!(matches!(
        broker.acknowledge_outbox(entry.outbox_sequence, &entry.attestation_digest, 100),
        Err(SourceError::InvalidOutboxAcknowledgement)
    ));
}
