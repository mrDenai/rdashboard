use std::str::FromStr as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    authorization::{
        ActionGrantIssueInputV1, ActionGrantRoleV1, ActionGrantSignerV1,
        ActionGrantVerificationKeyV1, ActionGrantVerifierV1, AuthenticatedActionGrantV1,
    },
    domain::{EvidenceDigest, GitCommitId, OperationKind, ProjectId, ReleaseClass},
    executor_intent::{
        EXECUTOR_INTENT_MAX_TTL_MS, ExecutorIntentConsequenceV1, ExecutorIntentError,
        ExecutorIntentExpectedBindingV1, ExecutorIntentIssueInputV1, ExecutorIntentRequiredRoleV1,
        ExecutorIntentSignerV1, ExecutorIntentVerificationKeyV1, ExecutorIntentVerifierV1,
        SignedExecutorIntentV1, inspect_unverified_executor_intent,
    },
    store::{ActionGrantConsumptionV1, ExecutorIntentPersistenceV1, SecurityStore, StoreError},
};
use tempfile::tempdir;
use uuid::Uuid;

const ISSUER: &str = "rdashboard-executor";
const AUDIENCE: &str = "rdashboard-authorizer";
const KEY_ID: &str = "executor-intent-2026-01";

struct Fixture {
    signer: ExecutorIntentSignerV1,
    signing_key: SigningKey,
    input: ExecutorIntentIssueInputV1,
    expected: ExecutorIntentExpectedBindingV1,
}

struct GrantAuthority {
    signer: ActionGrantSignerV1,
    verifier: ActionGrantVerifierV1,
}

fn digest(value: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(value)
}

fn project(value: &str) -> ProjectId {
    ProjectId::from_str(value).unwrap_or_else(|error| panic!("project fixture: {error}"))
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40))
        .unwrap_or_else(|error| panic!("commit fixture: {error}"))
}

fn fixture() -> Fixture {
    let signing_key = SigningKey::from_bytes(&[51_u8; 32]);
    let input = ExecutorIntentIssueInputV1 {
        issued_at_ms: 10_000,
        not_before_ms: 10_000,
        expires_at_ms: 250_000,
        intent_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        project_id: project("rimg"),
        operation_kind: OperationKind::Deploy,
        target_commit: Some(commit('a')),
        proposed_release_class: Some(ReleaseClass::StatefulCompatible),
        effective_release_class: Some(ReleaseClass::StatefulBreaking),
        installed_policy_digest: digest("installed policy"),
        source_attestation_digest: Some(digest("source attestation")),
        source_sequence: Some(17),
        release_bundle_digest: Some(digest("candidate release")),
        build_attestation_digest: Some(digest("build attestation")),
        migration_id: Some("20260715_add_generation".to_owned()),
        previous_release_bundle_digest: Some(digest("previous release")),
    };
    let expected = ExecutorIntentExpectedBindingV1 {
        request_id: input.request_id,
        project_id: input.project_id.clone(),
        operation_kind: input.operation_kind,
        target_commit: input.target_commit.clone(),
        installed_policy_digest: input.installed_policy_digest.clone(),
    };
    let signer = ExecutorIntentSignerV1::new(ISSUER, AUDIENCE, KEY_ID, 7, signing_key.clone())
        .unwrap_or_else(|error| panic!("intent signer: {error}"));
    Fixture {
        signer,
        signing_key,
        input,
        expected,
    }
}

fn verification_key(
    signing_key: &SigningKey,
    epoch: u64,
    active_from_ms: i64,
    signing_retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
) -> ExecutorIntentVerificationKeyV1 {
    ExecutorIntentVerificationKeyV1::new(
        KEY_ID,
        epoch,
        signing_key.verifying_key(),
        active_from_ms,
        signing_retired_at_ms,
        verify_until_ms,
        revoked_at_ms,
    )
    .unwrap_or_else(|error| panic!("intent verification key: {error}"))
}

fn verifier(signing_key: &SigningKey, minimum_epoch: u64) -> ExecutorIntentVerifierV1 {
    ExecutorIntentVerifierV1::new(
        ISSUER,
        AUDIENCE,
        minimum_epoch,
        [verification_key(signing_key, 7, 9_000, None, None, None)],
    )
    .unwrap_or_else(|error| panic!("intent verifier: {error}"))
}

fn grant_authority() -> GrantAuthority {
    let signing_key = SigningKey::from_bytes(&[61_u8; 32]);
    let signer = ActionGrantSignerV1::new(
        "https://actions.dev.4u.ge",
        "rdashboard-executor",
        "authorizer-2026-01",
        9,
        signing_key.clone(),
    )
    .unwrap_or_else(|error| panic!("grant signer: {error}"));
    let key = ActionGrantVerificationKeyV1::new(
        "authorizer-2026-01",
        9,
        signing_key.verifying_key(),
        10_000,
        None,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("grant verification key: {error}"));
    let verifier =
        ActionGrantVerifierV1::new("https://actions.dev.4u.ge", "rdashboard-executor", 9, [key])
            .unwrap_or_else(|error| panic!("grant verifier: {error}"));
    GrantAuthority { signer, verifier }
}

fn grant_input(
    intent: &SignedExecutorIntentV1,
    role: ActionGrantRoleV1,
) -> ActionGrantIssueInputV1 {
    ActionGrantIssueInputV1 {
        issued_at_ms: 11_000,
        not_before_ms: 11_000,
        expires_at_ms: 120_000,
        nonce: Uuid::new_v4(),
        actor_id: Uuid::new_v4(),
        role,
        lease_id: Uuid::new_v4(),
        lease_generation: 4,
        intent_id: intent.claims().intent_id,
        intent_digest: intent.digest().clone(),
        installed_policy_digest: intent.claims().installed_policy_digest.clone(),
        request_id: intent.claims().request_id,
    }
}

fn authenticate_grant(
    authority: &GrantAuthority,
    input: &ActionGrantIssueInputV1,
) -> AuthenticatedActionGrantV1 {
    let token = authority
        .signer
        .issue(input)
        .unwrap_or_else(|error| panic!("issue action grant: {error}"));
    authority
        .verifier
        .authenticate_for_persisted_intent(&token, 11_500)
        .unwrap_or_else(|error| panic!("authenticate action grant: {error}"))
}

fn assert_accepted_candidate_binding(security: &SecurityStore, input: &ExecutorIntentIssueInputV1) {
    let accepted = security
        .accepted_mutations()
        .unwrap_or_else(|error| panic!("load accepted mutation: {error}"));
    assert_eq!(accepted.len(), 1);
    assert_eq!(
        accepted[0].release_bundle_digest,
        input.release_bundle_digest
    );
    assert_eq!(
        accepted[0].build_attestation_digest,
        input.build_attestation_digest
    );
}

fn assert_consumed_intent_state(path: &std::path::Path, intent_id: Uuid) {
    let inspected = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("inspect security store: {error}"));
    let (state, grants): (String, i64) = inspected
        .query_row(
            "SELECT i.state, (SELECT COUNT(*) FROM executor_action_grants)
             FROM executor_operation_intents AS i WHERE i.intent_id = ?1",
            [intent_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect atomic consumption: {error}"));
    assert_eq!((state.as_str(), grants), ("consumed", 1));
}

#[test]
fn deterministic_signed_intent_round_trip_derives_destructive_consequences() {
    let primary_fixture = fixture();
    let signed = primary_fixture
        .signer
        .issue(&primary_fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let verified = verifier(&primary_fixture.signing_key, 7)
        .verify_bound(signed.compact(), &primary_fixture.expected, 10_500)
        .unwrap_or_else(|error| panic!("verify intent: {error}"));
    let inspected = inspect_unverified_executor_intent(signed.compact())
        .unwrap_or_else(|error| panic!("inspect intent for presentation: {error}"));
    assert_eq!(verified.digest(), signed.digest());
    assert_eq!(verified.claims(), signed.claims());
    assert_eq!(inspected, *signed.claims());
    assert_eq!(
        verified.claims().minimum_role,
        ExecutorIntentRequiredRoleV1::Admin
    );
    assert_eq!(
        verified.claims().consequences,
        vec![
            ExecutorIntentConsequenceV1::CodeDeployment,
            ExecutorIntentConsequenceV1::VerifiedBackupRequired,
            ExecutorIntentConsequenceV1::ApplicationWriteDrain,
            ExecutorIntentConsequenceV1::SchemaMigration,
            ExecutorIntentConsequenceV1::AutomaticRollbackProhibited,
            ExecutorIntentConsequenceV1::DataRestoreIsManual,
        ]
    );
    assert_eq!(
        signed.compact(),
        primary_fixture
            .signer
            .issue(&primary_fixture.input)
            .unwrap_or_else(|error| panic!("repeat intent: {error}"))
            .compact()
    );
}

#[test]
fn request_project_operation_target_and_policy_substitution_fail_closed() {
    let fixture = fixture();
    let signed = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let verifier = verifier(&fixture.signing_key, 7);

    let mut expected = fixture.expected.clone();
    expected.request_id = Uuid::new_v4();
    assert!(matches!(
        verifier.verify_bound(signed.compact(), &expected, 10_500),
        Err(ExecutorIntentError::BindingMismatch)
    ));

    let mut expected = fixture.expected.clone();
    expected.project_id = project("other");
    assert!(matches!(
        verifier.verify_bound(signed.compact(), &expected, 10_500),
        Err(ExecutorIntentError::BindingMismatch)
    ));

    let mut expected = fixture.expected.clone();
    expected.target_commit = Some(commit('b'));
    assert!(matches!(
        verifier.verify_bound(signed.compact(), &expected, 10_500),
        Err(ExecutorIntentError::BindingMismatch)
    ));

    let mut expected = fixture.expected;
    expected.installed_policy_digest = digest("substituted policy");
    assert!(matches!(
        verifier.verify_bound(signed.compact(), &expected, 10_500),
        Err(ExecutorIntentError::BindingMismatch)
    ));
}

#[test]
fn malformed_lifetime_source_migration_and_operation_combinations_are_not_signed() {
    let mut lifetime_fixture = fixture();
    lifetime_fixture.input.expires_at_ms =
        lifetime_fixture.input.issued_at_ms + EXECUTOR_INTENT_MAX_TTL_MS + 1;
    assert!(matches!(
        lifetime_fixture.signer.issue(&lifetime_fixture.input),
        Err(ExecutorIntentError::InvalidLifetime)
    ));

    let mut source_fixture = fixture();
    source_fixture.input.source_sequence = None;
    assert!(matches!(
        source_fixture.signer.issue(&source_fixture.input),
        Err(ExecutorIntentError::InvalidSourceAuthority)
    ));

    let mut migration_fixture = fixture();
    migration_fixture.input.migration_id = None;
    assert!(matches!(
        migration_fixture.signer.issue(&migration_fixture.input),
        Err(ExecutorIntentError::InvalidMigrationId)
    ));

    let mut operation_fixture = fixture();
    operation_fixture.input.effective_release_class = Some(ReleaseClass::Rollback);
    assert!(matches!(
        operation_fixture.signer.issue(&operation_fixture.input),
        Err(ExecutorIntentError::OperationMismatch)
    ));
}

#[test]
fn compact_token_canonicality_signature_and_lifetime_edges_are_enforced() {
    let fixture = fixture();
    let signed = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let parts = signed.compact().split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 2);
    let mut payload = URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap_or_else(|error| panic!("payload base64: {error}"));
    payload.push(0);
    let trailing = format!("{}.{}", URL_SAFE_NO_PAD.encode(payload), parts[1]);
    assert!(matches!(
        verifier(&fixture.signing_key, 7).verify(&trailing, 10_500),
        Err(ExecutorIntentError::NonCanonicalPayload)
    ));

    let mut signature = URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap_or_else(|error| panic!("signature base64: {error}"));
    signature[0] ^= 1;
    let tampered = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(signature));
    assert!(matches!(
        verifier(&fixture.signing_key, 7).verify(&tampered, 10_500),
        Err(ExecutorIntentError::SignatureVerification(_))
    ));
    assert!(matches!(
        verifier(&fixture.signing_key, 7)
            .verify(signed.compact(), fixture.input.not_before_ms - 1,),
        Err(ExecutorIntentError::NotYetValid)
    ));
    assert!(matches!(
        verifier(&fixture.signing_key, 7).verify(signed.compact(), fixture.input.expires_at_ms),
        Err(ExecutorIntentError::Expired)
    ));
}

#[test]
fn key_epoch_retirement_and_revocation_are_explicit() {
    let fixture = fixture();
    let signed = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    assert!(matches!(
        verifier(&fixture.signing_key, 8).verify(signed.compact(), 10_500),
        Err(ExecutorIntentError::KeyEpochRejected)
    ));

    let overlap = ExecutorIntentVerifierV1::new(
        ISSUER,
        AUDIENCE,
        7,
        [verification_key(
            &fixture.signing_key,
            7,
            9_000,
            Some(20_000),
            Some(30_000),
            None,
        )],
    )
    .unwrap_or_else(|error| panic!("overlap verifier: {error}"));
    overlap
        .verify(signed.compact(), 25_000)
        .unwrap_or_else(|error| panic!("verify overlap: {error}"));
    assert!(matches!(
        overlap.verify(signed.compact(), 30_000),
        Err(ExecutorIntentError::KeyRetired)
    ));

    let revoked = ExecutorIntentVerifierV1::new(
        ISSUER,
        AUDIENCE,
        7,
        [verification_key(
            &fixture.signing_key,
            7,
            9_000,
            None,
            None,
            Some(10_400),
        )],
    )
    .unwrap_or_else(|error| panic!("revoked verifier: {error}"));
    assert!(matches!(
        revoked.verify(signed.compact(), 10_500),
        Err(ExecutorIntentError::KeyRevoked)
    ));
}

#[test]
fn prepared_intent_is_durable_idempotent_and_rejects_identity_conflicts() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let primary_fixture = fixture();
    let signed = primary_fixture
        .signer
        .issue(&primary_fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    assert_eq!(
        security
            .persist_signed_executor_intent(&signed, 10_500)
            .unwrap_or_else(|error| panic!("persist intent: {error}")),
        ExecutorIntentPersistenceV1::Prepared
    );
    drop(security);

    let reopened = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("reopen security store: {error}"));
    assert_eq!(
        reopened
            .persist_signed_executor_intent(&signed, 10_600)
            .unwrap_or_else(|error| panic!("replay exact intent: {error}")),
        ExecutorIntentPersistenceV1::AlreadyPrepared
    );

    let mut conflict_input = primary_fixture.input.clone();
    conflict_input.intent_id = Uuid::new_v4();
    let conflicting = primary_fixture
        .signer
        .issue(&conflict_input)
        .unwrap_or_else(|error| panic!("issue conflicting intent: {error}"));
    assert!(matches!(
        reopened.persist_signed_executor_intent(&conflicting, 10_700),
        Err(StoreError::ExecutorIntentConflict)
    ));

    let expired_fixture = fixture();
    let expired = expired_fixture
        .signer
        .issue(&expired_fixture.input)
        .unwrap_or_else(|error| panic!("issue expiring intent: {error}"));
    assert!(matches!(
        reopened.persist_signed_executor_intent(&expired, expired_fixture.input.expires_at_ms),
        Err(StoreError::ExecutorIntentExpired)
    ));
    drop(reopened);

    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect security store: {error}"));
    let (rows, state, consequences): (i64, String, String) = inspected
        .query_row(
            "SELECT COUNT(*), state, consequences_json
             FROM executor_operation_intents WHERE intent_id = ?1",
            [primary_fixture.input.intent_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("inspect prepared intent: {error}"));
    assert_eq!(rows, 1);
    assert_eq!(state, "prepared");
    assert!(consequences.contains("automatic_rollback_prohibited"));
}

#[test]
fn security_schema_v13_migration_preserves_prepared_intents_and_adds_candidate_bindings() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v13-security.sqlite");
    let fixture = fixture();
    let signed = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("open current security store: {error}"));
    security
        .persist_signed_executor_intent(&signed, 10_500)
        .unwrap_or_else(|error| panic!("persist prepared intent: {error}"));
    drop(security);

    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open legacy security store: {error}"));
    legacy
        .execute_batch(
            "ALTER TABLE executor_operation_intents DROP COLUMN release_bundle_digest;
             ALTER TABLE executor_operation_intents DROP COLUMN build_attestation_digest;
             UPDATE security_meta SET integer_value = 13 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade candidate-binding schema: {error}"));
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v13 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated security store: {error}"));
    let (version, columns, state, token, release, attestation): (
        i64,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
    ) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM pragma_table_info('executor_operation_intents')
                 WHERE name IN ('release_bundle_digest', 'build_attestation_digest')),
                state, compact_token, release_bundle_digest, build_attestation_digest
             FROM executor_operation_intents WHERE intent_id = ?1",
            [fixture.input.intent_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("inspect migrated prepared intent: {error}"));
    assert_eq!((version, columns, state.as_str()), (14, 2, "prepared"));
    assert_eq!(token, signed.compact());
    assert_eq!((release, attestation), (None, None));
}

#[test]
fn prepared_intent_and_action_grant_are_consumed_atomically_with_root_role_enforcement() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let intent_fixture = fixture();
    let signed_intent = intent_fixture
        .signer
        .issue(&intent_fixture.input)
        .unwrap_or_else(|error| panic!("issue intent: {error}"));
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    security
        .persist_signed_executor_intent(&signed_intent, 10_500)
        .unwrap_or_else(|error| panic!("persist intent: {error}"));

    let authority = grant_authority();
    let base_grant = grant_input(&signed_intent, ActionGrantRoleV1::Operator);

    let mut early_input = grant_input(&signed_intent, ActionGrantRoleV1::Admin);
    early_input.issued_at_ms = 10_000;
    early_input.not_before_ms = 10_000;
    let early_grant = authenticate_grant(&authority, &early_input);
    assert!(matches!(
        security.consume_prepared_intent_action_grant(
            signed_intent.claims().intent_id,
            &early_grant,
            Uuid::new_v4(),
            10_499,
        ),
        Err(StoreError::ExecutorIntentNotCurrent)
    ));

    let mut substituted_input = base_grant.clone();
    substituted_input.intent_digest = digest("substituted signed intent");
    let substituted = authenticate_grant(&authority, &substituted_input);
    assert!(matches!(
        security.consume_prepared_intent_action_grant(
            signed_intent.claims().intent_id,
            &substituted,
            Uuid::new_v4(),
            11_500,
        ),
        Err(StoreError::ExecutorIntentGrantBinding)
    ));

    let operator_grant = authenticate_grant(&authority, &base_grant);
    assert!(matches!(
        security.consume_prepared_intent_action_grant(
            signed_intent.claims().intent_id,
            &operator_grant,
            Uuid::new_v4(),
            11_500,
        ),
        Err(StoreError::ExecutorIntentRole)
    ));

    let mut admin_input = base_grant;
    admin_input.nonce = Uuid::new_v4();
    admin_input.role = ActionGrantRoleV1::Admin;
    let admin_grant = authenticate_grant(&authority, &admin_input);
    let attempt_id = Uuid::new_v4();
    assert_eq!(
        security
            .consume_prepared_intent_action_grant(
                signed_intent.claims().intent_id,
                &admin_grant,
                attempt_id,
                11_500,
            )
            .unwrap_or_else(|error| panic!("consume intent and grant: {error}")),
        ActionGrantConsumptionV1::Consumed
    );
    drop(security);

    let reopened = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("reopen security store: {error}"));
    assert_eq!(
        reopened
            .consume_prepared_intent_action_grant(
                signed_intent.claims().intent_id,
                &admin_grant,
                attempt_id,
                admin_input.expires_at_ms,
            )
            .unwrap_or_else(|error| panic!("replay consumed intent: {error}")),
        ActionGrantConsumptionV1::AlreadyConsumed
    );
    assert!(matches!(
        reopened.consume_prepared_intent_action_grant(
            signed_intent.claims().intent_id,
            &admin_grant,
            Uuid::new_v4(),
            11_600,
        ),
        Err(StoreError::ExecutorIntentConsumed)
    ));
    assert_accepted_candidate_binding(&reopened, &intent_fixture.input);
    drop(reopened);
    assert_consumed_intent_state(&security_path, signed_intent.claims().intent_id);
}
