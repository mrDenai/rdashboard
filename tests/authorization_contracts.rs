use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rdashboard::{
    authorization::{
        ACTION_GRANT_MAX_TTL_MS, ActionGrantError, ActionGrantExpectedBindingV1,
        ActionGrantIssueInputV1, ActionGrantRoleV1, ActionGrantSignerV1,
        ActionGrantVerificationKeyV1, ActionGrantVerifierV1, inspect_unverified_action_grant,
    },
    domain::EvidenceDigest,
    store::{ActionGrantConsumptionV1, SecurityStore, StoreError},
};
use tempfile::tempdir;
use uuid::Uuid;

const ISSUER: &str = "https://actions.dev.4u.ge";
const AUDIENCE: &str = "rdashboard-executor";
const KEY_ID: &str = "authorizer-2026-01";

struct Fixture {
    signer: ActionGrantSignerV1,
    signing_key: SigningKey,
    input: ActionGrantIssueInputV1,
    expected: ActionGrantExpectedBindingV1,
}

fn digest(value: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(value)
}

fn fixture() -> Fixture {
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let input = ActionGrantIssueInputV1 {
        issued_at_ms: 2_000,
        not_before_ms: 2_000,
        expires_at_ms: 120_000,
        nonce: Uuid::new_v4(),
        actor_id: Uuid::new_v4(),
        role: ActionGrantRoleV1::Admin,
        lease_id: Uuid::new_v4(),
        lease_generation: 7,
        intent_id: Uuid::new_v4(),
        intent_digest: digest("intent"),
        installed_policy_digest: digest("policy"),
        request_id: Uuid::new_v4(),
    };
    let expected = ActionGrantExpectedBindingV1 {
        actor_id: input.actor_id,
        role: input.role,
        lease_id: input.lease_id,
        lease_generation: input.lease_generation,
        intent_id: input.intent_id,
        intent_digest: input.intent_digest.clone(),
        installed_policy_digest: input.installed_policy_digest.clone(),
        request_id: input.request_id,
    };
    let signer = ActionGrantSignerV1::new(ISSUER, AUDIENCE, KEY_ID, 3, signing_key.clone())
        .unwrap_or_else(|error| panic!("signer: {error}"));
    Fixture {
        signer,
        signing_key,
        input,
        expected,
    }
}

fn verification_key(
    signing_key: &SigningKey,
    key_epoch: u64,
    active_from_ms: i64,
    signing_retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
) -> ActionGrantVerificationKeyV1 {
    ActionGrantVerificationKeyV1::new(
        KEY_ID,
        key_epoch,
        signing_key.verifying_key(),
        active_from_ms,
        signing_retired_at_ms,
        verify_until_ms,
        revoked_at_ms,
    )
    .unwrap_or_else(|error| panic!("verification key: {error}"))
}

fn verifier(signing_key: &SigningKey, minimum_key_epoch: u64) -> ActionGrantVerifierV1 {
    ActionGrantVerifierV1::new(
        ISSUER,
        AUDIENCE,
        minimum_key_epoch,
        [verification_key(signing_key, 3, 1_000, None, None, None)],
    )
    .unwrap_or_else(|error| panic!("verifier: {error}"))
}

#[test]
fn deterministic_grant_round_trip_binds_every_authority_field() {
    let primary_fixture = fixture();
    let token = primary_fixture
        .signer
        .issue(&primary_fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let verified = verifier(&primary_fixture.signing_key, 3)
        .verify(&token, &primary_fixture.expected, 2_500)
        .unwrap_or_else(|error| panic!("verify: {error}"));
    let inspected = inspect_unverified_action_grant(&token)
        .unwrap_or_else(|error| panic!("inspect canonical claims: {error}"));
    assert_eq!(inspected.actor_id, primary_fixture.input.actor_id);
    assert_eq!(inspected.lease_id, primary_fixture.input.lease_id);
    assert_eq!(
        inspected.lease_generation,
        primary_fixture.input.lease_generation
    );
    assert_eq!(inspected.intent_id, primary_fixture.input.intent_id);
    assert_eq!(verified.claims().nonce, primary_fixture.input.nonce);
    assert_eq!(verified.claims().key_epoch, 3);
    assert_eq!(verified.claims().intent_id, primary_fixture.input.intent_id);
    assert_eq!(
        verified.claims().request_id,
        primary_fixture.input.request_id
    );
    assert_eq!(
        verified.claims().expires_at_ms,
        primary_fixture.input.expires_at_ms
    );
    assert_eq!(verified.digest().as_str().len(), 64);

    let repeated = primary_fixture
        .signer
        .issue(&primary_fixture.input)
        .unwrap_or_else(|error| panic!("repeat issue: {error}"));
    assert_eq!(token, repeated);
}

#[test]
fn actor_lease_intent_policy_and_request_substitution_fail_closed() {
    let fixture = fixture();
    let token = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let verifier = verifier(&fixture.signing_key, 3);

    let mut expected = fixture.expected.clone();
    expected.actor_id = Uuid::new_v4();
    assert!(matches!(
        verifier.verify(&token, &expected, 2_500),
        Err(ActionGrantError::BindingMismatch)
    ));

    let mut expected = fixture.expected.clone();
    expected.lease_generation += 1;
    assert!(matches!(
        verifier.verify(&token, &expected, 2_500),
        Err(ActionGrantError::BindingMismatch)
    ));

    let mut expected = fixture.expected.clone();
    expected.intent_digest = digest("substituted intent");
    assert!(matches!(
        verifier.verify(&token, &expected, 2_500),
        Err(ActionGrantError::BindingMismatch)
    ));

    let mut expected = fixture.expected.clone();
    expected.installed_policy_digest = digest("substituted policy");
    assert!(matches!(
        verifier.verify(&token, &expected, 2_500),
        Err(ActionGrantError::BindingMismatch)
    ));

    let mut expected = fixture.expected;
    expected.request_id = Uuid::new_v4();
    assert!(matches!(
        verifier.verify(&token, &expected, 2_500),
        Err(ActionGrantError::BindingMismatch)
    ));
}

#[test]
fn grant_lifetime_is_bounded_and_checked_at_both_edges() {
    let mut invalid_fixture = fixture();
    invalid_fixture.input.expires_at_ms =
        invalid_fixture.input.issued_at_ms + ACTION_GRANT_MAX_TTL_MS + 1;
    assert!(matches!(
        invalid_fixture.signer.issue(&invalid_fixture.input),
        Err(ActionGrantError::InvalidLifetime)
    ));

    let fixture = fixture();
    let token = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let verifier = verifier(&fixture.signing_key, 3);
    assert!(matches!(
        verifier.verify(&token, &fixture.expected, fixture.input.not_before_ms - 1),
        Err(ActionGrantError::NotYetValid)
    ));
    assert!(matches!(
        verifier.verify(&token, &fixture.expected, fixture.input.expires_at_ms),
        Err(ActionGrantError::Expired)
    ));
}

#[test]
fn issuer_audience_key_and_signature_substitution_are_rejected() {
    let fixture = fixture();
    let token = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let key = verification_key(&fixture.signing_key, 3, 1_000, None, None, None);

    let wrong_issuer =
        ActionGrantVerifierV1::new("https://other.example", AUDIENCE, 3, [key.clone()])
            .unwrap_or_else(|error| panic!("wrong issuer verifier: {error}"));
    assert!(matches!(
        wrong_issuer.verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::IssuerMismatch)
    ));

    let wrong_audience = ActionGrantVerifierV1::new(ISSUER, "other-executor", 3, [key.clone()])
        .unwrap_or_else(|error| panic!("wrong audience verifier: {error}"));
    assert!(matches!(
        wrong_audience.verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::AudienceMismatch)
    ));

    let unknown_key = ActionGrantVerificationKeyV1::new(
        "other-key",
        3,
        fixture.signing_key.verifying_key(),
        1_000,
        None,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("unknown key fixture: {error}"));
    let unknown_key_verifier = ActionGrantVerifierV1::new(ISSUER, AUDIENCE, 3, [unknown_key])
        .unwrap_or_else(|error| panic!("unknown key verifier: {error}"));
    assert!(matches!(
        unknown_key_verifier.verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::UnknownKey(key_id)) if key_id == KEY_ID
    ));

    let wrong_signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let wrong_key = ActionGrantVerificationKeyV1::new(
        KEY_ID,
        3,
        wrong_signing_key.verifying_key(),
        1_000,
        None,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("wrong key fixture: {error}"));
    let wrong_key_verifier = ActionGrantVerifierV1::new(ISSUER, AUDIENCE, 3, [wrong_key])
        .unwrap_or_else(|error| panic!("wrong key verifier: {error}"));
    assert!(matches!(
        wrong_key_verifier.verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::SignatureVerification(_))
    ));
}

#[test]
fn noncanonical_or_tampered_compact_tokens_are_rejected() {
    let fixture = fixture();
    let token = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 2);

    let mut payload = URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap_or_else(|error| panic!("payload base64: {error}"));
    payload.push(0);
    let noncanonical = format!("{}.{}", URL_SAFE_NO_PAD.encode(payload), parts[1]);
    assert!(matches!(
        verifier(&fixture.signing_key, 3).verify(&noncanonical, &fixture.expected, 2_500),
        Err(ActionGrantError::NonCanonicalPayload)
    ));

    let mut signature = URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap_or_else(|error| panic!("signature base64: {error}"));
    signature[0] ^= 1;
    let tampered = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(signature));
    assert!(matches!(
        verifier(&fixture.signing_key, 3).verify(&tampered, &fixture.expected, 2_500),
        Err(ActionGrantError::SignatureVerification(_))
    ));

    assert!(matches!(
        verifier(&fixture.signing_key, 3).verify(
            &format!("{token}.extra"),
            &fixture.expected,
            2_500
        ),
        Err(ActionGrantError::InvalidTokenEncoding)
    ));
}

#[test]
fn key_epoch_rotation_overlap_retirement_and_revocation_are_explicit() {
    let fixture = fixture();
    let token = fixture
        .signer
        .issue(&fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));

    assert!(matches!(
        verifier(&fixture.signing_key, 4).verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::KeyEpochRejected)
    ));

    let overlap_key = verification_key(
        &fixture.signing_key,
        3,
        1_000,
        Some(3_000),
        Some(4_000),
        None,
    );
    let overlap = ActionGrantVerifierV1::new(ISSUER, AUDIENCE, 3, [overlap_key])
        .unwrap_or_else(|error| panic!("overlap verifier: {error}"));
    overlap
        .verify(&token, &fixture.expected, 3_500)
        .unwrap_or_else(|error| panic!("verify during overlap: {error}"));
    assert!(matches!(
        overlap.verify(&token, &fixture.expected, 4_000),
        Err(ActionGrantError::KeyRetired)
    ));

    let revoked_key = verification_key(
        &fixture.signing_key,
        3,
        1_000,
        Some(3_000),
        Some(4_000),
        Some(2_400),
    );
    let revoked = ActionGrantVerifierV1::new(ISSUER, AUDIENCE, 3, [revoked_key])
        .unwrap_or_else(|error| panic!("revoked verifier: {error}"));
    assert!(matches!(
        revoked.verify(&token, &fixture.expected, 2_500),
        Err(ActionGrantError::KeyRevoked)
    ));
}

#[test]
fn verified_grant_consumption_is_durable_idempotent_and_auditable() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let primary_fixture = fixture();
    let token = primary_fixture
        .signer
        .issue(&primary_fixture.input)
        .unwrap_or_else(|error| panic!("issue: {error}"));
    let verified = verifier(&primary_fixture.signing_key, 3)
        .verify(&token, &primary_fixture.expected, 2_500)
        .unwrap_or_else(|error| panic!("verify: {error}"));
    let attempt_id = Uuid::new_v4();

    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    assert_eq!(
        security
            .consume_verified_action_grant(&verified, attempt_id, 2_500)
            .unwrap_or_else(|error| panic!("consume action grant: {error}")),
        ActionGrantConsumptionV1::Consumed
    );
    drop(security);

    let reopened = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("reopen security store: {error}"));
    assert_eq!(
        reopened
            .consume_verified_action_grant(
                &verified,
                attempt_id,
                primary_fixture.input.expires_at_ms,
            )
            .unwrap_or_else(|error| panic!("replay exact action grant: {error}")),
        ActionGrantConsumptionV1::AlreadyConsumed
    );
    assert!(matches!(
        reopened.consume_verified_action_grant(&verified, Uuid::new_v4(), 2_501),
        Err(StoreError::ExecutorActionGrantReplay)
    ));

    let expired_fixture = fixture();
    let expired_token = expired_fixture
        .signer
        .issue(&expired_fixture.input)
        .unwrap_or_else(|error| panic!("issue expiring grant: {error}"));
    let expired_verified = verifier(&expired_fixture.signing_key, 3)
        .verify(&expired_token, &expired_fixture.expected, 2_500)
        .unwrap_or_else(|error| panic!("verify expiring grant: {error}"));
    assert!(matches!(
        reopened.consume_verified_action_grant(
            &expired_verified,
            Uuid::new_v4(),
            expired_fixture.input.expires_at_ms,
        ),
        Err(StoreError::ExecutorActionGrantExpired)
    ));
    drop(reopened);

    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect security store: {error}"));
    let audited_rows: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM executor_action_grants
             WHERE nonce = ?1 AND grant_digest = ?2 AND attempt_id = ?3
               AND schema_version = 1 AND issuer = ?4 AND executor_audience = ?5
               AND intent_id = ?6 AND intent_digest = ?7 AND request_id = ?8
               AND actor_id = ?9 AND role = 'admin' AND lease_id = ?10
               AND lease_generation = ?11 AND key_id = ?12 AND key_epoch = 3
               AND installed_policy_digest = ?13 AND issued_at_ms = ?14
               AND not_before_ms = ?15 AND expires_at_ms = ?16
               AND consumed_at_ms = 2500",
            rusqlite::params![
                primary_fixture.input.nonce.to_string(),
                verified.digest().as_str(),
                attempt_id.to_string(),
                ISSUER,
                AUDIENCE,
                primary_fixture.input.intent_id.to_string(),
                primary_fixture.input.intent_digest.as_str(),
                primary_fixture.input.request_id.to_string(),
                primary_fixture.input.actor_id.to_string(),
                primary_fixture.input.lease_id.to_string(),
                i64::try_from(primary_fixture.input.lease_generation)
                    .unwrap_or_else(|error| panic!("lease generation: {error}")),
                KEY_ID,
                primary_fixture.input.installed_policy_digest.as_str(),
                primary_fixture.input.issued_at_ms,
                primary_fixture.input.not_before_ms,
                primary_fixture.input.expires_at_ms,
            ],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect audited grant: {error}"));
    assert_eq!(audited_rows, 1);
}
