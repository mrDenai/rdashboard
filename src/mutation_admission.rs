use std::fmt;

use crate::{
    authorization::ActionGrantError,
    domain::{GitCommitId, MutationStatusV1, OperationKind, ProjectId, ReleaseClass},
    executor_authority::RootExecutorAuthorityV1,
    executor_intent::{ExecutorIntentError, ExecutorIntentIssueInputV1},
    protocol::ControlRejectionCodeV1,
    store::{ActionGrantConsumptionV1, SecurityStore, StoreError},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareMutationIntentV1 {
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub proposed_release_class: Option<ReleaseClass>,
    pub idempotency_key: uuid::Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMutationGrantV1 {
    pub intent_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub action_grant: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveMutationStatusV1 {
    pub intent_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationAcceptanceV1 {
    pub intent_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationControlFailureV1 {
    pub code: ControlRejectionCodeV1,
    pub retryable: bool,
}

pub trait MutationControlV1: fmt::Debug + Send + Sync + 'static {
    fn prepare_intent(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<String, MutationControlFailureV1>;

    fn accept_grant(
        &self,
        request: &ExecuteMutationGrantV1,
        now_ms: i64,
    ) -> Result<MutationAcceptanceV1, MutationControlFailureV1>;

    fn mutation_status(
        &self,
        request: &ObserveMutationStatusV1,
    ) -> Result<MutationStatusV1, MutationControlFailureV1>;
}

pub trait ExecutorIntentResolverV1: fmt::Debug + Send + Sync + 'static {
    fn resolve(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<ExecutorIntentIssueInputV1, IntentResolutionFailureV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentResolutionFailureV1 {
    Rejected,
    TemporarilyUnavailable,
}

#[derive(Debug)]
pub struct RootMutationAdmissionV1<R> {
    security: SecurityStore,
    authority: RootExecutorAuthorityV1,
    resolver: R,
}

impl<R: ExecutorIntentResolverV1> RootMutationAdmissionV1<R> {
    pub const fn new(
        security: SecurityStore,
        authority: RootExecutorAuthorityV1,
        resolver: R,
    ) -> Self {
        Self {
            security,
            authority,
            resolver,
        }
    }

    fn prepare(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<String, MutationAdmissionError> {
        if let Some(compact) = self.replay_prepared(request)? {
            return Ok(compact);
        }
        let input = self
            .resolver
            .resolve(request, now_ms)
            .map_err(MutationAdmissionError::Resolution)?;
        if input.request_id != request.idempotency_key
            || input.project_id != request.project_id
            || input.operation_kind != request.operation_kind
            || input.target_commit != request.target_commit
            || input.proposed_release_class != request.proposed_release_class
        {
            return Err(MutationAdmissionError::ResolverBindingMismatch);
        }
        let signed = self.authority.executor_intent_signer().issue(&input)?;
        match self
            .security
            .persist_signed_executor_intent(&signed, now_ms)
        {
            Ok(_) => Ok(signed.compact().to_owned()),
            Err(StoreError::ExecutorIntentConflict) => {
                self.replay_prepared(request)?
                    .ok_or(MutationAdmissionError::Store(
                        StoreError::ExecutorIntentConflict,
                    ))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn replay_prepared(
        &self,
        request: &PrepareMutationIntentV1,
    ) -> Result<Option<String>, MutationAdmissionError> {
        self.security
            .replay_signed_executor_intent(
                request.idempotency_key,
                &request.project_id,
                request.operation_kind,
                request.target_commit.as_ref(),
                request.proposed_release_class,
            )
            .map_err(Into::into)
    }

    fn accept(
        &self,
        request: &ExecuteMutationGrantV1,
        now_ms: i64,
    ) -> Result<MutationAcceptanceV1, MutationAdmissionError> {
        let grant = self
            .authority
            .action_grant_verifier()
            .authenticate_for_persisted_intent(&request.action_grant, now_ms)?;
        if grant.claims().intent_id != request.intent_id {
            return Err(MutationAdmissionError::GrantBindingMismatch);
        }
        let consumption = self.security.consume_prepared_intent_action_grant(
            request.intent_id,
            &grant,
            request.attempt_id,
            now_ms,
        )?;
        Ok(MutationAcceptanceV1 {
            intent_id: request.intent_id,
            attempt_id: request.attempt_id,
            replayed: consumption == ActionGrantConsumptionV1::AlreadyConsumed,
        })
    }

    fn status(
        &self,
        request: &ObserveMutationStatusV1,
    ) -> Result<MutationStatusV1, MutationAdmissionError> {
        self.security
            .mutation_status(request.intent_id, request.attempt_id)?
            .ok_or(MutationAdmissionError::StatusNotFound)
    }
}

impl<R: ExecutorIntentResolverV1> MutationControlV1 for RootMutationAdmissionV1<R> {
    fn prepare_intent(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<String, MutationControlFailureV1> {
        self.prepare(request, now_ms)
            .map_err(MutationAdmissionError::control_failure)
    }

    fn accept_grant(
        &self,
        request: &ExecuteMutationGrantV1,
        now_ms: i64,
    ) -> Result<MutationAcceptanceV1, MutationControlFailureV1> {
        self.accept(request, now_ms)
            .map_err(MutationAdmissionError::control_failure)
    }

    fn mutation_status(
        &self,
        request: &ObserveMutationStatusV1,
    ) -> Result<MutationStatusV1, MutationControlFailureV1> {
        self.status(request)
            .map_err(MutationAdmissionError::control_failure)
    }
}

#[derive(Debug, thiserror::Error)]
enum MutationAdmissionError {
    #[error("the installed resolver rejected the requested operation")]
    Resolution(IntentResolutionFailureV1),
    #[error("the installed resolver changed a caller-visible request binding")]
    ResolverBindingMismatch,
    #[error("the action grant does not name the requested prepared intent")]
    GrantBindingMismatch,
    #[error("the accepted mutation status does not exist")]
    StatusNotFound,
    #[error(transparent)]
    Intent(#[from] ExecutorIntentError),
    #[error(transparent)]
    Grant(#[from] ActionGrantError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl MutationAdmissionError {
    fn control_failure(self) -> MutationControlFailureV1 {
        let (code, retryable) = match self {
            Self::Resolution(IntentResolutionFailureV1::TemporarilyUnavailable) => {
                (ControlRejectionCodeV1::InternalFailure, true)
            }
            Self::Resolution(IntentResolutionFailureV1::Rejected)
            | Self::ResolverBindingMismatch
            | Self::GrantBindingMismatch
            | Self::StatusNotFound
            | Self::Intent(_)
            | Self::Grant(_)
            | Self::Store(
                StoreError::ExecutorIntentExpired
                | StoreError::ExecutorIntentNotCurrent
                | StoreError::ExecutorIntentMissing
                | StoreError::ExecutorIntentGrantBinding
                | StoreError::ExecutorIntentRole
                | StoreError::ExecutorActionGrantExpired,
            ) => (ControlRejectionCodeV1::MutationRejected, false),
            Self::Store(
                StoreError::ExecutorIntentConflict
                | StoreError::ExecutorIntentConsumed
                | StoreError::ExecutorActionGrantReplay,
            ) => (ControlRejectionCodeV1::MutationConflict, false),
            Self::Store(_) => (ControlRejectionCodeV1::InternalFailure, true),
        };
        MutationControlFailureV1 { code, retryable }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        authorization::{ActionGrantIssueInputV1, ActionGrantRoleV1, ActionGrantSignerV1},
        domain::EvidenceDigest,
        executor_authority::{
            ActionGrantVerificationKeyConfigV1, ROOT_EXECUTOR_AUTHORITY_SCHEMA_VERSION,
            RootExecutorAuthorityConfigV1,
        },
        executor_intent::ExecutorIntentSignerV1,
    };

    #[derive(Debug)]
    struct StaticResolver {
        input: ExecutorIntentIssueInputV1,
        calls: Arc<AtomicUsize>,
    }

    impl ExecutorIntentResolverV1 for StaticResolver {
        fn resolve(
            &self,
            _request: &PrepareMutationIntentV1,
            _now_ms: i64,
        ) -> Result<ExecutorIntentIssueInputV1, IntentResolutionFailureV1> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            let mut input = self.input.clone();
            if call > 0 {
                input.intent_id = uuid::Uuid::new_v4();
                input.issued_at_ms += 1;
                input.not_before_ms += 1;
                input.expires_at_ms += 1;
            }
            Ok(input)
        }
    }

    fn authority(
        temporary: &tempfile::TempDir,
        intent_key: &SigningKey,
        action_key: &SigningKey,
    ) -> RootExecutorAuthorityV1 {
        let credential = temporary.path().join("executor-intent-seed");
        fs::write(&credential, intent_key.to_bytes())
            .unwrap_or_else(|error| panic!("write credential: {error}"));
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("credential permissions: {error}"));
        let config = RootExecutorAuthorityConfigV1 {
            schema_version: ROOT_EXECUTOR_AUTHORITY_SCHEMA_VERSION,
            action_grant_issuer: "https://actions.dev.4u.ge".to_owned(),
            executor_audience: "rdashboard-executor".to_owned(),
            minimum_action_grant_key_epoch: 9,
            action_grant_verification_keys: vec![ActionGrantVerificationKeyConfigV1 {
                key_id: "authorizer-2026-01".to_owned(),
                key_epoch: 9,
                public_key_base64url: URL_SAFE_NO_PAD.encode(action_key.verifying_key().to_bytes()),
                active_from_ms: 10_000,
                signing_retired_at_ms: None,
                verify_until_ms: None,
                revoked_at_ms: None,
            }],
            executor_intent_issuer: "rdashboard-executor".to_owned(),
            authorizer_audience: "https://actions.dev.4u.ge".to_owned(),
            executor_intent_key_id: "executor-2026-01".to_owned(),
            executor_intent_key_epoch: 7,
            executor_intent_public_key_base64url: URL_SAFE_NO_PAD
                .encode(intent_key.verifying_key().to_bytes()),
        };
        RootExecutorAuthorityV1::load_from_credential_path(
            &config,
            &credential,
            fs::metadata(&credential)
                .unwrap_or_else(|error| panic!("credential metadata: {error}"))
                .uid(),
        )
        .unwrap_or_else(|error| panic!("authority: {error}"))
    }

    fn prepare_documents() -> (PrepareMutationIntentV1, ExecutorIntentIssueInputV1) {
        let request = PrepareMutationIntentV1 {
            project_id: "rimg"
                .parse()
                .unwrap_or_else(|error| panic!("project: {error}")),
            operation_kind: OperationKind::BackupOnly,
            target_commit: None,
            proposed_release_class: None,
            idempotency_key: uuid::Uuid::new_v4(),
        };
        let issue_input = ExecutorIntentIssueInputV1 {
            issued_at_ms: 10_500,
            not_before_ms: 10_500,
            expires_at_ms: 40_500,
            intent_id: uuid::Uuid::new_v4(),
            request_id: request.idempotency_key,
            project_id: request.project_id.clone(),
            operation_kind: request.operation_kind,
            target_commit: None,
            proposed_release_class: None,
            effective_release_class: None,
            installed_policy_digest: EvidenceDigest::sha256("installed policy"),
            source_attestation_digest: None,
            source_sequence: None,
            release_bundle_digest: None,
            build_attestation_digest: None,
            migration_id: None,
            previous_release_bundle_digest: None,
        };
        (request, issue_input)
    }

    fn assert_accepted_projection(
        security: &SecurityStore,
        request: &PrepareMutationIntentV1,
        issue_input: &ExecutorIntentIssueInputV1,
        signed: &crate::executor_intent::SignedExecutorIntentV1,
        attempt_id: uuid::Uuid,
    ) -> crate::store::AcceptedMutationV1 {
        let accepted = security
            .accepted_mutations()
            .unwrap_or_else(|error| panic!("accepted mutations: {error}"));
        assert_eq!(accepted.len(), 1);
        let record = &accepted[0];
        assert_eq!(record.intent_id, issue_input.intent_id);
        assert_eq!(record.intent_digest, *signed.digest());
        assert_eq!(record.signed_intent, signed.compact());
        assert_eq!(record.attempt_id, attempt_id);
        assert_eq!(record.request_id, request.idempotency_key);
        assert_eq!(record.project_id, request.project_id);
        assert_eq!(record.operation_kind, OperationKind::BackupOnly);
        assert_eq!(record.release_bundle_digest, None);
        assert_eq!(record.build_attestation_digest, None);
        assert_eq!(record.action_grant_role, ActionGrantRoleV1::Operator);
        assert_eq!(record.accepted_at_ms, 11_500);
        record.clone()
    }

    fn assert_reopened_projection(
        security_path: &std::path::Path,
        expected: crate::store::AcceptedMutationV1,
    ) {
        let reopened = SecurityStore::open(security_path)
            .unwrap_or_else(|error| panic!("reopen security: {error}"));
        assert_eq!(
            reopened
                .accepted_mutations()
                .unwrap_or_else(|error| panic!("reopened accepted mutations: {error}")),
            vec![expected]
        );
    }

    fn assert_accepted_status(
        admission: &RootMutationAdmissionV1<StaticResolver>,
        intent_id: uuid::Uuid,
        attempt_id: uuid::Uuid,
    ) {
        let status = admission
            .status(&ObserveMutationStatusV1 {
                intent_id,
                attempt_id,
            })
            .unwrap_or_else(|error| panic!("accepted status: {error}"));
        assert_eq!(
            status.state,
            crate::domain::MutationExecutionStateV1::Accepted
        );
        assert_eq!(status.current_phase, crate::domain::OperationPhase::Queued);
        assert!(status.completed_phases.is_empty());
    }

    fn assert_prepared_replay(
        first: &str,
        replay: &str,
        expected: &crate::executor_intent::SignedExecutorIntentV1,
        resolver_calls: &AtomicUsize,
    ) {
        assert_eq!(first, expected.compact());
        assert_eq!(replay, first);
        assert_eq!(resolver_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn signed_intent_and_grant_consumption_are_durable_and_replay_exact() {
        let temporary = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let intent_key = SigningKey::from_bytes(&[73_u8; 32]);
        let action_key = SigningKey::from_bytes(&[61_u8; 32]);
        let authority = authority(&temporary, &intent_key, &action_key);
        let (request, issue_input) = prepare_documents();
        let expected_signed = ExecutorIntentSignerV1::new(
            "rdashboard-executor",
            "https://actions.dev.4u.ge",
            "executor-2026-01",
            7,
            intent_key,
        )
        .and_then(|signer| signer.issue(&issue_input))
        .unwrap_or_else(|error| panic!("expected signed intent: {error}"));
        let security_path = temporary.path().join("security.sqlite");
        let security =
            SecurityStore::open(&security_path).unwrap_or_else(|error| panic!("security: {error}"));
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let admission = RootMutationAdmissionV1::new(
            security,
            authority,
            StaticResolver {
                input: issue_input.clone(),
                calls: Arc::clone(&resolver_calls),
            },
        );
        let first = admission
            .prepare(&request, 10_500)
            .unwrap_or_else(|error| panic!("prepare: {error}"));
        let replay = admission
            .prepare(&request, 10_600)
            .unwrap_or_else(|error| panic!("prepare replay: {error}"));
        assert_prepared_replay(&first, &replay, &expected_signed, &resolver_calls);

        let mut conflicting_request = request.clone();
        conflicting_request.project_id = "other"
            .parse()
            .unwrap_or_else(|error| panic!("conflicting project: {error}"));
        assert!(matches!(
            admission.prepare(&conflicting_request, 10_700),
            Err(MutationAdmissionError::Store(
                StoreError::ExecutorIntentConflict
            ))
        ));

        let action_signer = ActionGrantSignerV1::new(
            "https://actions.dev.4u.ge",
            "rdashboard-executor",
            "authorizer-2026-01",
            9,
            action_key,
        )
        .unwrap_or_else(|error| panic!("action signer: {error}"));
        let action_grant = action_signer
            .issue(&ActionGrantIssueInputV1 {
                issued_at_ms: 11_000,
                not_before_ms: 11_000,
                expires_at_ms: 20_000,
                nonce: uuid::Uuid::new_v4(),
                actor_id: uuid::Uuid::new_v4(),
                role: ActionGrantRoleV1::Operator,
                lease_id: uuid::Uuid::new_v4(),
                lease_generation: 3,
                intent_id: issue_input.intent_id,
                intent_digest: expected_signed.digest().clone(),
                installed_policy_digest: issue_input.installed_policy_digest.clone(),
                request_id: issue_input.request_id,
            })
            .unwrap_or_else(|error| panic!("action grant: {error}"));
        let attempt_id = uuid::Uuid::new_v4();
        let execute = ExecuteMutationGrantV1 {
            intent_id: issue_input.intent_id,
            attempt_id,
            action_grant,
        };
        assert_eq!(
            admission
                .accept(&execute, 11_500)
                .unwrap_or_else(|error| panic!("accept: {error}")),
            MutationAcceptanceV1 {
                intent_id: issue_input.intent_id,
                attempt_id,
                replayed: false,
            }
        );
        assert_accepted_status(&admission, issue_input.intent_id, attempt_id);
        assert!(
            admission
                .accept(&execute, 11_600)
                .unwrap_or_else(|error| panic!("accept replay: {error}"))
                .replayed
        );
        let expected_accepted = assert_accepted_projection(
            &admission.security,
            &request,
            &issue_input,
            &expected_signed,
            attempt_id,
        );
        drop(admission);
        assert_reopened_projection(&security_path, expected_accepted);
    }
}
