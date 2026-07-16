# Independent security review: executor intent and atomic grant consumption

Perform a focused, read-only security/correctness review of the current signed executor-intent and
atomic action-grant integration. Report only concrete P0/P1/P2 findings or `PASS`. Do not treat the
still-disabled socket mutation handler, policy/source resolver, credentials or adapter runner as a
defect in this bounded slice unless the implemented API makes their safe integration impossible.

## Implemented boundary

- `src/executor_intent.rs` issues deterministic canonical-CBOR Ed25519 receipts under a separate
  signature domain and key lifecycle. Claims bind request/intent IDs, project, operation, immutable
  target, proposed/effective release class, policy digest, source attestation/sequence,
  migration/rollback targets, derived confirmation consequences and derived minimum role.
- Intent lifetime is at most five minutes. Stateful-breaking deploy and code rollback derive
  `admin`; other valid operations derive `operator`.
- `src/authorization.rs` can authenticate an authorizer action grant for subsequent binding to a
  persisted root intent. The existing fully expected-bound verification API remains available.
- `src/store/security.rs` schema v12 persists the complete signed intent before authorization.
  Request ID, intent ID, digest and compact token are independently unique. Exact preparation retry
  is idempotent; overlapping identities conflict.
- `consume_prepared_intent_action_grant` runs in one immediate SQLite transaction. It exact-binds
  grant intent digest/ID, request and policy, enforces the root-derived role, inserts the audited
  single-use grant and marks the intent consumed by the exact attempt. Any error rolls back both.
  Exact delivery replay by the same intent/grant/attempt is idempotent even after grant expiry;
  another attempt or grant fails.
- The protocol can carry the signed-intent response, but `ReadOnlyExecutorHandler` still rejects
  prepare/execute requests. No real mutation path is enabled.
- Bare `bin/ci` is green with 196 executable Rust tests, browser TAP, schema checks and optimized
  release build.

## Threat model

An unprivileged controller-UID peer can replay, reorder, substitute or truncate socket requests and
can hold a valid signed grant. It cannot modify the root-owned security journal/config, obtain
signing keys or break Ed25519/SHA-256. Crashes and restarts can occur at every SQLite boundary.

## Review questions

1. Can canonical encoding, signature/key lifecycle, field validation or optional-field combinations
   accept an ambiguous/malformed intent?
2. Can consequences or minimum role diverge from the effective operation/release class?
3. Can a valid grant be rebound to another persisted intent, request, policy or attempt?
4. Can transaction ordering, uniqueness, exact-replay handling or migration permit double use,
   partial consumption or a false idempotent success?
5. Does the public authenticated-grant API create a type-state footgun that makes safe root socket
   integration unrealistic?

For each finding cite exact functions/lines, give a realistic failure or exploit trace, severity,
confidence and the smallest coherent remediation. Separate confirmed defects from hardening ideas.
