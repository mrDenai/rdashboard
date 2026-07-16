# Independent security review: signed action-grant authority

Review the current repository state as a focused, read-only security and correctness audit. Report
only concrete P0/P1/P2 defects in this slice, or `PASS` if none survive source inspection. Do not
review unrelated Phase 6A code or request implementation changes outside the stated boundary.

## Implemented slice

- `src/authorization.rs` defines deterministic map-CBOR Ed25519 action grants with a fixed signature
  domain and compact base64url encoding.
- Exact signed claims include schema, issuer, executor audience, verification key ID/epoch,
  issue/not-before/expiry times, nonce, actor/role, lease ID/generation, intent ID/digest, installed
  policy digest and request ID.
- `ActionGrantVerifierV1` requires an exact expected binding, a configured key lifecycle and a
  minimum key epoch. Its result is the opaque `VerifiedActionGrantV1` accepted by storage.
- `src/store/security.rs` schema v11 durably consumes a verified grant in an immediate SQLite
  transaction. First use must be inside the signed window. The nonce is globally unique. An exact
  token replay by the same consuming attempt is idempotent even after expiry; any other nonce reuse
  fails. The audit row retains all material signed claims plus grant digest, attempt and consumption
  time.
- `tests/authorization_contracts.rs` exercises deterministic issuance, every expected binding,
  lifetime edges, service/key/signature substitution, noncanonical/trailing encodings, rotation,
  retirement, revocation, restart-persistent replay and audit data.
- `tests/executor_recovery.rs` covers v10-to-v11 and older migrations.
- The full bare `bin/ci` is green with 187 executable Rust tests, browser TAP, schema checks and an
  optimized release build.

## Boundary and pending integration

- Root mutation requests remain disabled. This review is of the authority primitive and durable
  replay ledger, not a claim that mutations are enabled.
- The next slice will define a signed executor intent, bind its attempt/project/phase and exact
  adapter request to the action grant, load the root verifier keyring, and require adapter-level
  idempotency. Do not report their deliberate absence as a defect in this primitive unless the
  current API makes that safe integration impossible.
- Attacker assumptions: unprivileged/controller-UID clients may connect to the root Unix socket and
  may replay, substitute, truncate or reorder captured requests. They do not control root-owned
  config/key material or break Ed25519/SHA-256.

## Questions

1. Can a malformed/noncanonical token, key-lifecycle edge or binding substitution be accepted?
2. Can concurrency, restart, expiry or SQL uniqueness permit a grant/nonce to authorize two
   different attempts or hide an ambiguous first consumption?
3. Is the exact-replay rule safely scoped for later idempotent execution, or does this API lose a
   material identity that must be persisted now?
4. Does migration or schema validation permit a v11 store to serve without the replay invariant?
5. Are any signed claim validation/range constraints materially missing?

For each finding cite exact files/functions, a realistic exploit/failure trace, severity and the
smallest coherent remediation. Distinguish confirmed defects from hardening suggestions.
