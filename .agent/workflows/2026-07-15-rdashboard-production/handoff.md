# Phase 6B restart handoff

Saved: 2026-07-16

## Current production activation checkpoint

- Commit `f7019db` is installed on production; the controller, read-only executor and private
  systemd bridge are active with zero restarts.
- The exact Access issuer, application audience and operator identity are installed only in the
  root-readable production environment file. Protected origin requests fail closed with 403.
- The separate Cloudflare Access self-hosted application for
  `dev.4u.ge/.well-known/acme-challenge/*` now has a Bypass/Everyone policy. The root dashboard
  continues to use the exact email allow policy.
- Kamal Proxy has a healthy TLS route for `dev.4u.ge` and stores a trusted Let's Encrypt certificate
  with the exact hostname SAN, valid through 2026-10-14. Verified TLS reaches the origin and fails
  closed with 403 when the Access assertion is absent.
- The only remaining step is the operator's real browser login and confirmation that the snapshot
  and SSE-backed dashboard render through Cloudflare Access.
- Do not add nginx. Mutation authority, rimg producer deployment, push and release execution remain
  out of scope.

## Stable verified checkpoint

- Security schema v13 and the separate base-backup boundary are complete.
- The production `BackupCapture` path is complete across `rdashboard` and `rimg`.
- Exact escalated `rdashboard bin/ci` passed at that checkpoint with 225 executable Rust tests and
  four browser TAP tests.
- Exact escalated `rimg bin/ci` passed with 34 executable tests; one benchmark is intentionally
  ignored and local `cargo-audit` is explicitly unavailable.

## Current in-progress tree

The age/Google Drive pipeline is implemented but the latest formatted tree is not yet fully
verified. It currently includes:

- fixed `encrypt-v1`, `upload-v1` and `readback-v1` backup-adapter entrypoints;
- deterministic streaming `RDBARCH1` plaintext construction without a persisted plaintext archive;
- pinned age/rclone executable digests, an exact secret-free rclone config, and an X25519 recipient
  fingerprint bound to the authorized backup specification;
- crash-replay-safe owner-only ciphertext/encryption state publication;
- immutable deterministic Google Drive object keys, duplicate-name rejection, provider ID plus MD5
  version binding, and independent streamed SHA-256 readback;
- an operation-scoped systemd `LoadCredential` for the Drive service-account JSON;
- typed pipeline orchestration and a full manifest → local → upload → readback chain regression;
- runtime tests for recipient fingerprints, exact readback length/hash, Drive version binding and
  rejection of an rclone config containing embedded secrets.

The last `bin/ci` before the final recipient/config-test edits passed formatting, strict Clippy and
all 80 then-present library tests, then stopped only at the five known Unix-socket tests because the
sandbox returns `EPERM`. After that run, the recipient fingerprint helper was moved into
`backup.rs`, the Phase 6 test fixture was updated to use it, and the installed-runtime config test
was added. `cargo fmt --all` succeeds on the saved tree; no verification after those last edits has
been run.

## Resume exactly here

1. Run the required bare `bin/ci` in `rdashboard`.
2. Fix any compile/Clippy/test defect without weakening checks.
3. When the run reaches only the five sandbox-denied Unix-socket tests, rerun the exact bare
   `bin/ci` with the established escalation and require exit 0.
4. Self-review `src/backup_adapter/pipeline_runtime.rs`, especially crash windows, rclone output
   shape, systemd credential path derivation and exact archive metadata checks.
5. Update `plan.md` and `review.md` with the final test count and evidence.
6. Then continue to the fixed Kamal/readiness/smoke/soak adapters. Root mutation socket execution,
   commit, push and deployment remain unauthorized and disabled.

## Files central to the unfinished slice

- `src/backup_adapter/mod.rs`
- `src/backup_adapter/pipeline_runtime.rs`
- `src/bin/backup-adapter.rs`
- `src/adapter.rs`
- `src/backup.rs`
- `src/phase6.rs`
- `deploy/systemd/README.md`

The repository remains a largely untracked/dirty baseline. Preserve `.idea/` as user-owned and do
not infer commit, push or deployment authorization.
