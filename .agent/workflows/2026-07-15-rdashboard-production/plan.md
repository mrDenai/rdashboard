# rdashboard production implementation execution plan

Workflow: `.agent/workflows/2026-07-15-rdashboard-production`

Status: rimg production deployment and dashboard health integration in progress

Restart checkpoint: commit `823c5cc` is installed on the production VPS as the native
observation-only `rdashboard` controller with the prior read-only executor. Both systemd services
are enabled and active with zero restarts; the controller listens only on `127.0.0.1:3100`, and the
systemd socket bridge exposes it only on the private `kamal` gateway `172.19.0.1:3100`. `/health`
is green and every protected loopback and bridge request without a valid Access assertion returns
403. Exact Cloudflare Access issuer, audience and allowed identity are installed outside the
repository. A more-specific Bypass/Everyone application exposes only
`dev.4u.ge/.well-known/acme-challenge/*`, and Kamal Proxy obtained a trusted Let's Encrypt
certificate for `dev.4u.ge`. The root remains protected by the exact Access application and routes
to the healthy backend. Diagnostic commit `e72137f` identified the origin mismatch as the
over-strict mandatory/exact JWT `typ` check. Commit `823c5cc` applies the standards-compatible fix,
and exact gated release SHA-256 `c8e1a6fa…702230` is active with zero restarts, health 200 and
fail-closed 403 without an assertion. The operator's authenticated browser now renders fresh host
telemetry, a current snapshot and a connected advancing SSE stream, closing the public
observation-only activation. nginx is explicitly excluded. Production inspection found no running
`rimg` service/container/listener, only its GitHub Actions runner. U026 now authorizes the separate
first `rimg` production bootstrap and its internal read-only health integration, while dashboard
mutation authority remains disabled.

Last updated: 2026-07-17

Product specification: [`PLAN.md`](../../../PLAN.md)

## Current milestone — Phase 6B

1. **Completed — installed policy and derived authority.** `InstalledRimgPolicyV1` binds exact protocol v1, Kamal policy, backup units, schema transitions, timeouts and capabilities. Release classification is derived from verified bundles, schema inspection and owner-reviewed transitions rather than accepted as a caller assertion. Migration-plan and data-compatibility evidence is typed and bound to the exact intent/policy/schema/migration context, then revalidated during classification. The inspection is exact-bound to both verified bundle projects and schema versions; phase resolution accepts a revalidated `ReleaseClassificationAuthorityV1`, not a caller-supplied classification document.
2. **Completed — canonical backup chain and freshness.** Base chains include manifest, encrypted local evidence, provider upload and offsite readback; cutover chains include the exact fenced local snapshot. Whole-chain digests, deadlines, synchronized-clock freshness and security-journal document binding fail closed.
3. **Completed — stateful drain/fence ordering.** Stateful phases are `BackingUp → Draining → CutoverSnapshotting → Migrating`. The live source ticket starts before base backup, is refreshed before fence acquisition, and retains the project/disk owners across a transient retry or ambiguous reconciliation. A failed pre-effect abort remains on the original retryable phase and converges by idempotent ticket replay. A successful cutover releases the ticket only after its receipt is committed.
4. **Completed — fixed privileged specifications.** `AuthorizedPhaseSpecV1` binds branch, release classification, base/cutover chains, clock boundary/expiry, secret-bound fence receipt, mutation grant, runtime release state, the exact classified migration target schema, exact expected observation artifacts and fixed adapter request/result schemas. Unknown protocol versions, artifact substitutions, cross-phase evidence and arbitrary command/path/environment input are rejected. SecurityStore independently compares the complete optional observed source proof with the persisted proof for its admission phase and durably records `needs_reconcile` before returning a rejected-proof error.
5. **Completed — durable single-use security authority.** Security schema v14 persists canonical phase specs and verified chains, revalidates prerequisite rows and the live fence at permit/observation, consumes stateful-breaking grants exactly once, records a per-project bootstrap reservation/receipt, journals rejected source proofs as an explicit `abort_pending → compensated` pre-effect recovery state, reserves the exact drain epoch/token before atomically promoting it into the fence, records a separate base-backup boundary identity, records complete signed action-grant claims under a durable single-use nonce, persists executor-signed prepared intents before authorization, and binds accepted deploys to exact signed build candidates. `NeverInstalled` bootstrap needs no nonexistent backup or fence; installed deploys do.
6. **Completed — regression and full verification.** Latest bare `bin/ci` exited 0 on
   2026-07-16: strict fmt/Clippy, 284 executable Rust tests, five browser TAP tests,
   schema/document checks and optimized release build, with no ignored or skipped tests. Release
   bundles, backup evidence and Phase 6 authorization share one canonical bounded ASCII
   schema-version validator.
7. **Completed — closure finding remediation.** Receipt-less source rejection now retries an idempotent abort only after independently observing the effect absent, then atomically restores the original phase. Rejected proofs cannot mutate committed rows; foreign effect evidence is journaled before artifact-authority validation; successful ticket reconciliation projects the committed receipt into the controller; classification authority directly binds the intent policy/project and has stateful/rollback resolver coverage. The remaining Gemini artifact-digest hypothesis was rejected because the receipt digest binds the external observation digest and the final artifact set as separate canonical fields.
8. **Completed — final independent closure.** Final manifest `ffc7846689b2cd9ce034c496dbef75fb9bec60403cd922c09d72daece0bfc1fb` (58 implementation files, excluding `.agent`, `.idea`, `.git` and `target`) passed `bin/ci` and the configured cross-model closure round. No task-related P0/P1/P2 finding survived local source verification. DeepSeek Pro returned `PASS`; DeepSeek Free and Gemini Flash were partial; Gemini Pro was attempted but skipped by its provider despite a subsequent healthy route check. Exact dispositions are recorded in `review.md`.
9. **Completed — rimg Phase 2 operational contracts.** The existing checkout at `/home/denai/RustroverProjects/rimg` now implements explicit schema inspection/migration, persisted drain/fence, truthful readiness, coherent SQLite-plus-masters backup, bounded recovery/deploy scripts and cancellation-safe write leases. Bare `bin/ci` passes 31 executable tests; one benchmark is intentionally ignored and the gate reports local `cargo-audit` unavailable.
10. **Completed — real Phase 6B adapters and first-bootstrap driver.** The root socket, signed
    intent/grant authority, canonical phase specs, fixed rimg/backup/Kamal/health adapters and
    hardened transient units are implemented. The optional mutation runtime sequentially drives
    accepted backup and first-bootstrap deploy work outside the socket deadline. Deploy admission
    reopens a build-key-signed candidate, live source snapshot, installed policies and initial
    release state, derives the effective class and rejects installed upgrades/rollback. Testing,
    Building and Preflight are exact signed candidate observations with only the live root disk
    reservation rebound; Deploying, Health and Soak run through the real privileged adapter layer.
    Terminal receipt replay promotes the exact root bundle and commits release state without a
    second privileged effect. Chrony evidence is collected through a policy-pinned fixed command.
    The non-root candidate handoff uses exact build UID plus reader GID and `2750`/`0440` modes, so
    the capability-free executor can read it while the controller cannot. The external producer is
    the documented non-privileged integration point and remains responsible for source bytes,
    isolated CI/BuildKit and candidate signing; no unsafe internal producer is implied.
11. **Completed — integrated local acceptance.** Bare `bin/ci` is green with 284 executable Rust
    tests and five browser tests. Earlier exact-manifest review of the 104-file bootstrap target
    passed DeepSeek Free, DeepSeek Pro and Gemini Pro after source/chrony transport and
    release-state crash findings were remediated. Production credentials, deployment and drills
    remain separate authorized installation work and were not performed.
12. **Completed locally — source-to-dashboard-to-bootstrap transport.** The source broker publishes
    a signed immutable Git archive; release-bundle schema v3 binds the exact OCI archive; the
    reader-group handoff, root-private promotion and Kamal import/loopback-registry flow revalidate
    the archive, registry digest and local image identity. Publisher and promotion crash windows
    recover only exact validated temporary links, candidate directories require exact setgid
    `2750`, and the source unit can write only its export store. The controller exposes versioned
    fail-closed prepare/execute/status/capability endpoints, while the browser validates inputs and
    renders unavailable, running, retryable, reconciliation and terminal states. Local HTTP smoke
    returned 200 for capabilities and health and 503 `mutation_unavailable` without executor
    authority, as designed.
13. **External-input milestone — not enabled or represented as complete.** A real installed
    non-root CI/image producer requires changes to the adjacent `rimg` build inputs and an installed
    BuildKit runtime: its current Dockerfile uses dynamic base references, network downloads and
    BuildKit cache mounts, while `buildctl`/`buildkitd` are absent on this host. The isolated
    authorizer still requires exact Access identities and credentials. Upgrades and rollback remain
    fail-closed until stable-routing and compatibility capabilities exist. Production installation,
    credentials, provider operations and deployment require separate authority.
14. **In progress — first rimg production bootstrap.** Production preflight confirms the dedicated
    runner and `kamal` network are healthy, with no existing rimg container, image, storage,
    bootstrap marker or incomplete recovery state. The adjacent checkout's bare `bin/ci` is green
    with 34 executable Rust tests plus operational-script checks; one benchmark is intentionally
    ignored and local `cargo-audit` is absent while remaining mandatory in GitHub CI. The previously
    broken hosted-CI native dependency path now builds the pinned development toolchain and exposes
    its pkg-config metadata. Production config disables the not-yet-implemented webhook receiver,
    mounts only the real Sartuli source and verifies old-container Docker health during rollback.
    DeepSeek Pro closure found no surviving deployment defect: two ERR-trap concerns were disproved
    against Bash's real exit semantics, while its missing migrated-recovery coverage was accepted
    and added for both restore success and failure. A fresh bare `bin/ci` then passed the complete
    target. Commit `429c1f6` (`feat: harden rimg production operations`) records the exact clean
    candidate; its commit hook repeated the complete green gate. The next external boundary is an
    explicitly authorized push through the repository deployment workflow. After bootstrap, the native
    dashboard will reach rimg through a loopback-only per-connection systemd socket proxy that
    dynamically selects the current Kamal container; no rimg port or nginx route will be public.

## Owned paths for the current milestone

- `Cargo.toml`, `Cargo.lock`
- `src/backup.rs`, `src/build.rs`, `src/phase6.rs`, `src/source.rs`
- `src/build_source.rs`, `src/build_attestation.rs`, `src/oci_handoff.rs`
- `src/installed_source.rs`, `src/installed_deploy.rs`, `src/deploy_driver.rs`
- `src/controller.rs`, `src/executor.rs`
- `src/executor_socket.rs`, `src/protocol/`, `src/bin/rdashboard-executor.rs`,
  `src/bin/rdashboardd.rs`, `deploy/systemd/`
- `src/domain/operation.rs`, `src/domain/states.rs`
- `src/store/mod.rs`, `src/store/security.rs`
- `src/web/routes.rs`, `web/`, `README.md`, `PLAN.md`
- corresponding `tests/` and fixtures
- workflow artifacts in this directory (not for commit)

## Verification contract

- Required full gate: `bin/ci`
- No targeted `cargo test`, `cargo check`, `cargo clippy`, or alternative partial verification.
- Formatting may be applied as a mechanical edit, but it is not verification.
- Final evidence must include command, exit status, remaining warnings/failures, and final diff inspection.

## Current verified state

- Resolved diagnostic history: a real OTP-authenticated request initially reached the production
  origin but was rejected by its JWT verifier. No cookie or JWT was requested from the user or
  written to logs.
  Bounded denial-category diagnostics are implemented with regression coverage for missing and
  duplicate assertions plus audience, email, token-type and every library validation failure. The
  log contains only a fixed category string, never the assertion, claims, email or request path.
  DeepSeek Pro's focused review found missing category-mapping coverage and a low-value allowlist
  cardinality disclosure; both were corrected. Its subject-category naming note was narrowed as two
  intentionally distinct cases: malformed subject claim versus configured-subject mismatch. The
  final bare `bin/ci` exited 0 with 288 executable Rust tests (131 library, one `rdashboardd`, 156
  integration), five browser TAP tests, strict formatting/Clippy, schema/document checks and the
  optimized release build. Commit `e72137f` and release SHA-256
  `34fabbc64211bef17c23f51fdeca3f72258de26cc940d97b00c2b60c47da7a27` were installed for
  diagnosis and then superseded by `823c5cc`; throughout both deployments the service remained
  healthy and assertion-free protected requests returned 403. The diagnostic request identified
  the mismatch without weakening verification.
- The post-diagnostic authenticated request was rejected as
  `header_algorithm_or_type_invalid`. Cloudflare's current contract signs application tokens with
  RS256, while RFC 7519 defines `typ` as optional and case-insensitive when present. The verifier
  incorrectly required exact `typ: JWT` before signature validation. The completed fix preserves
  the exact RS256 and key/signature/issuer/audience/identity checks, accepts an absent `typ` or
  case-insensitive `JWT`, rejects any other present type, and splits algorithm/type denial
  categories with regression coverage. Fresh bare `bin/ci` exited 0 with 289 executable Rust tests (132
  library, one `rdashboardd`, 156 integration), five browser TAP tests, strict formatting/Clippy,
  schema/document checks and optimized release build. DeepSeek Free returned `PARTIAL/CORRECT` and
  DeepSeek Pro returned `ANSWERED/PASS` for fingerprint
  `2be07b4d0c1f00b35ad15e359e11fb2dc20ceec30c942da294281453164936d0`; neither found a
  security or correctness defect. Commit `823c5cc` and its exact gated binary are installed. The
  operator's real browser smoke renders the dashboard, current snapshot, fresh telemetry and a
  connected SSE stream; no post-deployment authenticated denial or service restart was observed.
- Production runs the exact locally gated `rdashboardd` SHA-256
  `c8e1a6fa33a0f60326d49cb605a98b91a250f32cc3f967c5d991aafafd702230`. The controller,
  executor and private bridge are active with zero restarts. Loopback and bridge `/health` return
  200, while protected requests without an Access assertion return 403.
- Cloudflare Access is active for `dev.4u.ge`: an unauthenticated public request redirects to the
  configured team login and exact application audience. The path-scoped ACME bypass reaches Kamal
  Proxy and leaves the root protected. Kamal Proxy records the rdashboard target as healthy and now
  stores a trusted Let's Encrypt certificate whose subject/SAN is only `dev.4u.ge`, valid from
  2026-07-16 through 2026-10-14. A locally verified TLS request reaches the origin and returns the
  expected fail-closed 403 without an Access assertion.
- Commit `f7019db` implements the fail-closed Cloudflare Access origin boundary and the nginx-free
  Kamal Proxy bridge contract. The production systemd unit requires Access configuration; every
  route except the redacted `/health` probe validates the exact signed application token at the
  origin. The bridge units bind only the installed `kamal` network gateway and remain disabled.
- Final bare `bin/ci` on `f7019db`'s tree exited 0 with 287 executable Rust tests, five browser TAP
  tests, strict formatting/Clippy, schema/document checks and optimized release build. The first
  post-review run failed only on two strict Clippy forms, which were corrected without suppression.
- DeepSeek Pro found the missing production-required Access guard; the unit and config parser now
  fail startup when the three values are absent or partial. DeepSeek Free reviewed the corrected
  target and returned READY. Its clock-failure SSE observation was not applied because immediate
  closure is the safer fail-closed behavior and authentication itself also rejects an unavailable
  clock.

- Final bare `bin/ci` on 2026-07-16 exited 0 with 284 executable Rust tests (127 library, one
  `rdashboardd`, 156 integration), five browser TAP tests, strict formatting/Clippy,
  schema/document checks and the optimized release build. `git diff --check` is clean.
- `/tmp/rdashboard-phase6b-oci.manifest` freezes 24 source, systemd, test and browser files; all
  entries verify and its SHA-256 is
  `a6fe2b10fc39c6bb046bf4d01959e2449fbb372410510345175251fa7c197414`.
- DeepSeek Pro returned PASS in both source-to-OCI closure rounds. Its two below-P2 hardening
  observations were accepted: runtime validators now require exact setgid `2750`, and candidate
  attestation directories are canonical, held open and inode-revalidated across the file read.
  The final manifest differs from the second reviewed target only by that accepted directory
  hardening and passed the complete gate. Gemini Pro was checked but unavailable, so it was not
  represented as having reviewed this closure target.
- Manual local HTTP QA used the release binary on `127.0.0.1:3100` with temporary databases and no
  executor: `/health` and `/api/v1/mutations/capabilities` returned 200, mutation status returned
  503 `mutation_unavailable`, and strict CSP/security headers were present. In-app interactive
  browser control was unavailable in this session, so click-level visual QA was not claimed.
- The observation-only `rdashboard` and read-only executor are installed and active on production.
  No mutation credential, Git fetch, source export, candidate build, provider effect, push or
  `rimg` deployment was performed. The dashboard is publicly reachable only through the exact
  Cloudflare Access application and existing Kamal Proxy TLS route; the origin remains loopback plus
  private-bridge only.
- Commit `8c4ca0c` records the 107 owned implementation files after the final green gate. Only
  `.agent/` and the user-owned `.idea/` remain untracked; neither was included in the commit.

## Historical verification log (superseded by the current state above)

- The final Phase 6A tree at manifest `ffc7846689b2cd9ce034c496dbef75fb9bec60403cd922c09d72daece0bfc1fb` passes the exact repository gate, `bin/ci`, with no warnings or failures and no surviving task-related P0/P1/P2 cross-model finding.
- Source acceptance and privileged execution have durable local contracts and deterministic crash-boundary coverage, including source TTL/control, a ticket spanning base backup through cutover, retryable first-admission/abort outages, retained ownership on pre-fence retry/reconciliation, singleton epochs, and filesystem-bound quantitative disk reservations; production process and external-effect adapters are not yet implemented.
- CI/build/Kamal schemas share one authorization-bound sealed release identity. Phase 6A adds canonical backup, classification, fence, runtime and grant documents plus exact phase-observation binding and reservation-evidence validation, but typed evidence must not be mistaken for proof that real isolated commands ran; adapter work remains Phase 6B scope.
- The read-only executor boundary and its controller client are live local code, not only contracts.
  Bare `bin/ci` exits 0 with 207 executable Rust tests, browser TAP, schema checks and optimized
  release build. The configured DeepSeek Pro security/concurrency review produced two important
  findings; both were remediated (frame-write/half-close separation and strict configured data-dir
  paths). Root/runtime directory trust and post-bind socket cleanup were also hardened. No
  production mutation, commit, push or deployment was performed.
- The repository is largely untracked/dirty baseline work; `.idea/` is user-owned and out of scope.
- Root mutation authority is now a staged, optional installation boundary: the service remains
  read-only without it, and when configured it requires one fixed systemd credential whose owner,
  mode, inode, exact size and derived public key match the root configuration. The temporary seed
  copy is zeroized. Phase-spec schema v2 and the owner-only adapter job store bind exact canonical
  request bytes to each fixed step and stop on conflicting requests. Hardened transient-unit plans,
  bounded execution/cleanup, canonical typed result reconciliation and read-only predecessor mounts
  are implemented. No concrete external-effect adapter or production mutation is enabled yet.
- The resumed adapter-input repair is verified by bare `bin/ci` on 2026-07-16: strict fmt/clippy,
  208 executable Rust tests, four browser TAP tests, schema/document checks and optimized release
  build all passed with no ignored or skipped test. Two earlier gate attempts correctly failed on a
  duplicate method/strict Clippy finding and missing release-plan fixture binding; both root causes
  were fixed before this green run.
- The operation-identity and first production rimg-admin slice is verified by bare `bin/ci` on
  2026-07-16: 218 executable Rust tests, four browser TAP tests, schema/document checks and the
  optimized release build passed. Earlier gate failures exposed and fixed only new compile/test
  fixture defects; no authorization or deadline check was weakened. Bare `bin/ci` in the existing
  `rimg` checkout also passed 32 executable tests; its benchmark remains intentionally ignored and
  local `cargo-audit` remains explicitly unavailable, as reported by that repository's gate.
- The distinct base-backup boundary, production `backup-adapter` and coherent snapshot runtime are
  verified on 2026-07-16. Exact escalated `rdashboard bin/ci` exited 0 with 225 executable Rust
  tests, four browser TAP tests, documentation/schema checks and optimized release build. The
  sandboxed run failed only at five Unix-socket tests because the sandbox denied socket operations
  with `EPERM`. Exact escalated `rimg bin/ci` also exited 0 with 34 executable tests; one benchmark
  remains intentionally ignored and the gate explicitly reports local `cargo-audit` unavailable.
  No production command, commit, push or deployment was performed.
- The production age/Google Drive slice is locally verified on 2026-07-16. Exact escalated bare
  `bin/ci` exited 0 with 231 executable Rust tests (82 library, one `rdashboardd`, 148 integration),
  four browser TAP tests, documentation/schema checks and the optimized release build. No Rust or
  browser test was ignored or skipped. Self-review fixed the transient systemd credential path to
  include the actual `.service` unit suffix and made upload replay recover a completed remote write
  by exact provider-stream SHA-256 before publishing local state. No provider upload, production
  command, commit, push or deployment was performed.
- The fence-job, root-fence, durable socket-admission, installed backup-only resolver and composite
  installed-effects slices are locally verified on 2026-07-16. Exact escalated bare `bin/ci`
  exited 0 with 252 executable Rust tests (101 library, one `rdashboardd`, 150 integration), four
  browser TAP tests, strict
  formatting/Clippy, documentation/schema checks and the optimized release build. Prepared-intent
  replay now reads the exact persisted request binding before invoking the resolver, so a restart
  cannot mint a conflicting token for the same idempotency key. Accepted grants are fully
  reconstructible from root state across restart.
- The installed backup-only driver and worker are locally verified on 2026-07-16. Exact escalated
  bare `bin/ci` exited 0 with 257 executable Rust tests (103 library, one `rdashboardd`, 153
  integration), four browser TAP tests, strict formatting/Clippy, documentation/schema checks and
  the optimized release build. The restart test reopens `security.sqlite`, reconstructs the same
  terminal operation and exact authorization/receipt, and proves the privileged backup effect was
  applied once. The socket acknowledges only durable admission; the worker scans pending accepted
  backups at startup and on a bounded retry interval. A final hardening pass moved every privileged
  data path below the root-owned executor StateDirectory, derives the pre-bound backing phase plan
  from the operation contract, refreshes time per sequential job and makes transient execution
  cancellation-aware during shutdown. No production effect, commit, push or deployment was
  performed.
- The installed source-broker process and protocol are locally verified on 2026-07-16. Exact
  escalated bare `bin/ci` exited 0 with 264 executable Rust tests (110 library, one `rdashboardd`,
  153 integration), four browser TAP tests, strict formatting/Clippy, documentation/schema checks
  and the optimized release build. Startup now completes remote reconciliation before binding the
  socket; operator pause blocks initial and live admission; synchronous broker work cannot block the
  async deadline; and root-side snapshot verification independently checks the installed Ed25519
  key, signature lifetime, repository/policy identity, target, sequence, attestation digest and
  active source controls. Deploy intent resolution, CI/build execution and production installation
  remain deliberately disabled. No production effect, commit, push or deployment was performed.
- The signed-candidate deploy admission and first-bootstrap worker are locally verified on
  2026-07-16. Bare `bin/ci` exited 0 with 273 executable Rust tests (117 library, one
  `rdashboardd`, 155 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build. The full bootstrap regression uses
  real filesystem policy/candidate/release stores and `security.sqlite`, drives the privileged
  Deploying/Health/Soak boundaries, reopens after a simulated terminal-receipt crash and proves
  each privileged effect remains single-application. A production-permission review exposed and
  fixed the capability-free executor's inability to traverse a build-UID-owned `0700` tree:
  deploy-policy schema v2 now pins a dedicated reader GID, the handoff requires exact
  `0750`/`0440` owner/group modes, and only the mutation-authority systemd drop-in grants that
  supplementary group. The external non-root producer remains responsible for source export,
  isolated CI/BuildKit and signing. No production service, credential, provider effect, commit,
  push or deployment was performed.
- The capability-free production transport follow-up is locally verified on 2026-07-16. The
  source broker now supports an exact `0750` source-owned runtime directory plus `0660` Unix socket
  while retaining peer-UID-0 protocol authentication; the mutation drop-in grants only the
  `rdashboard-source`, `rdashboard-build-readers` and host `chrony` groups. Private `0700/0600`
  source-socket mode remains supported, and broader modes fail closed. Release-state promotion now
  holds and revalidates the opened directory identity, removes only exact safe orphan temp files,
  and fsyncs that directory handle. Bare `bin/ci` exited 0 with 274 executable Rust tests (118
  library, one `rdashboardd`, 155 integration), four browser TAP tests and the optimized release
  build. The preceding run failed only because the new Tokio Unix-listener regression initially
  lacked a runtime; the test was corrected rather than removed. No production mutation occurred.
- After the Codex restart, the frozen 104-file implementation target was rechecked in the live
  workspace: `sha256sum -c /tmp/rdashboard-bootstrap-final-v2.manifest` verified 104 files with
  zero failures and the manifest digest remained
  `a42e113b1ce6ba020c192573a741016c904bed3114c9fac17df94fe34057cf55`. A fresh bare `bin/ci`
  exited 0 with the same 274 executable Rust tests, four browser tests, strict checks and optimized
  release build. Only workflow artifacts changed after the frozen implementation target; no
  production installation, mutation, commit, push or deployment occurred.
