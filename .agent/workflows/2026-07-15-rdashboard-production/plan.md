# rdashboard production implementation execution plan

Workflow: `.agent/workflows/2026-07-15-rdashboard-production`

Status: production control-center telemetry and project overview in progress

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

Exact rimg commit `126f27be578bb4b5f0b112ef869f1820c1ce999b` is now deployed privately by
successful workflow `29546207917`. One `rimg` web container is running Docker-healthy with zero
restarts, no host port bindings, exact private `kamal` address `172.19.0.14`, current schema 4/4,
ready/live 204, correct mounts and numeric storage ownership, an exact bootstrap marker and no
recovery files. Live verification exposed one production config drift: Kamal 2.12 treated the empty
clear webhook value as a value-less Docker env argument and copied a deploy-host URL, so health
reported `webhook.enabled=true`. Root-cause hotfix commit `b923636` adds an explicit strict
`RIMG_WEBHOOK_ENABLED=false` contract and is locally gated/reviewed. U036 confirms both pending
commits were pushed: `rdashboard origin/main` is exact `4ac31c7`, while `rimg origin/main` is exact
`b923636` and workflow `29575934981` is running. The rimg hotfix still requires a separately
authorized one-time container replacement because the bootstrap marker intentionally blocks a
second automatic deploy.

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
    candidate; its commit hook repeated the complete green gate. U027 confirms both repositories
    were pushed; `origin/main` contains the exact rimg commit. GitHub Actions run `29539612292`
    failed safely in CI before deploy because the relative pkg-config path was resolved from the
    dependency build-script directory on the clean hosted runner. The fix uses an absolute pinned
    native prefix plus exact pkg-config libdir/sysroot and checks that libjxl 0.12 is resolved from
    that prefix; `bin/bench` and direct Cargo commands receive the same clean-host contract.
    DeepSeek Free returned `ANSWERED/CORRECT`, both review observations were closed, and fresh bare
    `bin/ci` is green. Commit `87bcc89` (`fix: pin native CI toolchain paths`) records the exact
    four-file remediation and its commit hook repeated the green gate. Production remains
    untouched. U028 confirms the rimg-only follow-up push: `origin/main` is exact commit `87bcc89`
    and GitHub Actions run `29541492295` is executing CI for the full SHA
    `87bcc89d762f14a222ca7c62632bf0caf3a4bcda`. After CI and bootstrap, the native
    dashboard will reach rimg through a loopback-only per-connection systemd socket proxy that
    dynamically selects the current Kamal container; no rimg port or nginx route will be public.
    U029/U030 exposed a separate delivery-performance defect: rimg retained the Sartuli-style
    multi-stage native graph but not Sartuli's persistent Titanium cache boundary. Its hosted
    runner was therefore paying a complete cold native build on every push. The active remediation
    persists both the exact assembled toolchain and BuildKit's per-stage cache under an exact
    recipe/CPU key, uses a portable hosted `x86-64-v3` target, and makes bare `bin/ci` own the
    local update plus mandatory warm-cache postcondition. A mocked behavior harness covers cold
    export, warm skip, stale rejection, prior-cache import and failed-build preservation before the
    real local gate runs. The already-running `87bcc89` workflow is not cancelled: its runtime
    candidate is unchanged and still eligible for the authorized first bootstrap. That workflow's
    CI passed, but bootstrap stopped safely before image build because GNU `install -o 10001`
    interpreted the numeric UID as a missing account name. The root fix moves storage preparation
    into a locally tested script that creates exact modes first and applies numeric ownership with
    `chown`. Commit `ed06435` is locally gated and pushed; production still has no rimg container,
    marker or recovery state. The first cache-enabled hosted attempt then exposed a provider-only
    Docker-driver limitation before compiling native code: Ubuntu's default `docker` driver could
    not export a local BuildKit cache. Commit `3ac57a0` adds Docker's current official setup-buildx
    action so CI selects the cache-capable container driver; it is locally gated and pending push.

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

15. **Review and batch safe rimg dependency updates** — pushed; exact CI/deploy in progress
    - Pin all seven current Renovate PR heads and compare them to current main rather than trusting
      stale red checks.
    - Verify release/security claims against primary upstream sources, complete native archive
      checksum metadata, and confirm self-hosted runner compatibility for actions/checkout v7.
    - Apply accepted updates as one coherent mainline batch, run only bare `bin/ci`, obtain the
      required independent review, commit once, and avoid one production deployment per PR.
    - All seven accepted updates are integrated with independently verified native checksums. The
      review also fixed the shared native cache-key root cause with per-library manifests and
      stage-local arguments. Bare `bin/ci` and the final independent review are green; one exact
      task-scoped commit `126f27b` is complete. U035 confirms the manual push; `origin/main` now
      equals exact full SHA `126f27be578bb4b5f0b112ef869f1820c1ce999b`, and push run
      `29546207917` is the sole eligible deployment target. Superseded run `29543709811` completed
      CI for `3ac57a0` but was cancelled during its obsolete deploy build; its always-run cleanup
      released the Kamal lock and pruned the bounded BuildKit cache before the exact run started.
16. **Completed — connect private rimg health observation.**
    - Add a loopback-only socket-activated helper that discovers exact `service=rimg`, `role=web`
      Docker containers, revalidates running/healthy state and a private `kamal` IPv4 address, and
      execs the fixed systemd socket proxy to port 8080 without giving the controller Docker access.
    - Load a source-controlled rimg origin after the optional operator environment, keep rimg
      unpublished, and install no nginx route.
    - Treat a ps/inspect deploy race narrowly: skip only an exact full container ID confirmed
      removed after failed inspection; retain fail-closed behavior for every other Docker error.
    - Bare `bin/ci` is green after focused discovery-race, empty/ineligible, output-bound, command
      and systemd contract coverage. DeepSeek Pro's first review found the race and missing
      end-to-end coverage; both are fixed. DeepSeek Free was checked but its response was
      provider-skipped. Final DeepSeek Pro review returned `PASS`; its useful minor empty/ineligible
      coverage note was added and the complete gate passed again. Task-scoped commit `4ac31c7`
      records only the seven reviewed source/systemd/documentation paths. U036 reconciled local and
      remote `main` to the exact full commit. A fresh bare `bin/ci` exited 0 with 132 library tests,
      eight helper tests, all integration/browser/schema checks and the optimized release build.
      Production preflight found the prior controller healthy with zero restarts and the exact
      original rimg container still Docker-healthy on `172.19.0.14`.
    - Rollback-armed installation placed the exact release helper SHA-256
      `c6128e1886cc7519c40c62a2af52822cb3f0d62c5e3d38d4d61daf60ea7ea81e`, fixed environment and
      three systemd units. The socket is enabled/listening only on `127.0.0.1:18080`; controller,
      executor and socket are active, controller restarts remain zero, loopback and private-bridge
      health return 200, and an assertion-free protected request still returns 403. Direct proxy
      status reaches the exact old rimg container. Five consecutive production SQLite samples at
      the five-second collection interval report `rimg` as fresh `healthy`, proving the controller
      uses the new origin. The still-visible `webhook_enabled=true` detail is the known hotfix target.
17. **Close production webhook config drift** — pushed; exact CI and cutover decision pending
    - Replace Kamal's ambiguous empty clear env with non-empty `RIMG_WEBHOOK_ENABLED=false`; apply it
      after URL/secret overrides so disabled always wins and clears both values.
    - Reject every spelling except exact `true`/`false`; preserve the absent-variable development
      path and configured enabled behavior with focused tests.
    - Bare `bin/ci` passed twice plus the commit hook, each with two immediate native warm hits.
      DeepSeek Free returned `PASS`; its minor absent/alternate-string test notes were accepted.
    - Commit `b923636` records exactly README, production deploy config and config parser/test.
      U036 reconciled local and remote `main` to exact full SHA
      `b92363609d846fac32c43b2201104d7b77e70b65`; push workflow `29575934981` is running. The
      installed bootstrap marker must still block automatic replacement; bypassing that safety
      boundary requires the user's explicit decision and a zero-work, stop/boot/rollback procedure.
    - Workflow `29575934981` completed hosted CI successfully, built and published the hotfix
      image, then failed at the pre-app-boot marker with the expected automatic-deploy-disabled
      error. Its always-run cleanup released the Kamal lock and pruned BuildKit. The old exact
      production container remains running and healthy; no cutover occurred.
18. **Completed — persist the pinned cargo-audit tool in Titanium.**
    - Install exact cargo-audit 0.22.2 under the repository's already cached
      `.titanium/state/tools` subtree instead of
      compiling the unpinned latest crate on every hosted runner.
    - Extend the existing Titanium Actions cache without changing its three-path set. Bump its
      schema once, restore the existing native cache as a fallback, and bind the new exact key to
      the tool-installer contract so a version change creates a new combined cache without
      rebuilding unaffected native stages.
    - Make bare `bin/ci` own exact tool verification and audit execution locally and in hosted CI;
      cover cold installation, warm reuse, failure preservation and workflow cache wiring before
      the required full gate, review and one task-scoped commit.
    - Exact cargo-audit 0.22.2 now lives under `.titanium/state/tools` and is included in the
      existing single Actions cache without changing its path-derived cache version. Cache schema
      v2 falls back to the prior native key once, then saves the 23 MiB verified tool with unchanged
      native outputs. The installer is locked, atomic and
      exact-version checked; it cleans interrupted staging names and rejects/replaces stale tools.
      Bare `bin/ci` passed on the one-time cold fill, on immediate warm reuse, and again after
      review remediation. DeepSeek Free's initial P2 indentation-brittleness finding and two useful
      P3 test/cleanup notes were fixed; exact closure fingerprint `ea344ae…c8a7` returned `PASS`.
      Task-scoped commit `4845fd0` records the exact five-file optimization and its commit hook
      repeated the complete warm gate. No production effect was part of this optimization.
    - The first pushed v2 run `29577464028` exposed a path-version error in that commit: adding
      `.titanium/tools` made the old three-path archive ineligible even under its restore prefix.
      Its log explicitly reported `Cache not found` and began a full native rebuild. The run was
      cancelled before cache save or deploy. Follow-up commit `c270a33` moves the tool below the
      already cached state directory, removes the fourth cache path and makes the workflow test
      reject its reintroduction. Bare `bin/ci` passed on a 44-second one-time local tool fill and
      then in 3.9 seconds on exact warm reuse; the commit hook repeated the green warm gate. The
      global PreToolUse hook blocked the authorized push; U039 supplied the manual push and local
      plus remote `main` now equal full SHA `c270a338372dbd116cba2a67a2aeaccf7dfb5d79`.
    - Push run `29578601776` attempt 1 restored the exact prior native key (1,691,046,582 bytes),
      confirmed two immediate native warm hits, compiled cargo-audit once in 5m19s, passed the full
      check step and saved exact v2 key
      `rimg-titanium-v2-Linux-x86-64-v3-73161ae825d7e23945e955e3504d897d1c5a9a4a50c16c61039964194c0a7af1`
      (1,699,203,266 bytes). Attempt 2 restored that exact v2 key, again confirmed both native warm
      hits, contained no installer invocation and passed the full check step in 2m38s. Both
      marker-ineligible deploy jobs were cancelled after CI; always-run lock release and the 1 GB
      BuildKit cleanup completed. Production remains on the original healthy exact image with no
      recovery residue.
19. **Completed — retain the production native BuildKit graph.**
    - Replace the impossible 1 GB builder/cleanup ceiling with one shared 6 GB maximum and a 12 GB
      minimum-free-space boundary. The live VPS had 22 GB free before the change.
    - Bind both daemon GC and always-run workflow prune values in the native-cache contract and
      document the production policy.
    - Exact prior deploy evidence showed the unchanged `vips-build-base` package layer missing and
      all dependent native build commands rerunning; the image build took 1108.947 seconds. Live
      inspection after bounded cleanup showed only 217.6 MB in the dedicated builder.
    - Bare `bin/ci` passed, then the commit hook repeated the complete gate. DeepSeek Free returned
      `ANSWERED/PASS` with no P0/P1/P2. Its Buildx compatibility P3 is disproved by the live runner's
      own `docker buildx prune --help`, which exposes `--min-free-space`; the requested two-pass
      runtime cache proof remains the post-push acceptance test.
    - Task-scoped commit `10d549e` records the exact four workflow/config/test/documentation paths
      and is present exactly on `origin/main`.
    - Exact run `29580086966` attempt 1 passed CI in 3m18s, cold-filled the recreated builder to
      5.79 GB and built the image in 1140.6 seconds. The bootstrap marker then blocked cutover as
      designed; always-run lock release succeeded, the new bounded prune deleted 0 B and left
      17 GB filesystem space free.
    - Attempt 2 reran the same `10d549e` SHA. CI again passed in 3m18s; every expensive native and
      Rust stage was `CACHED`, image build time fell to 14.0 seconds and the whole production job
      ended at the same marker in 25 seconds. Cleanup again deleted 0 B and retained the 5.79 GB
      graph. The original `126f27b...` container remained Docker-healthy and ready, its marker was
      unchanged and no recovery file appeared.
20. **In progress — perform the authorized one-time rimg replacement.**
    - Revalidate exact local/remote `10d549e` provenance, the sole healthy prior container,
      zero-work readiness, current schema/storage and the repository's marker/recovery hooks.
    - Release the existing bootstrap marker exactly once, rerun the already verified workflow SHA
      and preserve its rollback/recovery state until the candidate is healthy.
    - Require the sole resulting container to use exact image `10d549e...`, remain private on the
      `kamal` network with the existing mounts, report schema 4/4 and `webhook.enabled=false`, and
      leave an exact renewed marker with no recovery residue.
    - Require rdashboard's loopback helper and consecutive stored project samples to observe the
      replacement as healthy before closing the cutover.
    - The real rolling gap exposed a directly coupled observer defect: three parallel five-second
      probe bursts exhausted systemd's default failed-start limit while no healthy container
      existed, permanently failing the listening socket. Restore the live socket, disable the
      helper's start-rate limit while retaining its existing deadlines/resource bounds, bind that
      contract in source tests and complete the exact rdashboard gate before installation.
    - The live socket was restored and eight consecutive samples are healthy. Bare `bin/ci` passed
      the durable three-file correction; commit `1ce0e3c` records only its unit, contract test and
      documentation. The global PreToolUse hook blocked the authorized push, so source-controlled
      production installation awaits the user's manual push. The temporary prior-marker backup was
      removed only after the exact new marker and empty recovery state were revalidated.
21. **In progress — reshape the dashboard into a project-oriented production control center.**
    - Inventory the existing metrics schema, collection cadence, controller state, web payload and
      UI before changing the product surface. Preserve the proven executor and authorization
      boundaries while removing prototype-only presentation.
    - Add durable historical host rollups for current, one hour, one day, one week and one month,
      using medians for completed windows and explicit insufficient/unavailable states.
    - Make `rimg` the first reusable project overview with health and resource history, an hourly
      repository-size series, and first-class deployment, dependency-update, GlitchTip-error and
      backup summaries. Never synthesize data for an integration that is not configured.
    - Replace the unexplained generic production-operation block with a concrete project deploy
      journey only when the direct controller/executor path can expose honest admission, progress,
      failure and recovery states. Persist a Telegram-notification outbox for terminal failures;
      external delivery remains disabled until its credential and destination are configured.
    - Keep the dense monitoring surface semantic, keyboard-readable and stable under live updates;
      use responsive overflow or drill-down without hiding status from assistive technology.
    - Verify each coherent slice only through bare `bin/ci`, obtain the required focused
      cross-model review for the final substantive diff, commit only owned paths, and do not deploy
      or enable an external integration without fresh evidence and authorization.
    - Completed local host-history slice: `MetricsStore::host_history` merges retained minute
      sketches and still-raw samples into aligned completed-minute hour/day/week/30-day windows,
      returns medians with explicit covered/expected minute counts, and is exposed through the
      authenticated `/api/v1/host-history` route without blocking the async reactor. The browser now
      compares live values with all four periods in one semantic table and labels partial history;
      the unexplained manual Intent/Attempt-ID workspace was removed while its fail-closed HTTP API
      remains intact for the later project-specific deploy journey.
    - Browser-platform decision: use a semantic table with row and column headers plus horizontal
      overflow for the dense repeated mapping, centralized live regions for failures, and text-first
      values rather than canvas-only charts. The relevant bundled guidance was
      `guides/accessibility/accessible-error-announcement.md` and
      `guides/performance/interactions-in-complex-layouts.md`; no new browser feature or dependency
      is required. In-app visual automation was unavailable because this session exposes no browser
      JavaScript control tool, so the current evidence is the browser contract suite and inspected
      responsive markup/CSS rather than a claimed screenshot pass.
    - Bare `bin/ci` exited 0 for the host-history slice: 132 library tests, all binary/integration
      tests including the raw-plus-rollup median and HTTP regressions, six browser tests, schema/doc
      checks and the optimized release build. Two preceding runs failed only on the exact rustfmt
      layout and a new test exceeding the deny-level line limit; both were corrected without an
      allow attribute or weakened assertion.
    - Completed local project-history slice: the project card now loads bounded, project-scoped
      deploy/rollback/backup attempts from the durable controller journal and renders their exact
      phase, result, target and bounded failure summary. Integrations without a real source remain
      visibly unavailable rather than receiving placeholder values. Bare `bin/ci` exited 0 with
      132 library tests, all integration tests including the new controller/API contracts, six
      browser tests and the optimized release build; preceding failures were rustfmt and a
      deny-level test line-count finding, both fixed structurally.
    - Completed local accepted-repository history slice: source protocol v2 measures the logical
      byte sum and regular tracked-file count of the exact accepted Git tree, revalidates the
      accepted ref across measurement and returns only the typed result through the root-peer source
      socket and control protocol v2. The controller never receives repository paths or Git command
      authority. Metrics schema v4 enforces one stored point per project per hour across restarts,
      retains bounded 30-day history, and preserves last-known data alongside collection errors.
      The `rimg` card shows latest commit/file count/size plus covered changes for hour/day/week/month.
      Bare `bin/ci` exited 0 with 132 library tests, all binary/integration tests including 19
      store/web contracts, seven browser tests and the optimized release build. Earlier runs found
      only formatting, missing schema derive/Clippy structure and one literal old protocol version;
      each was corrected without weakening validation.
    - Final local closure review used DeepSeek Free against the complete non-workflow diff and
      returned `PASS`. Its valid multi-project DOM-performance finding was fixed by replacing only
      the completed project's card after operation or repository fetches. A systemd contract now
      proves the mutation drop-in extends rather than resets the executor's source-socket group.
      The final bare `bin/ci` exited 0 after both changes with 132 library tests, all binary and
      integration contracts including nine executor-socket and 19 store/web tests, seven browser
      tests and the optimized release build. The preceding run exposed only a one-line
      deny-level Clippy function-length regression from the new retry branch; initialization was
      extracted into a cohesive helper rather than suppressing the lint.
    - Task-scoped commit `16d61b9` records the exact 26 product, contract, deployment and
      documentation paths. Workflow artifacts remain intentionally uncommitted. No push or
      production deployment was performed for this redesign slice.
22. **Completed — deploy the pushed control-center history slice to production.**
    - Local `main` and `origin/main` both resolved to full
      `16d61b9a8c87ab3062afbc8f5ae0586d8d3ca05b`; its already green bare `bin/ci` release binaries
      were installed with an ERR-trapped copy of the complete pre-v4 SQLite state and exact prior
      binaries/units retained under the root-only release state.
    - The attempted source-broker preflight failed before service or data mutation because `rimg`
      is private and production intentionally has no broker credential. The broker clears ambient
      Git credential helpers and HOME, so silently borrowing the deploy user's SSH key would violate
      its privilege boundary. The rollout was narrowed to the controller, executor, UI, schema-v4
      migration and affected observation units; source config, credential, service and state remain
      absent and the repository card truthfully reports that source as unavailable.
    - The installed controller and executor hashes are `09e1ac4…5a7` and `8218783…0680`; both
      services are active with zero restarts. Loopback and private-bridge health return 200, an
      assertion-free snapshot returns 403, the rimg observer is ready/idle, and the unchanged sole
      `10d549e…` container remains healthy. Metrics schema is v4 with advancing five-second host and
      rimg project samples; repository samples remain zero by design until an explicit private-Git
      credential contract exists.
    - Public `https://dev.4u.ge/` returns the expected Cloudflare Access 302, no warning-or-higher
      controller/executor journal entries were emitted, and the temporary bundle plus unused seed
      were removed. The authenticated operator-visible render requires the user's existing browser
      identity and is the only smoke not reproducible from the server shell.
23. **Pending — add an explicit private-Git credential contract for the source broker.**
    - Provide a bounded, auditable credential through the broker's source-controlled systemd
      boundary, pin host identity, preserve ambient-credential clearing, and prove read-only access
      to exactly `mrDenai/rimg` before enabling the existing repository-history path in production.
    - Re-run the bare gate, independent review and rollback-armed source installation; do not treat
      the unused production system identities as evidence that the service is configured.
24. **Completed — compact the production overview around operator decisions.**
    - Remove redundant host labels and successful-history prose, remove PSI from the primary table,
      and derive received/sent traffic volumes from monotonic network counters across raw and durable
      minute-rollup history. Counter resets must skip the unknowable interval rather than inventing
      bytes, and the API must expose traffic coverage separately from resource median coverage.
    - Replace expanded project cards with one semantic table row per project and columns for state,
      resources, deployments, backups, repository, updates and errors. Keep raw health/executor/source
      diagnostics out of the summary and preserve truthful compact loading, empty, unavailable,
      stale and failure states.
    - Follow the bundled accessibility and CSS-layout guidance: native table headers/caption, DOM
      order matching visual order, native horizontal `overflow:auto`, and text plus state symbols so
      color is never the only signal. Verify only through bare `bin/ci`, inspect the final diff,
      complete independent review, then create one task-scoped commit without touching workflow
      artifacts.
    - Host-history API schema v2 now reports received/sent byte totals with independent covered
      durations, excludes counter-reset intervals, and keeps resource medians unchanged. The primary
      UI omits the redundant node/history prose and PSI row, and renders current plus historical
      network traffic as volume rather than rate.
    - Projects now render as one compact semantic row with the requested operational columns. Raw
      health and executor/source diagnostics never enter the overview; compact truthful states retain
      available last-known information. DeepSeek Free returned `PASS`, and the final bare `bin/ci`
      exited 0 with 132 library tests, all integration/browser contracts and the optimized release
      build. Task-scoped local commit `8de0a3d` records exactly the seven product/test/documentation
      paths; production was not changed.
25. **Completed — deploy the pushed compact overview to production.**
    - Reconcile local and remote `main` to the exact reviewed commit and ensure the only dirty paths
      are the authoritative workflow artifacts.
    - Perform read-only production preflight for disk, active/restart state, current binary and UI
      hashes, metrics schema, rimg health and rollback inputs before changing services or data.
    - Build/install the exact pushed controller assets with an ERR-trapped binary/data rollback,
      restart only the affected service, then verify loopback/private health, authenticated API
      schema v2 behavior, advancing metrics/project samples, public Access routing and clean logs.
    - Record exact installed hashes and residual unavailable integrations; do not install or enable
      the private source broker or any mutation/provider integration in this slice.
    - Provenance and preflight complete: local and remote `main` both resolve to full
      `8de0a3dd9b4f2351f3a7e316b6c80674d9bcb10c`; bare `bin/ci` exited 0 on that target. Production
      has 16.79 GB free, one healthy exact `10d549e...` rimg container, active zero-restart
      controller/executor/bridge/health socket, metrics schema v4 with advancing host/rimg samples,
      no repository samples by design and no controller warnings in the preceding 30 minutes.
      Current controller hash is `09e1ac4...5a7`; candidate hash is `7cf5a9f...1d18`.
    - Installed only `rdashboardd` with a stopped-controller copy of the full StateDirectory and
      previous binary retained under root-only release
      `/var/lib/rdashboard-releases/20260717T154924Z-8de0a3dd9b4f`. The ERR trap would restore both;
      candidate health succeeded and the installed hash exactly matches `7cf5a9f...1d18`.
    - Post-cutover controller is active/running with zero restarts; loopback and private-bridge
      health return 200, assertion-free snapshot remains 403, and 36 host plus 36 rimg samples
      advanced during the initial soak. Metrics schema remains v4, current network counters are
      present, rimg remains the sole unchanged healthy `10d549e...` container, and public Access
      routing returns 302. There are no error log lines. The one source-unavailable warning is
      expected because the private broker remains uninstalled; one assertion-missing warning was
      generated by the deliberate fail-closed smoke.
    - The exact deployed binary contains the compact project table and history API v2 browser
      contract. Authenticated visual smoke could not be automated because this session exposes no
      browser-control JavaScript tool; no screenshot claim is made. Repository samples remain zero
      and every unconfigured integration remains truthful and disabled.
26. **In progress — remove redundant table chrome and connect real project sources.**
    - Remove the host section heading/status and internal table scroll containers. Keep semantic
      tables in document flow and make column sizing fit the operator viewport without clipping or
      nested scrolling.
    - Inventory the existing root-observation, rimg health, repository-source and provider seams.
      Implement the first complete credential-free project source with durable current/history data
      and one compact table cell, rather than replacing “Not configured” with a static label.
    - Determine the exact credential/configuration contracts required for private repository,
      dependency-update and GlitchTip data. Implement safe local contracts when they form a coherent
      slice, but keep production disabled until the real credential and provider identity exist.
    - Cover responsive semantics, collection success/failure/restart behavior and API/browser output
      with high-signal tests; verify only through bare `bin/ci`, complete independent review and
      create one task-scoped commit without including workflow artifacts.
    - Completed the first credential-free source locally: a mode-`0600` controller-only Unix socket
      activates a short-lived root helper, revalidates the exact healthy rimg container and returns
      bounded numeric Docker statistics without giving the controller Docker authority. Current
      CPU/RAM plus hour/day/week/month medians and counter-derived traffic/I/O history now persist in
      metrics schema v5; stale repeats do not enter rollups and v4 migration is covered directly.
    - Removed both internal table scroll containers and the visible host heading/freshness chrome.
      Tables remain semantic and use the document scrollbar with fixed percentage columns.
    - Repository, dependency-update and GlitchTip sources remain outstanding. The repository broker
      implementation exists but production has no installed source identity/credential; GitHub
      dependency and GlitchTip query credentials do not yet exist in the controller boundary. These
      cells remain truthful rather than fabricated while the next source slice is implemented.
27. **Completed — diagnose and resolve rimg run `29592074146` / job `87924148149`.**
    - Read the exact GitHub job metadata and log, pin the failing SHA/step and distinguish CI,
      BuildKit, bootstrap/cutover, health, rollback and cleanup outcomes.
    - Confirm the failure against current `/home/denai/RustroverProjects/rimg` source and production
      state. Fix repository-owned behavior at its source with a regression contract; do not weaken
      the bootstrap marker, cache, cleanup, rollback or health gates.
    - Run only the rimg bare `bin/ci`, complete required review and create one task-scoped commit if
      source changes are necessary. Push/deploy remains subject to the established explicit
      authorization and local hook boundary.
    - The candidate image built and published successfully; `.kamal/hooks/pre-app-boot` then failed
      because `/var/lib/rimg/.bootstrap-deployed` intentionally disables push cutovers after
      bootstrap. The production container stayed healthy and no candidate boot occurred.
    - Added a pre-effect workflow decision that turns this expected disabled state into a successful
      no-op before BuildKit, storage mutation, Kamal locking, image publication or cleanup. The
      unchanged `predeploy-migrate` remains an independent hard fail-safe.
    - Both marker states and all guarded effects are covered by operational tests. Bare `bin/ci`
      passed in `/home/denai/RustroverProjects/rimg`; DeepSeek Free found no P0-P2 issues.
28. **Completed — deploy the first project-resource source and activate the rimg CI guard.**
    - Reconcile both exact remote heads (`rdashboard` `5961b63b4b4c...`, `rimg`
      `00cdcbfd9df5...`) and deploy only the already gated rdashboard binary/helper/unit slice.
    - Preserve the complete pre-v5 StateDirectory plus all replaced binaries and units in a
      root-only release; automatically restore them if installation, startup, health, socket or
      exact-hash verification fails.
    - Verify schema v5, the mode-`0600` controller socket, the fixed resource protocol, advancing
      fresh rimg samples, loopback/private-bridge health, Access fail-closed behavior and clean
      service logs. Keep the running rimg image unchanged.
    - Production now runs controller hash `53474403a072...ff425` and helper hash
      `5243aa45b64c...968bf`; rollback state is retained at
      `/var/lib/rdashboard-releases/20260717T174409Z-5961b63`. Controller and both observation
      sockets are active with zero controller restarts. The resource protocol returned bounded
      real CPU, RAM, network and block-I/O counters, and fresh project samples advanced every five
      seconds. Both loopback and private-bridge health returned 200, a protected assertion-free
      request remained 403, public Access routing returned 302, and warning/error journals were
      empty after cutover.
    - rimg run `29600740331` passed. Its deploy job evaluated automatic-deploy mode, then skipped
      builder, storage, Deploy, lock and cache effects exactly as designed; the sole healthy
      production container remains image `10d549e...`. The disposable curl image pulled only for
      bridge verification was deleted after confirming no container used it.
29. **Completed locally — add the private-Git credential contract for the source broker.**
    - Upgrade canonical installed source schema to v3 and bind each SSH project to its own fixed
      credential names plus exact private-key and known-hosts SHA-256 identities. Reject missing,
      partial, cross-project or HTTPS-attached bindings.
    - Load project keys only through a separate systemd credential drop-in. Clear ambient Git/SSH
      environment and require the exact key, no agent/default identity/password/interactive prompt,
      strict host checking, the exact pinned file, no global fallback and no host-key update.
    - Validate credential inode/owner/mode/length/content before the first reconciliation. Keep the
      controller credential-free and preserve existing source attestation/export behavior.
    - Add `rdashboard-source-config`, which reads only fixed root-owned credential paths, derives
      attestation public identity and per-project digests, and emits canonical secret-free JCS. The
      pilot remains `auto_deploy=false` until the stable dashboard-owned cutover exists.
    - DeepSeek Free returned `PASS` with no P0-P2 findings for fingerprint
      `a0b72b1cac94...0b095`. The first bare `bin/ci` exposed one needless pass-by-value Clippy
      failure; the parser now takes a slice rather than suppressing the lint. The repeated full gate
      passed with 137 library tests, 10 root-helper tests, two config-generator tests, all
      integration/browser/schema/doc checks and the optimized release build.
    - No SSH key, source config, source repository state, systemd drop-in or source service has been
      created or enabled on production. Activation still requires the generated public deploy key
      to be granted read-only access to `mrDenai/rimg`, followed by an exact policy/config install
      and a rollback-armed production smoke.
30. **Completed locally — implement stable repeated `rimg` deployment through `rdashboard`.**
    - Trace the current first-bootstrap-only driver, installed-release state, executor effect and
      rollback contracts to identify the exact missing installed-upgrade path rather than treating
      private source activation as the whole deployment problem.
    - Implement one coherent, restart-safe update and rollback journey with persisted observable
      state, exact release identity and high-signal failure-path tests. Preserve the existing
      fail-closed source, authorization, backup and migration boundaries.
    - Verify only through bare `bin/ci`, obtain a focused independent review of the substantive
      change, commit only owned product/test/documentation paths, and leave production unchanged
      until remote provenance and a fresh deployment authorization exist.
    - Installed code-only deployments now preserve one stable private `rimg` route, adopt the
      bootstrap release, start exact content-addressed candidate backends, switch only after direct
      health, soak through the consumer route, and automatically restore the previous release on
      health or soak failure. Restart replay observes the persisted router target rather than
      oscillating it, and current/last-known-good release state advances atomically only after the
      terminal forward soak.
    - Cross-attempt verified base backups remain freshness- and policy-bound; rollback uses its own
      durable branch while retaining the original deploy authorization. A sole-owned-alias check
      rejects any foreign `rimg` network claimant before repeated cutover or rollback. DeepSeek Pro
      identified that alias gap and the implementation closes it; the full bare `bin/ci` passed
      with 142 library tests, all integration/browser/schema/doc checks and the optimized release
      build.
    - Production remains unchanged. Activation still requires the candidate build producer,
      installed mutation/runtime/release documents, source service and a rollback-armed first
      adoption. Retention/pruning of older content-addressed releases is a separate bounded-storage
      policy and must not be improvised as a destructive production side effect.
