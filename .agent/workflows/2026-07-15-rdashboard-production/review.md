# rdashboard production implementation review

Workflow: `.agent/workflows/2026-07-15-rdashboard-production`

Status: compact production overview deployed; private source and provider integrations pending

Last updated: 2026-07-17

## Reviewed target

- Git baseline: `3317d1535faa6a1300268b4c3b6bd8f6699844b4`
- Scope: Phase 5 source admission, controller/executor authorization and recovery, build evidence, Kamal planning, and tests.
- Final reviewed content manifest (implementation files, excluding `.agent`, `.idea`, `.git` and
  `target`): `a9ebfcce4853cdeef9fcbed7180750ffbc99858a7485dfe0f3bc7a702e2e01a2`.
- Final source-adapter hash: `ecf20900ce27309bae1d6cef2e9bbcd9b6af710e8afa4205e1220dba62a8db3d`.
- Final dispatcher fingerprint: `4937d22a5e6c087afbba52a79c66fa26d7147796aaa94573f8bc556c228367a5`.
- No commit, production mutation or deployment is part of this review.
- Round 1 dispatcher fingerprint: `f6415b72292ba991aa5c0bfa805f49c8e7ac7e3ca569adda82c612e98147d457`.
- Round 2 dispatcher fingerprint: `1c8d6c32ba28921a0d358098aab0cfdf3a2ad72039a8cbc0a4ee5ea472116034`.
- Hardening-round content manifest (implementation files, excluding `.agent`, `.idea`, `.git` and
  `target`): `cc20a8344b905d5567b301331581b0fda78187d6ac1267d78c9e9a1e3580b0c4`.
- `bin/ci` mode at the pinned target: `0755`.

## Independent agent review

Three read-only agents reviewed distinct lenses: source admission; build/Kamal isolation; controller/executor recovery. Confirmed findings were:

- no production source or external-effects adapters yet;
- completed reconciliation results could become stale, expired same-head attestations could not renew, and divergence resolution lacked a durable audit-safe close path;
- source gate errors for interactive operations used automation-only controller paths;
- executor phase ordering could be bypassed by mutating an authorized in-memory operation;
- live source validation had a check/effect race;
- disk reservation was a per-project mutex rather than quantitative global accounting;
- rollback and write-fence prerequisites were weaker than the intended mutation boundary;
- build context did not validate the exact Dockerfile/FROM evidence and build/Kamal evidence was not bound to one immutable release identity.

## Cross-model consultation ledger — round 1

| Route | Status | Fingerprint | Output | Disposition |
| --- | --- | --- | --- | --- |
| `deepseek-free` (`opencode/deepseek-v4-flash-free`) | ANSWERED | `f6415b…d457` | `/tmp/rdashboard-consult/deepseek-free/response.md` | Confirmed missing production adapters and source-recovery gaps; fixes in progress. |
| `gemini-flash` | ANSWERED | `f6415b…d457` | `/tmp/rdashboard-consult/gemini-flash/response.md` | Confirmed stale divergence journal, reconciliation identity, Dockerfile/base binding, and SSE cursor risks; source/build findings fixed, SSE remains queued. |
| `gemini-pro` | PARTIAL | `f6415b…d457` | `/tmp/rdashboard-consult/gemini-pro/response.md` | Confirmed build/Kamal evidence lacked sequence, attestation, policy, exact executor authorization, and a sealed release bundle; fixed. |
| `deepseek-pro` | ANSWERED | `f6415b…d457` | `/tmp/rdashboard-consult/deepseek-pro/response.md` | Confirmed live-gate TOCTOU and divergence audit risks; mutation ticket and durable divergence events implemented. |

## Cross-model consultation ledger — round 2

| Route | Status | Fingerprint | Output | Disposition |
| --- | --- | --- | --- | --- |
| `deepseek-free` (`opencode/deepseek-v4-flash-free`) | ANSWERED | `1c8d6c…6034` | `/tmp/rdashboard-consult-round2/deepseek-free/response.md` | Confirmed disk-ledger and filesystem-hardening risks. Live observations, single emergency-floor accounting, trusted-path checks and tests were added; Git object-format hypotheses were rejected against real Git tests. |
| `gemini-flash` | ANSWERED | `1c8d6c…6034` | `/tmp/rdashboard-consult-round2/gemini-flash/response.md` | Confirmed stale disk snapshots, double-counted reserve, mutation-ticket ambiguity and empty-history SSE cursor behavior; all four were fixed with regression coverage. |
| `gemini-pro` | ANSWERED | `1c8d6c…6034` | `/tmp/rdashboard-consult-round2/gemini-pro/response.md` | Confirmed the foundational absence of a production executor/socket boundary and independently policy-derived authorization. This remains explicit adapter work; narrower journal/resource findings were fixed. |
| `deepseek-pro` | ANSWERED | `1c8d6c…6034` | `/tmp/rdashboard-consult-round2/deepseek-pro/response.md` | Confirmed orphaned mutation tickets and controller-transition coupling. Safe abort/re-observation and operation-kind-derived live gating were implemented. |

## Post-implementation hardening round

Three independent agents split the stable tree into build/filesystem, executor/controller and
source/security lenses. Confirmed findings were:

- the selected Dockerfile path and installed base-registry allowlist were absent from immutable
  build identity; repository `VOLUME` was accepted;
- release-bundle pre-link temporaries for an older digest were not reconciled globally;
- a canonical bare Git repository on a separate mount bypassed the staging-root emergency floor;
- a ticket persisted before source-proof storage could become permanently orphaned after
  `blocked_sha` or installed-policy changes;
- ambiguous forward health/soak journal rows prevented rollback; rollback health evidence collided
  with candidate health evidence; recovery readiness had a per-project TOCTOU; fence release read
  unvalidated receipt columns; BackupOnly skipped disk admission.

All were fixed with focused regressions. The resulting security schema is v5 and preserves the
forward journal through an audited rollback takeover rather than rewriting history.

| Route | Status | Input/output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-free` (`opencode/deepseek-v4-flash-free`) | ANSWERED after a bounded retry | `/tmp/rdashboard-review-round4/deepseek-free-retry` | Independently confirmed Dockerfile-path and base-registry identity gaps. Generic BackupOnly and cross-filesystem dismissals were rejected against the actual budget and mount-point behavior. |
| `gemini-flash` | ANSWERED | `/tmp/rdashboard-review-round4/gemini-flash` | Its Docker positional-option, hardlink and SSE replay claims were disproved; its broad ticket concern was narrowed to the real ticket-before-proof/control-change crash window and fixed. |
| `gemini-pro` | ANSWERED | `/tmp/rdashboard-review-round4/gemini-pro` | Source-proof/branch claims were rejected after tracing; its recovery/effect concern overlapped the verified per-project gate defect. |
| `deepseek-pro` | ANSWERED | `/tmp/rdashboard-review-round4/deepseek-pro` | Generic ticket, immutable-epoch data-race and SSE semaphore claims were not reproducible; no additional finding survived local verification. |

## Verified and fixed findings

- Source divergence now preserves append-only incidents; owner resolution verifies the real accepted ref, clears the pending ref journal, and closes the audit event transactionally.
- Reconciliation identity includes mutable source controls/state; expired same-head attestations are renewed for direct and reconciliation ingress; pause expiry and unblock are reevaluated.
- A durable per-project mutation ticket serializes accepted-ref changes with the live mutation window.
- Interactive and automated source failures share trusted source-admission guards without actor confusion.
- Security receipts enforce the authorization-bound phase plan before resource acquisition; forged phase skips and authorization mutations fail closed.
- Rollback requires a committed deployment and excludes stateful-breaking releases; fence acquisition requires the owning project-deploy resource and a committed backup.
- Dockerfile bytes and digest must match the immutable export; FROM stages and digest-pinned bases must match exactly; remote ADD, external COPY, repository syntax frontends, and privileged RUN features are rejected.
- `AuthorizedReleaseIdentityV1` binds attempt, project, head, source sequence, attestation, installed policy, and executor authorization. Source export, frozen context, image build, Kamal plan, reservation, and `ReleaseBundleV1` preserve that identity.
- Disk reservations are now authorization-bound quantitative claims in a restart-stable global ledger. Admission is serialized with the project reservation lock, conservative aggregate capacity is enforced across projects, release is atomic, and Testing/Preflight reservation evidence must match the authorized digest.
- Disk capacity is re-observed locally for every acquire/reacquire, bound to a filesystem identity and freshness window, and aggregates operation peaks while counting the emergency floor once. Security schema v3 refuses to guess live v2 claims.
- Failed live mutations release their ticket only after the effect is re-observed absent; ambiguous or applied effects retain the ticket for reconciliation.
- Security recovery is project-scoped, Git execution revalidates trusted ownership/inodes and kills descendant process groups on deadline, and control/security stores have explicit schema versions and fail-closed migrations.
- Known reconciliation is detected before acquiring new phase resources, while slots held across a possibly applied external effect remain fenced. Replaying a committed receipt no longer depends on a new disk admission.
- `ReleaseBundleV1` has canonical versioned encoding, independent digest verification and an atomic owner-only single-link durable store. The source broker has an OS singleton lock plus a durable epoch fence.

## Discarded or deferred hypotheses

- Rechecking attestation expiry at the mutation boundary was rejected: expiry limits admission replay, while the mutation boundary requires current broker head/sequence/policy and a durable ticket. Expired same-head ingress now creates a new sequence before admission.
- A source push after an already completed external mutation cannot be prevented without making Git depend on a completed mutation forever; the ticket intentionally spans live check through effect completion and then releases.
- Registry lock lifetime through the deploy phase is intentional for the ephemeral loopback registry, but production recovery of registry state remains unimplemented.
- Production binaries/adapters, independently policy-derived executor intents, symlink-safe Kamal mount resolution, typed non-empty backup/migration/health evidence and causal failure capsules remain open and must not be represented as complete.

## Final closure round

Three read-only agents independently rehashed and reviewed final manifest
`a9ebfcce4853cdeef9fcbed7180750ffbc99858a7485dfe0f3bc7a702e2e01a2`:

| Agent lens | Result |
| --- | --- |
| source/security | No P0/P1/P2 findings; owner-only boundaries, backend and redirect rejection, immutable config digest, post-mutation validation and initialization marker were consistent. |
| executor/controller | No P0/P1/P2 findings; config-drift handling, recovery ordering, keep release and SQLite projection remained fail-closed. |
| build/filesystem | No P0/P1/P2 findings; canonical `0700` boundaries close transient pack/ref disclosure and remain compatible with the intended standalone bare repository. |

The final cross-model consultation used the same dispatcher fingerprint:

| Route | Status | Output | Disposition |
| --- | --- | --- | --- |
| `deepseek-free` (`opencode/deepseek-v4-flash-free`) | ANSWERED | `/tmp/rdashboard-review-final4/out3/deepseek-free` | `NO_FINDINGS`; inspected the complete source adapter and crash windows. |
| `gemini-flash` | PARTIAL | `/tmp/rdashboard-review-final4/out3/gemini-flash` | `SECURE`, with no finding. Its only open question was the future administrative retirement runbook for deliberately retained unknown-project staging. |
| `deepseek-pro` | ANSWERED | `/tmp/rdashboard-review-final4/out3/deepseek-pro` | `PASS`. Its low-confidence cleanup concern was rejected after inspecting `reconcile_failed_fetch`; its staging-root race idea is fail-closed under the process-wide lock and atomic `mkdir`. |
| `gemini-pro` | SKIPPED | `/tmp/rdashboard-review-postfix/out/gemini-pro` | Provider quota was exhausted. The route was attempted and is not represented as having reviewed the final manifest. |

The final hardening closes the confirmed Git trust-boundary findings from the preceding reviews:

- canonical repositories support only the files ref backend; staging pins the same backend and
  rejects reftable/common-dir/worktree redirects;
- local config is bounded, include-free and digest-pinned for the adapter lifetime;
- Git initialization, pack publication, ref publication and keep-marker release have explicit
  owner-only modes, filesystem durability and crash recovery;
- canonical root/repository, refs, packed refs, pack artifacts and object topology are validated
  before and after privileged Git writes; loose objects and external alternates fail closed;
- a durable identity-bound initialization marker distinguishes removable incomplete staging from
  initialized-but-damaged state that requires explicit reconciliation.

## Verification evidence

- Final `bin/ci` exited 0 on manifest `a9ebfcce…e01a2`: strict fmt/clippy, 139 Rust tests, the browser TAP suite, schema/doc checks and optimized release build. No test was ignored or skipped.
- An earlier `bin/ci` attempt failed only because sandbox DNS could not resolve `index.crates.io`; the approved networked rerun reached the compiler and subsequent gates passed.

## Current verdict

The modeled Phase 5 trust chain is green and its final review is closed without a surviving
P0/P1/P2 finding. Production adapters and the executor process/socket boundary remain explicit
Phase 6A work and must not be represented as live deployment capability. Gemini Pro did not review
the final manifest because the provider rejected the attempt for quota; the other three configured
routes and all three independent agents completed their reviews.

## Phase 6B root authority and adapter-job slice

- The root process optionally loads the executor-intent Ed25519 seed only from the fixed systemd
  credential path. It rejects symlinks, wrong owner/mode/size, inode replacement and a seed whose
  derived public key differs from the installed key identity. The temporary raw seed buffer is
  zeroized after constructing the signer.
- The same bounded configuration constructs the lifecycle-aware action-grant verification keyring.
  Omitting the authority preserves the existing read-only executor; loading it still does not make
  mutation requests executable.
- Authorized phase-spec schema v2 materializes every fixed step as a bounded canonical request
  whose file digest covers the exact attempt/request/project, phase/branch, fixed profile and result
  schema, policy/authorization identities, classification, prerequisites and expected artifacts.
- The adapter job store uses replay-stable owner-only directories and `create_new` request files,
  revalidates directory and file identities, fsyncs the request and directory chain, accepts only an
  exact replay, and blocks execution when a result already exists until a typed reconciliation path
  validates it.
- One intermediate `bin/ci` attempt stopped at two deny-level clippy findings in the new job-store
  module (`unused_mut` and `verbose_bit_mask`). Both were corrected without weakening the gate.
  The final bare `bin/ci` exited 0 with 201 Rust tests, browser TAP, schema/document checks and the
  optimized release build; no test was ignored or skipped.
- Remaining boundary: constrained systemd transient-unit execution, typed adapter result evidence,
  concrete rimg-admin/backup/Kamal effects and restart reconciliation. Socket mutation stays
  fail-closed, and no deployment, production credential installation or external effect occurred.

## Phase 6A implementation and pre-closure review

Three independent agent lenses reviewed manifest
`ba687b4e44154c472d5798fd78d0d41fd3cce156ad24b33ea5980a2a03310e84` before the final
hardening pass. Confirmed findings were:

- missing previous-release evidence could be mistaken for permission to bootstrap;
- stateful-breaking approval was not a typed, operation-bound, single-use authority;
- authorized phase specifications were shallowly JSON-checked and one scalar digest could not bind
  multiple privileged phases;
- drain/source validation and fence acquisition were ordered so an early failure could leave a
  fence without a committed drain boundary;
- backup artifact digests did not prove one canonical manifest/encryption/upload/readback chain,
  freshness evidence was replayable, and the base upload/readback deadline was incomplete;
- cutover backup identity and fence evidence were not carried as a typed migration prerequisite;
- protocol versions newer than the fixed argv implementation were accepted.

The integrated fixes add exact protocol-v1 negotiation, executor-derived classification from
installed schema transitions, canonical verified base/cutover chains, new-clock freshness,
`Draining`, secret-bound fence receipts, per-branch/per-phase specification history and security
schema v8. The final local hardening also added permit-time prerequisite expiry, active-fence and
prior-chain revalidation, a durable single-use mutation-grant ledger and a durable per-project
bootstrap reservation/receipt. Bootstrap is now explicitly `NeverInstalled`, not inferred from an
absent previous bundle, and does not require a backup of nonexistent state.

The current full `bin/ci` result is green: 156 Rust tests, browser TAP, strict fmt/clippy,
schema/doc checks and optimized release build. A final self-review also moved the drain invariant
into the security boundary itself: fence acquisition now requires committed primary `BackingUp`
and `Draining` receipts, with a direct regression test for the backup-only rejection. Final
manifest hash, repeated three-agent review and all available cross-model dispositions will be
appended after the closure round. No root adapter, production mutation, commit or deployment has
been enabled.

The first closure review of the preceding manifest found three additional boundary defects: the
stateful source ticket began only at drain and could be released without undraining after a
pre-fence failure; non-backup observations were not exact-bound to their authorized plan/release
artifacts and could carry future-phase evidence; and reservation evidence could be constructed with
public inconsistent fields. The integrated hardening now acquires the ticket before base backup,
retains source/project/disk ownership across transient retry and ambiguous reconciliation, rejects
artifact substitution and cross-phase evidence in both the typed spec and security store, makes
reservation fields private and validates their digest/bounds before release-bundle sealing, and
revalidates backup/drain receipts on idempotent fence acquisition. Dedicated regressions exercise
all of those failure paths. A subsequent self-review also found and closed an exact-authorization
gap in `Migrating`: the classified candidate schema version is now part of the authorized spec
digest and an observation carrying a substituted schema version is rejected. A new exact-manifest
closure review is still required before this section is signed off.

The next closure pass confirmed two more authority/recovery defects and closed them before taking a
new manifest. Installed transition contract digests could previously be paired with arbitrary
caller-supplied plan/compatibility digests; schema inspection now embeds typed, self-validating
evaluation envelopes bound to the exact intent, installed policy, project, schema pair, migration,
contract, verdict, observation and evaluation time, and classification validates the nested
evidence again. Separately, a source check followed by an unavailable compensating abort could
mark a phase `needs_reconcile` before any effect or receipt existed, leaving no convergence path.
That outage now keeps the original phase source-blocked and its ticket/resources owned so the same
phase can replay admission idempotently. SecurityStore also independently binds observed source
proofs to the persisted `BackingUp` or `Deploying` proof; test fixtures no longer bypass that root
authority. Exact-manifest closure review remains pending.

The next hardening pass closed the three findings from that exact-manifest review. Schema
inspection and classification now prove that both verified release bundles belong to the policy
project and carry the exact inspected schemas. The resolver accepts an opaque derived
`ReleaseClassificationAuthorityV1` and re-derives its full evidence chain, so a serialized
self-digested classification alone cannot authorize a privileged phase. Schema-version syntax is
shared by build, backup and Phase 6 validation. Finally, source-proof observation uses exact
optional equality and a rejected, zero or out-of-range sequence commits `needs_reconcile` before
the typed error escapes the transaction. Regression coverage includes forged-but-self-consistent
schema inspection, invalid recomputed bundle schemas, omitted persisted proof and restart after a
rejected first proof. The current complete `bin/ci` is green with 159 Rust tests, browser TAP,
strict fmt/clippy, schema/doc checks and optimized release build. A new frozen manifest and full
three-agent/four-model closure review remain pending; no production effect, commit or deployment
has been enabled.

## Phase 6A receipt-recovery closure candidate

- Candidate implementation manifest (58 files, excluding `.agent`, `.idea`, `.git` and
  `target`): `4ebc06aa28bf04528f602d9033b9b9d0d8afe8fa9d64b0add377302593505a10`.
- `bin/ci` exited 0 on 2026-07-15: strict fmt/clippy, 166 Rust tests, browser TAP,
  schema/documentation checks and optimized release build; no ignored or skipped tests.
- Security schema v9 adds an explicit durable `abort_pending → compensated` state for a rejected
  pre-effect source proof. Recovery independently observes the effect absent, retries the
  idempotent ticket abort, atomically removes the rejected per-attempt proof and restores the
  original `intent_persisted` phase without lowering the project trust high-water mark.
- Committed journal rows are immutable under source-proof admission; foreign effect evidence is
  persisted as `needs_reconcile` before artifact authority checks; bound deploy specifications
  require the exact persisted live-source proof while BackupOnly remains proof-free.
- Successful completion of a ticket whose phase receipt was already committed now projects that
  exact receipt from controller reconciliation into the next execution state, clearing the
  reconciliation capsule without reapplying the external effect.
- Release classification directly binds the phase intent to the installed policy generation and
  project. Full authority-to-resolver tests cover stateful and code-rollback specifications plus
  stale/mismatched authority rejection.
- This candidate was superseded by the final hardening and exact-manifest closure below. No commit,
  push, production mutation or deployment was authorized or performed.

## Phase 6A final exact-manifest closure

- Final implementation manifest (58 files, excluding `.agent`, `.idea`, `.git` and `target`):
  `ffc7846689b2cd9ce034c496dbef75fb9bec60403cd922c09d72daece0bfc1fb`.
- Bare `bin/ci` exited 0 on 2026-07-15: strict formatting/lints, 169 Rust tests,
  browser TAP, schema/documentation checks and optimized release build; no ignored tests,
  warnings or failures.
- The final hardening narrows required live-source proof to each release class's actual admission
  window, refuses to guess the origin of unresolved pre-v9 reconciliation rows, binds reconciled
  receipt projection and ticket completion to the transition's true recovery origin, and treats
  stateful `Draining` as a mutation boundary. Regressions cover stateful proof windows, unsafe v8
  migration, stale completion receipts, late health reconciliation and Draining terminal safety.

| Route | Status | Output | Disposition |
| --- | --- | --- | --- |
| `deepseek-free` | PARTIAL | `/tmp/rdashboard-phase6a-review-final/out/deepseek-free` | It did not complete its final trace and incorrectly compared the committed `HEAD` tree with the explicitly dirty/untracked implementation manifest. Its Draining rollback hypothesis also omitted the committed-deploy requirement. No verified finding. |
| `gemini-flash` | PARTIAL | `/tmp/rdashboard-phase6a-review-final/out/gemini-flash` | Its four findings describe the deliberately separate manual data-restore/recovery path: code rollback requires a committed deployment, stateful-breaking has no automatic rollback, and reconciliation retains the project lock fail-closed. These contracts are explicit in `PLAN.md`; real recovery adapters remain Phase 6B. No Phase 6A P0/P1/P2 finding survived. |
| `gemini-pro` | SKIPPED | `/tmp/rdashboard-phase6a-review-final/out/gemini-pro` | The provider produced no review after one dispatcher attempt. Required post-failure `consult check gemini-pro` reported the configured Gemini 3.1 Pro High route `OK`; the missing perspective is recorded and was not substituted or represented as reviewed. |
| `deepseek-pro` | ANSWERED | `/tmp/rdashboard-phase6a-review-final/out/deepseek-pro` | `PASS`. Both observations were explicitly non-findings because the status-first admission and source-trust regression checks already enforce the invariants. |

No task-related P0/P1/P2 finding remains for Phase 6A. The dashboard is still not deployed and no
root adapter, process/socket boundary, systemd unit, `rimg` mutation, commit, push or deployment was
performed. Phase 6B remains blocked until the separate `rimg` repository exposes explicit
migration, persisted drain/fence, truthful readiness/backup and manual recovery APIs.

## Phase 6B rimg contract closure and identity handoff

- The existing `/home/denai/RustroverProjects/rimg` checkout now supplies explicit schema
  inspect/migrate/restore commands, persisted maintenance/drain/fence administration, truthful
  versioned health, coherent SQLite-plus-masters backup, bounded deploy recovery scripts and
  cancellation-safe write leases.
- Bare `bin/ci` exited 0 on 2026-07-15: strict format/clippy, 31 executable tests and all operational
  script checks passed. One benchmark remains intentionally ignored; the repository gate reports
  `cargo-audit` skipped locally because the optional binary is not installed.
- DeepSeek Free returned `PASS` on the reviewed rimg state. DeepSeek Pro reviewed fingerprint
  `d17ca8e9b0e7dae6183076616cf0713a0d4c71daff1f69e9793c23293815ffbb` and found a real cancelled
  coalescer-leader hang plus two bounded consistency issues. The coalescer now owns an independent
  generation task and regression test; background image work retains its write lease after HTTP
  cancellation; admin transitions verify row counts; queue capacity is enforced in one immediate
  transaction. Its remaining sequential-webhook observation is retained for bounded receiver
  pressure and must be measured in the deployment drill.
- `rdashboard` security schema v10 now reserves the rimg drain epoch/token before the external drain
  effect and atomically promotes that exact identity into fence acquisition only after committed
  base-backup and drain receipts. The regression proves epoch and token equality across the handoff.
- Bare `rdashboard bin/ci` exited 0 with 171 Rust tests, browser TAP, schema checks and optimized
  release build; no ignored or skipped rdashboard tests. Production adapters, root socket/systemd
  isolation and deployment drills remain Phase 6B work. No commit, push or deployment was performed.

## Phase 6B read-only root executor boundary

- Added the real `rdashboard-executor` process with a strict root-owned configuration, fixed
  `/run/rdashboard/executor.sock`, exact Linux peer-UID authorization, bounded one-request framing,
  mandatory request EOF, explicit protocol negotiation, response/request binding, per-connection
  deadlines, bounded concurrency and graceful draining. The socket refuses pre-existing paths and
  removes only its own recorded socket inode.
- The executor returns real Linux host observations. Project Docker/systemd requests return an
  explicit `project_observation_not_configured`, and intent/execution requests return
  `mutation_authority_unavailable`; no unavailable operation can report success.
- `rdashboardd` can use the fixed executor socket. Connection/protocol failure becomes a persisted
  `signal_lost` host sample with empty values and a sanitized reason; it never silently switches to
  local collection or preserves stale values as healthy. Local collection remains an explicit
  development mode only when the socket variable is absent.
- Added hardened controller/executor systemd units. The executor validates that both its config
  directory and runtime socket directory are root-owned and not group/other writable; the config
  file must also be root-owned, regular, bounded and not writable by group/other.
- The initial sandboxed `bin/ci` run reached the socket tests and failed because the sandbox denied
  Unix bind and `SO_PEERCRED` with `EPERM`. The required unsandboxed gate then exposed a real test
  runtime error, which was fixed by running the bind test inside Tokio. A later remediation gate
  exposed that Rust path comparison normalizes repeated separators; raw bytes are now checked and
  covered by regression.
- Final bare `bin/ci` exited 0 on 2026-07-15: strict formatting/clippy, 179 executable Rust tests,
  browser TAP, generated-schema verification and optimized release build. No ignored or skipped
  rdashboard test was reported.

DeepSeek Pro reviewed the boundary through the global consultation route and returned `CONCERNS`
in `/tmp/rdashboard-root-executor-review`:

- Its important frame-shutdown finding was accepted. Frame writing and request half-close are now
  separate, so a successfully written server response is not reclassified by a later shutdown
  error while request EOF remains mandatory.
- Its important data-directory finding was accepted with the development contract preserved.
  Explicit `RDASHBOARD_DATA_DIR` values must now be absolute, normalized and bounded; only the
  built-in local default remains relative.
- The low-confidence parent TOCTOU scenario requires replacement of a root-owned, non-writable
  runtime directory by root and therefore does not cross the stated attacker boundary. Directory
  ownership/mode checks were nevertheless added before bind.
- The low-confidence shutdown-loop concern did not survive: every task already owns the same
  bounded timeout and a dead Tokio timer/driver would also prevent a redundant outer timeout from
  firing. The `/proc`/`/sys` `ReadOnlyPaths` suggestion was documentation-only and not a defect.
- Independent self-review found and fixed a post-bind failure path that could leave a stale socket:
  the inode-bound cleanup guard is now established before permissions are changed.

No P0/P1/P2 finding remains for this read-only boundary. It is implemented and locally verified,
but not installed on a host. Signed action grants, real fixed-argv mutation adapters, sanitized
Docker/systemd project snapshots, recovery drills and production deployment remain Phase 6B work.
No commit, push, production mutation or deployment was performed.

## Phase 6B transient adapter runner and typed result boundary

- Installed policy timeouts are copied into every authorized step and canonical request, then used
  as exact `RuntimeMaxSec` limits plus a bounded outer cleanup deadline.
- Fixed profiles run through root-owned `/usr/bin/systemd-run` and `/usr/bin/env -i`; caller input
  cannot select a shell, executable, path, environment or systemd property. The unit uses a strict
  filesystem view, private temporary/device namespaces, privilege and executable-memory controls,
  task/file/memory bounds and control-group termination. Adapter stdout/stderr are set to `null` in
  both the transient unit and child process so secrets are neither retained nor journaled.
- The current owner-only job directory is the sole writable bind. Completed predecessor job
  directories are individually revalidated and mounted read-only at fixed
  `/inputs/step-NNNNN` paths; no later/current job directory is exposed through that input view.
- A successful process exit is not completion. The runner requires a stable owner-only bounded
  canonical result, validates exact attempt/request/project/phase/branch/profile/schema bindings,
  enforces the prerequisite time window and verifies an ordered prior-result digest chain.
- Backup manifest/local/upload/readback results reuse the existing typed backup contracts;
  schema-inspection results reuse the classified schema evidence contract; phase observations must
  contain phase-valid artifacts matching the authorized specification. Existing valid results are
  reconciled, while conflicts, malformed documents and missing chain members fail closed.
- Complete result chains project to one final observation digest, phase-valid artifacts and an
  optional reusable verified backup chain. The last result is hash-bound to every predecessor, so
  the projected receipt cannot omit an earlier readiness/schema/backup step.
- Intermediate gates exposed one Rust import error, two overlong functions and three strict Clippy
  style findings; each was corrected without suppressions. The final bare `bin/ci` exited 0 on
  2026-07-16 with 207 executable Rust tests, four browser TAP tests, documentation/schema checks and
  an optimized release build. No test was ignored or skipped and no warning/failure remains.
- The production adapter executables and their fixed credential/data mount profiles do not exist
  yet, so runtime executable validation prevents effects and the mutation socket remains disabled.
  No systemd unit was executed, no production mutation occurred and no deployment was performed.

The focused first review used the exact state fingerprint
`4089c8e95950cef6dc9e6f20fa70c6ac68f825dba7fb88f5c3c33adf9efd15ec`:

- DeepSeek Pro returned `CONCERNS` in
  `/tmp/rdashboard-phase6b-adapter-review/deepseek-pro`. Its critical stale-state finding was
  accepted: a job prepared before execution now reconciles the freshly written result from disk
  instead of rejecting it because its cached state was `ReadyToExecute`. Its prior-file equality
  and appeared-after-prepare findings were also accepted and covered by regression tests.
- DeepSeek Free returned `DEFECTS_FOUND` in
  `/tmp/rdashboard-phase6b-adapter-review/deepseek-free`. Its prior-file finding matched the Pro
  review and was fixed once. Its output-reader leak was eliminated structurally by removing pipes
  and reader threads and setting both unit streams to `null`. Result files and their directory are
  fsynced before decode, and every result now satisfies both its prerequisite window and monotonic
  chain order.
- Independent self-review additionally bound schema-inspection results to the exact migration ID
  and classified candidate schema.

Both configured closure routes then returned `ANSWERED/PASS` for the focused question "do the
listed remediations close the earlier findings without a new P0-P2 defect?" at state fingerprint
`c929c2e54b9afe15a88a05322ba912710c76e6e74500bf4ff601c0a32518e1ac`:
`/tmp/rdashboard-phase6b-adapter-closure/deepseek-free` and
`/tmp/rdashboard-phase6b-adapter-closure/deepseek-pro`. Neither found a surviving P0-P2 defect or
an open question. Their only below-P2 observation was that the generic directory-sync helper allows
readable non-writable parents; every adapter job directory is still created and revalidated with
the stricter owner-only `0700` contract.

## Phase 6B signed action-grant authority

- Added deterministic canonical-CBOR Ed25519 action grants with an explicit signature domain,
  issuer and executor audience, key ID/epoch, bounded two-minute lifetime, actor/role, lease
  generation, exact intent and installed-policy digests, request identity and random nonce.
- Verification is exact-bound to caller expectations and rejects noncanonical payload/token
  encodings, trailing content, signature substitution, stale epochs, inactive/retired/revoked keys,
  issuer/audience mismatch and lifetime-edge reuse.
- Security schema v11 consumes verified grants in an immediate transaction. The nonce is globally
  single-use; only an exact repeat by the same attempt is idempotent, including after token expiry.
  First consumption outside the signed validity window fails without creating a row.
- The replay ledger stores the complete security-audit binding: signed schema and service
  identities, actor/role, lease, intent, request, policy, verification key, lifetime, grant digest,
  consuming attempt and consumption time. A v10-to-v11 migration creates the ledger without
  guessing authority.
- Mutation requests remain fail-closed. This layer does not yet load the root keyring or bind a
  signed executor intent to the socket request; those are required before fixed adapters can run.

DeepSeek Pro returned `CONCERNS` in `/tmp/rdashboard-action-grant-review`. Its important observation
that payload-shape validation did not independently enforce the durable `i64` ceiling for
`key_epoch` was accepted and covered by a regression. The oversized value could not pass the
existing exact epoch comparison because verifier keys already enforce that ceiling, but it now
fails earlier as structurally invalid. Its migration uncertainty did not survive direct source and
test inspection: the v10 arm executes `ACTION_GRANT_REPLAY_SCHEMA_SQL`, stamps schema version 11 in
`security_meta` through `finish_security_schema_upgrade`, and the v10-to-v11 integration test
passes. Its explicit issued-at check was defense-in-depth only because canonical claim validation
already requires `not_before_ms >= issued_at_ms` and the verifier rejects `now_ms < not_before_ms`.

## Phase 6B executor-signed operation intents

- Added separate canonical-CBOR Ed25519 executor intent receipts with a five-minute maximum
  lifetime and independent key lifecycle. They bind request and opaque intent IDs, project,
  operation kind, immutable target commit, proposed/effective release class, installed policy,
  source attestation/sequence, migration and rollback targets.
- Confirmation consequences are derived from the effective operation rather than accepted as
  caller text. Stateful-breaking intent receipts explicitly carry backup, write-drain, migration,
  no-automatic-rollback and manual-data-restore consequences.
- Bound verification rejects request/project/operation/SHA/policy substitution, malformed release
  and source combinations, noncanonical/trailing token encodings, signature tampering, invalid
  lifetime edges and stale/retired/revoked keys.
- Security schema v12 persists the complete signed token and claims before it can be returned to an
  authorizer. Request ID, intent ID, token and digest are each unique; an exact retry is idempotent,
  while any overlapping identity conflict fails closed across restart. Explicit v11-to-v12 and
  older migration coverage creates and validates the ledger.
- The protocol can represent a prepared signed-intent response, but the read-only executor still
  rejects preparation and execution until policy/source resolution, root credentials and socket
  integration are wired. No mutation path was enabled.
- The signed intent now derives its minimum role, with `admin` required for stateful-breaking deploy
  and code rollback. The security journal authenticates the authorizer signature and atomically
  binds the persisted intent, single-use nonce and attempt. Binding/role failures leave no grant
  row, exact same-attempt replay survives restart, and another attempt fails closed.

DeepSeek Pro failed to return this slice's focused review after two dispatcher attempts;
`consult check deepseek-pro` immediately afterwards still reported the route healthy. Gemini Flash
completed the fallback review in `/tmp/rdashboard-executor-intent-review-gemini` with four items:

- Its timing hardening was accepted. Consumption now rejects a timestamp before both the signed
  intent `not_before` and the durable `prepared_at` boundary, with regression coverage.
- Its claimed browser-lease bypass conflated the authorizer/controller tab lease with the
  executor's application write fence. `fence_journal` has no actor/tab-lease authority. The
  separate-origin authorizer signs the actor/role/lease claims; the controller validates the live
  lease during admission; root independently authenticates that signature, binds intent/request/
  policy, enforces the signed intent's minimum role and consumes the nonce.
- The authenticated-grant type is deliberately unbound until the root transaction compares it with
  the persisted intent. `authenticate_for_persisted_intent` returns only that type, and the only
  integrated consumption method performs the missing binding before insertion; the stronger
  expected-bound verifier remains for callers that independently own actor/lease expectations.
- Exact role equality in `ActionGrantExpectedBindingV1` checks the actor role claimed by a caller
  that owns an exact expectation. Minimum-role authorization is separate: the root accepts `admin`
  for an `operator` intent and rejects only `operator` for an `admin` intent.

## Phase 6B rimg operation hardening and production BackupCapture

- Security schema v13 adds a distinct base-backup boundary journal. Base backup uses its own exact
  epoch/token identity and cannot reuse or fabricate the later cutover fence; drain, fence and
  boundary transitions conflict and remain single-owner. Cutover capture instead requires the exact
  active fence identity and deliberately leaves that fence held for migration.
- The fixed `backup-adapter` verifies the installed `rimg-cli` identity and canonical operation
  identity, starts or resumes the exact base drain, invokes the coherent rimg backup command, and
  resumes writes only after all evidence validates. Crash replay reuses the already published
  snapshot and does not re-drain, replace randomized state or accept an identity change.
- Snapshot validation is recursive and fail-closed: fixed root inventory, exact masters inventory,
  owner-only regular files/directories, stable inode/size/digest observations, SQLite integrity and
  foreign-key checks, exact database-to-master references, current known rimg schema shape, internal
  rimg manifest binding, and a deterministic `RDBMSTR1` masters bundle with hard-link publication
  and post-link recovery. Invalid evidence keeps the base source drained.
- The backup transient profile exposes only `/var/lib/rimg/data`,
  `/var/lib/rdashboard-executor/backups`, `/var/lib/rdashboard-executor/locks` and the current `/job` as writable host
  paths. Tmpfiles install the backup/lock roots as root-owned `0700` directories.

The focused DeepSeek reviews found four real hardening gaps and two hypotheses that did not survive
source verification. Migration result replay was made deterministic after a crash, rimg backup and
migration now share an operation lock, recovery no longer removes a live backup lease, and bounded
retry/fallback behavior replaced unbounded ambiguity. The stale-fence hypothesis was rejected
because every admin action revalidates the exact active epoch/token against the persisted high-water
state. The claimed missing SQLite mutex was rejected because each connection sets its own mode and
the operations use distinct SQLite connections under WAL; no shared connection crosses threads.

Verification on 2026-07-16:

- Exact escalated `rdashboard bin/ci` exited 0: strict fmt/clippy, 225 executable Rust tests, four
  browser TAP tests, documentation/schema checks and optimized release build. The sandboxed gate
  failed only at five Unix-socket tests because the sandbox denied socket operations with `EPERM`.
- Exact escalated `rimg bin/ci` exited 0 with 34 executable tests. One benchmark remains
  intentionally ignored and the gate explicitly reports local `cargo-audit` unavailable.
- No production command, external upload, commit, push or deployment was performed. Age
  encryption, provider upload/readback, Kamal/health/soak adapters and mutation-socket orchestration
  remain open Phase 6B work.

## Phase 6B production age and Google Drive pipeline

- The fixed `backup-adapter` now streams the deterministic snapshot archive directly into pinned
  age X25519 without a persisted plaintext archive, fsyncs a pre-created mode-`0600` ciphertext,
  and publishes ciphertext plus canonical state through restart-safe hard-link reconciliation.
- Installed runtime authority binds the exact project/policy, age recipient fingerprint, age and
  rclone executable digests, canonical secret-free rclone config, Drive root folder, provider
  credential version and service-account digest. The upload and independent-readback units receive
  that account only through systemd `LoadCredential`; the source credential directory is
  inaccessible inside the sandbox and the runtime path includes the actual `.service` unit suffix.
- Google Drive upload uses a deterministic content-addressed key, immutable copy, exact-one object
  listing, provider ID plus MD5 version and canonical local state. A crash after remote completion
  but before state publication is reconciled instead of re-uploaded. Fresh upload, recovery and
  independent readback all require one stable `stat -> exact-length streamed SHA-256 -> stat`
  observation before evidence can be accepted.
- Self-review found and fixed two concrete pre-review defects: the systemd credential directory
  omitted the transient `.service` suffix, and immutable upload could not recover the crash window
  between remote completion and local state publication.
- Exact escalated bare `bin/ci` exited 0 after final remediation on 2026-07-16: 231 executable Rust
  tests (82 library, one `rdashboardd`, 148 integration), four browser TAP tests, strict
  formatting/Clippy, documentation/schema checks and the optimized release build. No Rust or
  browser test was ignored or skipped.

The focused first review used state fingerprint
`bd068febf78f9304a238401f4528d94ce141b898a98d8031ed81bd6cb16db672`:

- DeepSeek Free returned `ANSWERED/CONDITIONAL_ACCEPT` in
  `/tmp/consult-rdashboard-backup-free`. Its pending-file/umask scenario overlooked the existing
  transient `UMask=0077`, but the output path was hardened further by pre-creating the descriptor as
  `0600`, passing it as age stdout and fsyncing it. Its read-only backup-root observation was not a
  defect under `ProtectSystem=strict`; self-review instead made the unrelated root credential
  source directory explicitly inaccessible.
- DeepSeek Pro returned `ANSWERED/CONCERNS` in `/tmp/consult-rdashboard-backup-pro`. Both important
  findings were accepted. Fresh upload now verifies provider-returned SHA-256 before writing a
  receipt, and all remote verification requires identical metadata/identity before and after the
  streamed content read. Its monotonic-clock suggestion was rejected because these timestamps are
  durable cross-process evidence checked against an authorized wall-clock deadline and trusted
  clock boundary; a backward adjustment must fail the attempt rather than be masked by tolerance.
  Duplicate Drive names already fail closed and the suggested separate diagnostic variant was not
  a safety defect.

DeepSeek Pro then returned `ANSWERED/PASS` for the exact remediated tree in
`/tmp/consult-rdashboard-backup-closure`. Its two remaining ideas were below P2 and did not survive
as current defects: the destination-conflict scenario requires root-level filesystem replacement
outside the threat model and is caught by final validation, while the claimed retained parent
stdout descriptor is closed during process spawn. No production command, Drive upload, commit,
push or deployment was performed.

## Phase 6B Kamal, health and root phase execution closure

- Release bundle schema v2 embeds the complete canonical Kamal plan. Both Kamal and health runtimes
  revalidate the exact bundle, plan, installed policy, fixed `kamal` network, image digest and
  credential/template versions before an effect.
- Kamal bootstrap/deploy/rollback use fixed generated configuration, pinned executables, systemd
  credentials, immutable versions and post-effect observation. Failed observation never becomes
  permission to mutate; empty pre-observation is retried and is accepted only for bootstrap.
- Consumer smoke uses the exact digest on the fixed network with no pull, a read-only filesystem,
  dropped capabilities, no-new-privileges and bounded CPU/memory/PIDs. Two successful samples are
  separated by a measured monotonic two-minute interval. Soak aggregates repeated direct readiness.
- The exact-manifest DeepSeek Pro closure returned `PASS` in
  `/tmp/consult-rdashboard-kamal-closure`; no P0/P1/P2 finding remained. Its empty-version P3 was
  subsequently hardened as described above. Per-process watchdogs were not duplicated because each
  adapter already runs under a hard systemd `RuntimeMaxSec` and root cleanup deadline.
- The root phase executor now replays complete canonical result chains without another effect,
  rejects missing or extra operation identities, loads the phase spec only from the root security
  journal, consumes and verifies the exact durable permit, derives active lease identities itself
  and persists any verified backup chain before journal observation.
- The latest exact bare `bin/ci` exited 0 with 241 executable Rust tests (91 library, one
  `rdashboardd`, 149 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and optimized release build. Two earlier attempts stopped on strict
  Clippy findings and an intentionally owner-only test fixture; both root causes were corrected.
- Remaining boundary: acquire/release of the application write fence is outside phase specs and
  still needs its own fixed transient job. Mutation socket dispatch remains fail-closed until that
  job and recovery integration are complete. No production effect, commit, push or deployment was
  performed.

## Phase 6B fence and durable mutation admission

- A separate root-only fence job now materializes canonical acquire/release requests without
  exposing raw epoch or token values in unit names or process arguments. The fixed transient unit
  runs the pinned rimg fence adapter with bounded execution, owner-only job state and only the
  required application data path writable.
- The installed fence runtime reconciles acquire, release and resume as an exact state machine.
  Root projections use the latest security-journal lease plus live pinned rimg status and reject
  foreign, incomplete or reappearing state rather than inferring success.
- Root phase execution now compares the caller's complete phase intent with the exact authorized
  spec loaded from `security.sqlite`. A composite installed-effects adapter routes every privileged
  phase and fence through those root-bound runtimes while leaving source, CI and build effects behind
  an explicit delegate.
- The executor socket now supports short prepare and accept calls backed by a signed-intent ledger
  and atomic action-grant consumption. It acknowledges only durable admission, never long-running
  phase completion. Exact prepare replay is looked up from the root journal before resolver work;
  the same idempotency key with changed caller-visible bindings fails closed, including after a
  restart or a concurrent first writer.
- Exact escalated bare `bin/ci` exited 0 on 2026-07-16 with 251 executable Rust tests (100 library,
  one `rdashboardd`, 150 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build. No tests were ignored or skipped.
- The installed executor binary still intentionally supplies no mutation control. A durable
  operation driver, deploy source/classification resolver, non-privileged source/CI/build driver
  and end-to-end recovery drills remain required before mutation can be enabled. No production
  effect, commit, push or deployment was performed.

### Accepted-operation recovery and backup-only resolution

- Consumed intent/grant rows now decode into a complete typed accepted-operation record: exact
  signed intent and digest, attempt/request/project/operation bindings, policy/source/release
  authority, actor role, grant nonce/digest, authorizer lease and both expiry boundaries. The join
  is checked in both directions so a missing or mismatched grant row is corruption, not an omitted
  job. Exact accept replay produces one record and the same record survives reopening the journal.
- The installed resolver reopens canonical owner-only configuration on every non-replayed request.
  It supports only `rimg` backup-only, validates its owner policy identity and TTL, and requires the
  same installed rimg policy digest in the separate rimg and backup runtime documents. Deploy and
  rollback are rejected before installed-file access; runtime mismatch is retryable-unavailable,
  never a fallback policy.
- Exact escalated bare `bin/ci` exited 0 with 252 executable Rust tests (101 library, one
  `rdashboardd`, 150 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build. The service remains fail-closed
  because the installed operation driver is not yet present.

## Installed backup-only operation driver and worker

- The signed backup intent now binds the complete canonical mutation-policy document digest,
  including its rimg policy, unit, recipient and byte budgets. The driver reopens that exact policy
  plus the fully validating installed rimg policy before work and rejects any substitution.
- Executor authorization has a fail-closed reconstruction path. A first run measures the stable
  root backup filesystem, persists the quantitative reservation once, and binds it to the accepted
  grant nonce and authorized-operation digest. Restarts reuse that exact record instead of
  remeasuring into an incompatible authorization.
- Accepted backup work reconstructs only the ordered `Queued -> Preflight -> BackingUp` receipt
  prefix. Before the privileged effect it idempotently persists the backing phase intent, binds a
  scheduled base-backup spec using the installed unit/recipient/provider, and lets the existing root
  runtime consume the permit and verified chain. Terminal replay does not invoke the effect.
- The optional mutation authority now wires backup-only admission to an asynchronous worker. Grant
  responses acknowledge durable admission inside the short socket request; startup, notify and a
  30-second bounded scan drive pending work outside that request. The root journal lives in a
  separate mode-`0700` systemd StateDirectory. Deploy and rollback remain rejected.
- Exact escalated bare `bin/ci` exited 0 on 2026-07-16 with 256 executable Rust tests (102 library,
  one `rdashboardd`, 153 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build. The restart test reopened the
  security journal and proved identical terminal projection, authorization and receipt with one
  privileged effect application. No production command, backup, upload, commit, push or deployment
  was performed.

### Backup worker closure hardening and independent review

- Local boundary review moved backup, lock and immutable release-bundle storage from the
  controller-owned `/var/lib/rdashboard` parent into the root-owned mode-`0700`
  `/var/lib/rdashboard-executor` StateDirectory. This prevents the controller account from renaming
  privileged child directories through ownership of their former parent.
- The pre-spec `BackingUp` phase-intent write is required because the security store accepts a
  phase spec only against an existing exact intent journal. Its phase plan now comes from
  `OperationKind::required_phases` instead of a duplicate hard-coded sequence, so the driver's
  pre-bind and executor replay cannot drift.
- Pending jobs no longer share one scan-start timestamp. The installed driver reads the clock for
  each accepted job immediately before driving it, preventing a long first backup from giving later
  jobs an already-expired capture deadline.
- Executor shutdown now shares an atomic cancellation authority with the systemd transient runner.
  Cancellation kills and stops the active unit, reaps `systemd-run`, and leaves the durable
  intent/spec journal replayable rather than waiting for systemd's service-level SIGKILL timeout.
  The same authority is checked between accepted records, so shutdown never starts the next queued
  job after cancelling the current one.
- Exact escalated bare `bin/ci` exited 0 after these changes with 257 executable Rust tests (103
  library, one `rdashboardd`, 153 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build.

| Route | Status | Fingerprint | Output | Verified disposition |
| --- | --- | --- | --- | --- |
| `deepseek-pro` | ANSWERED / CONCERNS | `beca9a5f…aeff` | `/tmp/consult-rdashboard-backup-worker-security` | Its hard-coded phase-plan drift concern was accepted and fixed. Grant/intent expiry limits first durable admission, not scheduling of an already accepted job; `accepted_at_ms` is intentionally the authorization consumption time, so rejecting a queued accepted job after expiry would break durable admission semantics. Permanent-policy-error retry noise and composite policy-read atomicity remain below P2 and fail closed. |
| `gemini-pro` | ANSWERED / FAIL | `beca9a5f…aeff` | `/tmp/consult-rdashboard-backup-worker-architecture` | Fresh per-job time and cancellation-aware shutdown were confirmed and fixed. The deadline-recovery claim was disproved because the replay branch resolves `expected` from the persisted backup spec, including its original deadline. A still-running deterministic systemd unit can temporarily reject a duplicate start, but the intent remains replayable and the next bounded scan reconciles its atomically published result; this is bounded recovery latency, not terminal failure. Result publication is atomic hard-link publication, and the executor acquires the base-backup boundary before effect observation. |

No production command, backup, upload, commit, push or deployment was performed.

The focused closure after the four reviewed remediations used state fingerprint
`ffcab63b40e03a8f4a803f3caeb6e5a20c56005bb2a7c480ff98a4f48c983f1b`:

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `gemini-pro` | ANSWERED / PASS | `/tmp/consult-rdashboard-backup-worker-closure-gemini` | Confirmed the root-only paths, operation-derived phase plan, per-job clock, cancellation/reaping and exact result recovery; no P0/P1/P2 finding. |
| `deepseek-pro` | ANSWERED / CONCERNS | `/tmp/consult-rdashboard-backup-worker-closure-deepseek` | Confirmed the same four core remediations and at-most-once boundary. Its cancellation concern inspected blocking code inside `backup-adapter` but omitted that this binary is the process running inside the cancelled transient-unit cgroup; the executor polls cancellation while waiting on `systemd-run`, then kills/stops that unit and reaps the child. The default service stop timeout therefore does not need to cover the backup deadline. The single-worker race idea is unreachable by construction. |

The subsequent local closure tightened the same cancellation authority between accepted records so
shutdown cannot advance to new queued work. That small follow-up is covered by the final repository
gate below and does not alter the reviewed adapter-unit cancellation path.

## Phase 6B dedicated source-broker process

- A separate `rdashboard-source` binary now owns the canonical Git repositories and durable source
  ledger as a non-root account. Canonical installed configuration binds its fixed state/socket
  paths, numeric identities, remote-derived repository identities, owner policy generations,
  connection/deadline limits and one Ed25519 key identity. The exact systemd credential seed is
  stable-file checked, zeroized after loading, matched to the installed public key and rejects weak
  keys.
- The broker completes a bounded remote reconciliation for every configured project before binding
  its socket. Startup network/source failure therefore keeps the service unavailable instead of
  briefly authorizing a stale local head. Periodic reconciliation begins only after the configured
  interval. An active operator pause now blocks both independently verified initial snapshot
  admission and the live mutation gate.
- The Unix protocol is versioned, bounded and request-ID bound, accepts only UID 0, limits
  connections, owns/removes only its exact socket inode, and binds live responses back to the
  operation's project, source sequence, attestation digest and request time. Synchronous broker work
  runs in a blocking task so the async read/handle/write deadline remains effective. Transient
  interrupted/aborted accepts are logged and retried; a fatal accept drains already admitted bounded
  requests before the service exits for systemd recovery.
- Root-side snapshot verification independently verifies the installed public key, signature and
  expiry, exact target/sequence/digest, repository and owner-policy identities, Ready state,
  blocked-SHA, pause and divergence controls. This is the source half of future deploy intent
  resolution; it does not accept a caller's release class and does not enable deploy effects.
- Exact escalated bare `bin/ci` exited 0 with 264 executable Rust tests (110 library, one
  `rdashboardd`, 153 integration), four browser TAP tests, strict formatting/Clippy,
  documentation/schema checks and the optimized release build before the final accept-loop cleanup;
  the exact final gate is recorded below.

The first independent review used state fingerprint
`60457a00cffd04641132bd8f620e181789a88d3913cf90603344a175b6c8cb2b`:

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-pro` | ANSWERED / CONCERNS | `/tmp/consult-rdashboard-source-security` | Git fetch is already hard-limited to one minute. A retained ticket without executor proof is intentionally a fail-closed manual-reconciliation condition and must not be age-deleted. The useful deadline observation was accepted: synchronous handler work was moved off the Tokio reactor and a duration regression test proves the configured response deadline remains effective. |
| `gemini-pro` | ANSWERED / FAIL | `/tmp/consult-rdashboard-source-architecture` | The stale-socket crash loop does not apply because systemd's default `RuntimeDirectoryPreserve=no` removes the runtime directory across restart. Stateful completion normalizes `CutoverSnapshotting` to its stored `BackingUp` ticket, while code-only admission/completion both use `Deploying`. Same-head TTL renewal cannot advance sequence while a ticket exists because `begin_ref_update` rejects any active ticket transactionally. Its accept-loop concern was accepted in bounded form: transient interrupted/aborted accepts retry, while fatal errors drain active requests before exit. |

No production source service, credential, Git fetch, mutation, commit, push or deployment was
performed. Deploy/classification resolution and non-privileged CI/build execution remain the next
local Phase 6B boundary.

### Source-broker exact-target closure

Gemini's first closure pass exposed a real shutdown/socket-lifecycle window: cancelling the async
wait detached an in-flight blocking Git reconciliation, so Tokio could keep the process alive after
the socket guard had been dropped. Shutdown now awaits that exact bounded task before `main`
returns. A fatal accept closes the listener before draining admitted bounded requests. The service
uses `Type=notify`; the binary sends `READY=1` through fixed `systemd-notify` only after successful
initial reconciliation and socket bind, so ordered services cannot race an absent socket. Root-only
connection overflow intentionally remains fail-fast and maps to retryable source unavailability.

Exact escalated bare `bin/ci` then exited 0 with 264 executable Rust tests (110 library, one
`rdashboardd`, 153 integration), four browser TAP tests, strict formatting/Clippy,
documentation/schema checks and the optimized release build. `git diff --check` is clean. The final
implementation content manifest, excluding `.agent`, `.idea`, `.git` and `target`, is
`32f189c907fa778eb17c39eaeb1ad03743ae93e0f912e32f82696660cafe98b5`.

The exact final dispatcher fingerprint was
`26b54c0457433b6e52225a28cac79905aa076924ace38217aa055cc6392d4a84`:

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-free` | ANSWERED / PASS | `/tmp/consult-rdashboard-source-final-deepseek-free` | Independently confirmed shutdown ordering, post-reconciliation readiness, root-only socket lifecycle, accept-error decomposition and transactional ticket/ref exclusion; no P0/P1/P2 finding. |
| `gemini-pro` | ANSWERED / PASS | `/tmp/consult-rdashboard-source-final-gemini` | Rechecked its prior shutdown, listener-drain, readiness, connection-overflow, ticket-renewal and request-timeout hypotheses against the remediated tree and returned PASS. |

The source process slice is closed locally. No production source service, credential, Git fetch,
mutation, commit, push or deployment was performed.

## Signed candidate admission and first-bootstrap execution

- Installed deploy-policy schema v2 binds the exact owner-installed policy, rimg-policy digest,
  build UID, dedicated reader GID, build signing key identity/epoch/public key, policy-pinned
  `chronyc` digest, disk budgets and intent lifetime. Deploy admission independently reopens the
  live signed source snapshot, initial release state, exact build-owned attestation and immutable
  release bundle, then derives the effective release class. A current installed release rejects the
  request until stable-routing upgrade support exists; rollback remains disabled.
- The optional executor mutation runtime now drives accepted backup and bootstrap jobs sequentially
  outside the socket deadline. Testing, Building and Preflight project only the verified signed
  candidate evidence with the root-observed disk reservation rebound. Deploying, Health and Soak
  execute through fixed privileged adapters and canonical phase specs. Terminal replay promotes
  the exact bundle and commits release state without repeating an already receipted privileged
  effect.
- The installed chrony clock adapter invokes only `/usr/bin/chronyc` with fixed arguments against
  the local Unix socket, checks the exact executable digest/owner/mode/inode before and after, bounds
  output and deadline, and rejects stale, unsynchronized, malformed or non-finite tracking reports.
- The integrated regression uses real temporary policy/candidate/release stores and
  `security.sqlite`, produces distinct readiness and soak health evidence, simulates a crash after
  terminal receipts but before release-state commit, reopens the store, and proves Deploying,
  Health and Soak each retain one privileged application across recovery and terminal replay.

The architecture decision consultation used state fingerprint
`8b76765e2322031728028a8b8d219aa4be4377746dd02525e5a2af9dbd0697df`:

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `gemini-pro` | ANSWERED / OPTION_A | `/tmp/rdashboard-build-boundary/gemini-pro` | Accepted the externally provisioned signed candidate as the coherent bootstrap boundary. Its claim that privileged adapters were absent was rejected against `InstalledAdapterExternalEffectsV1`, the fixed systemd runner and Kamal/health profiles. |
| `deepseek-pro` | ANSWERED / CONCERNS | `/tmp/rdashboard-build-boundary/deepseek-pro` | Independently selected the same boundary and correctly identified the missing producer/install contract. The source-byte handoff and internal CI/BuildKit producer remain a separate Phase 5 product slice and are not represented as complete. |

Local verification of that recommendation exposed a production filesystem defect not mentioned by
either route: the capability-free executor could not traverse build-UID-owned mode-`0700` candidate
directories. The fix does not grant DAC bypass. Instead, the installed policy pins a dedicated
reader GID, candidate roots/projects/files require exact build owner plus reader group with
`0750`/`0440`, file reads reject hard links and revalidate identity, and only the
mutation-authority systemd drop-in grants `rdashboard-build-readers`. The controller is explicitly
excluded. A focused store regression proves exact group-read acceptance and rejects missing group
access.

The first post-change `bin/ci` correctly failed on strict Clippy findings only: similar UID/GID
names, an obsolete private helper, one unnecessary mutable binding and a test fixture exceeding the
line bound. Those structural findings were fixed without suppressions. The second bare `bin/ci`
exited 0 with 273 executable Rust tests (117 library, one `rdashboardd`, 155 integration), four
browser TAP tests, strict formatting/Clippy, documentation/schema checks and the optimized release
build. No test was ignored or skipped. No production service, credential, source export, BuildKit
job, provider effect, commit, push or deployment was performed.

### First exact-manifest closure round and transport remediation

The first frozen bootstrap target contained 104 files and had manifest digest
`8f511579004170030a0d0f8bbd5d3e25ec724803348fc0101825ecacbb2ceff8`.

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-free` | ANSWERED / FALSIFIED | `/tmp/rdashboard-bootstrap-final-review/deepseek-free` | It explicitly verified 104/104 hashes. The claimed UID/GID-equality defect was rejected because UID and GID are separate namespaces and the reader group isolates executor/controller, not producer from its own files. Directory races cannot forge the build signature or exact bundle/source bindings. Its temp-file accumulation finding was accepted and fixed. Signed candidate veracity remains the explicitly documented trusted-producer boundary. |
| `deepseek-pro` | ANSWERED / NEED_CONTEXT | `/tmp/rdashboard-bootstrap-final-review/deepseek-pro` | Provider policy prevented its own shell hash command, but its inspected target was the frozen tree. Root-directory replacement is outside the threat model; directory identity is nevertheless now held and revalidated around release-state promotion. Its orphan-temp observation was accepted. Other points were non-findings for bootstrap. |
| `gemini-pro` | ANSWERED / COHERENT | `/tmp/rdashboard-bootstrap-final-review/gemini-pro` | It verified the full manifest and found the candidate handoff coherent. Its open question about how a capability-free executor reaches the source socket exposed a real production blocker on local verification and was accepted. |

The original source unit created a mode-`0700` runtime directory and mode-`0600` socket owned by
`rdashboard-source`; the root executor has no DAC capabilities and therefore could not traverse or
connect. The repaired source transport accepts only exact private `0700/0600` or shared
`0750/0660` modes, requires a non-root shared GID, verifies socket owner/group/mode/inode after
chmod, and still authenticates peer UID 0 at the protocol layer. The source unit uses the shared
mode; only the mutation-authority executor drop-in gains the `rdashboard-source` group. Local host
inspection found the same issue for mode-`0750` `/run/chrony`, so the drop-in also gains the host's
`chrony` group. Controller identities receive neither group.

Release-state promotion now opens and revalidates the root-owned releases directory before temp
creation, before and after rename, syncs that exact handle, and sweeps only canonical
`.rimg.<uuid>.tmp` regular files with exact owner/mode/link count. The bootstrap regression proves
an interrupted temp is removed before terminal state commit. The first gate after these changes
failed only because the new Unix-listener test used ordinary `#[test]` without a Tokio reactor; it
was changed to `#[tokio::test]`. The next bare `bin/ci` exited 0 with 274 executable Rust tests (118
library, one `rdashboardd`, 155 integration), four browser TAP tests, strict formatting/Clippy,
documentation/schema checks and the optimized release build.

### Final exact-manifest closure

The remediated implementation target contains 104 files, excluding `.agent`, `.idea`, `.git` and
`target`. Its manifest digest is
`a42e113b1ce6ba020c192573a741016c904bed3114c9fac17df94fe34057cf55`.

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-free` | ANSWERED / PASS | `/tmp/rdashboard-bootstrap-final-v2-review/deepseek-free` | Verified 104/104 file hashes and the manifest digest, then confirmed source/chrony transport, release-state crash cleanup and signed-candidate binding. Its note that UID 0 always bypasses DAC was rejected: the service explicitly lacks `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`; the supplementary groups are required and intentional. Silent cleanup failure remains recoverable by the next exact sweep and is not a closure defect. |
| `deepseek-pro` | ANSWERED / PASS | `/tmp/rdashboard-bootstrap-final-v2-review/deepseek-pro` | Rechecked transport, candidate and state publication/recovery. Replacing the pinned executable requires external root and is outside the threat model; post-exec validation still rejects its evidence. Chrony package updates intentionally require a reviewed policy-pin update, and peer UID 0 is the fixed source authority for this architecture. No material finding. |
| `gemini-pro` | ANSWERED / PASS | `/tmp/rdashboard-bootstrap-final-v2-review/gemini-pro` | Verified the full capability-free installation chain: shared source transport plus UID-0 peer auth, build and chrony group access, private source state, observation-only base executor and truthful remaining-scope documentation. No open question remained. |

The final bare `bin/ci` on this implementation exited 0 with 274 executable Rust tests (118
library, one `rdashboardd`, 155 integration), four browser TAP tests, strict formatting/Clippy,
documentation/schema checks and the optimized release build. No test was ignored or skipped. The
first attempt after adding the source transport regression failed because it lacked a Tokio
runtime; the test was corrected and retained. No production service, credential, Git fetch, source
export, BuildKit job, provider mutation, commit, push or deployment was performed.

### Post-restart verification

After the user restarted Codex, the live implementation was rechecked against the same final
manifest. All 104 file hashes passed and the manifest digest remained
`a42e113b1ce6ba020c192573a741016c904bed3114c9fac17df94fe34057cf55`. A fresh bare `bin/ci`
exited 0 with 274 executable Rust tests (118 library, one `rdashboardd`, 155 integration), four
browser TAP tests, documentation/schema checks and the optimized release build. No test was
ignored or skipped. The resumed session changed only append-only/current workflow records; the
reviewed implementation remained byte-identical. No production installation, credential, source
export, BuildKit job, provider mutation, commit, push or deployment was performed.

## Phase 6B source, OCI and dashboard bootstrap closure

The resumed local slice closes the trustworthy transport from accepted source to the existing
first-bootstrap executor without claiming an installed producer or production deployment:

- `rdashboard-source` publishes the exact accepted Git tree and canonical digest-bound manifest
  from its sole external writable path. The non-root builder never receives the private bare
  repository.
- Release-bundle schema v3 and the build attestation bind the OCI archive digest, registry digest
  and local image ID. Candidate publication uses exact build-owner/read-group `2750` directories
  and `0440` files.
- OCI publication owns a store-level OS lock, serializes cloned operations and recovers both safe
  single-link orphans and the hard-link crash window only after owner/group/mode/inode validation.
  Root promotion performs the analogous fail-closed recovery in its private store.
- The Kamal adapter verifies and imports the promoted archive, checks the exact local Docker image
  ID, starts a bounded digest-pinned registry on `127.0.0.1:5555`, copies with explicit loopback
  TLS behavior, verifies the registry digest and performs mandatory owned cleanup. The installed
  profile is explicitly single-host.
- The controller exposes versioned lease, prepare, execute, status and capability endpoints. The
  browser validates operation identifiers, retains only the nonsensitive attempt ID and renders
  unavailable, running, retryable, reconciliation and terminal states.

Local release-binary HTTP smoke on `127.0.0.1:3100` used temporary databases and no executor.
`/health` and `/api/v1/mutations/capabilities` returned 200; mutation status returned 503 with the
typed `mutation_unavailable` failure; the HTML carried the expected strict CSP/security headers.
In-app interactive browser control was unavailable in this session, so no click-level visual QA is
claimed.

The first 24-file closure manifest had SHA-256
`60dff186435b79cc8f94d603d6a2dbfdb4ee2fafa7672f5b9c8e9c0bba855740`.
DeepSeek Pro returned PASS at `/tmp/rdashboard-phase6b-closure-deepseek`: no P0-P2 finding, with one
minor observation that runtime directory validators should require the installed setgid bit. That
was accepted by requiring exact `2750` in the OCI and candidate paths and matching the integrated
fixture. The second exact target had SHA-256
`06823ab35de82bba5bd129396ab2cb5f31f4888cd20acc997ec2581ed6650ef5`;
DeepSeek Pro again returned PASS at `/tmp/rdashboard-phase6b-setgid-closure-deepseek`. Its remaining
minor parity observation was also accepted: the candidate attestation root and project directory
are now required to be absolute/canonical, held open across the file read and revalidated by
device/inode, owner, group and exact mode. Gemini Pro was checked before the closure round but its
configured route was unavailable and is not represented as having reviewed this target.

The final exact 24-file manifest verifies with zero failures and has SHA-256
`a6fe2b10fc39c6bb046bf4d01959e2449fbb372410510345175251fa7c197414`.
The final bare `bin/ci` exited 0 with 284 executable Rust tests (127 library, one `rdashboardd`, 156
integration), five browser TAP tests, strict formatting/Clippy, schema/document checks and the
optimized release build. `git diff --check` is clean. The final target differs from the second
PASS target only by the accepted directory identity hardening.

The remaining work is not hidden as a percentage. The adjacent `rimg` Dockerfile still uses
dynamic base references, network downloads and BuildKit cache mounts that do not satisfy the
strict offline producer contract; `buildctl` and `buildkitd` are absent on this host. Exact
authorizer identities/credentials have not been supplied. Stable-routing capabilities required for
installed upgrades and rollback do not exist. Production installation, credentials, external
provider operations and deployment were not authorized. No service, credential, Git fetch, source
export, image build, provider effect, commit, push or deployment was performed.

## Task-scoped commit record

After the user explicitly authorized Git metadata writes, the exact owned implementation was
rechecked with bare `bin/ci`; it exited 0 with the same 284 Rust tests, five browser TAP tests,
strict formatting/Clippy, schema/document checks and optimized release build. `git diff --cached
--check` was clean. Commit `8c4ca0c` (`feat: implement hardened deployment control plane`) records
107 implementation files. `.agent/`, the user-owned `.idea/` directory and every file in the dirty
adjacent `rimg` checkout were excluded. No push or deployment was performed.

## Observation-only production installation

The user authorized starting with `rdashboard` itself and explicitly excluded nginx. A read-only
host audit found Ubuntu 26.04, the existing `kamal-proxy` container on ports 80/443, Docker network
`kamal` at gateway `172.19.0.1`, about 15 GiB free disk, and a pre-existing failed
`logrotate.service`. No prior rdashboard user, binaries, units or configuration existed.

The first clean installation attempt reached both listening services but its immediate curl raced
the Type=simple readiness boundary. Its ERR trap disabled and removed the new units, binaries and
configuration. Journal evidence confirmed both processes had started correctly. The second attempt
used a bounded connection-refused retry and succeeded. Production now runs the exact locally gated
binary hashes `c4ce5f662aa385571430500695f7d15f0cbd384bb7e95d94ae0a7ea2893518d2`
(`rdashboardd`) and `3c76f8e853f7e33b9f0dc01acb0a18fd270c9993882037551fae0409da3b1f46`
(`rdashboard-executor`). Both units are enabled and active with zero restarts and about 4 MiB total
resident memory. `/health` returns `status=ok`; capabilities report the executor socket configured
and `authorization_handoff_available=false`. The executor config contains no mutation authority.

Bare `bin/ci` was rerun after installation and exited 0 with 284 Rust tests, five browser TAP tests,
strict formatting/Clippy, schema checks and the optimized release build. The public route remains
disabled: `dev.4u.ge` currently returns Cloudflare 525 because Kamal Proxy has no service/certificate
for that hostname. More importantly, current evidence does not establish the required Cloudflare
Access application, origin-side Access JWT validation or protection against direct-origin Host/SNI
bypass. Publishing this operational surface before those controls would expose host telemetry.

## Cloudflare Access origin boundary

Commit `f7019db` (`feat: protect production dashboard access`) closes the code and host-routing part
of that boundary without introducing nginx. `rdashboardd` now loads an exact team domain,
application audience and email allowlist; fetches bounded JWKS over fixed HTTPS; verifies one RS256
`Cf-Access-Jwt-Assertion` against the exact issuer, audience, application token type, temporal
bounds and email; removes the assertion before routing; and closes authenticated SSE at token
expiry or after five minutes. All protected routes share that middleware. `/health` remains
unauthenticated for Kamal Proxy but no longer emits internal collector or retention error text.

The production unit fixes `RDASHBOARD_ACCESS_REQUIRED=true`, so missing or partial values fail
startup instead of selecting the local unauthenticated router. New inactive systemd socket-proxy
units provide the only container-to-loopback path: `172.19.0.1:3100` on the private `kamal` bridge
to `127.0.0.1:3100`. The documented activation order creates Cloudflare Access first, verifies
local rejection, enables the private bridge, and only then creates the Kamal Proxy TLS route.

The first full gate after the production-required correction failed on two Clippy structure
requirements (`needless_pass_by_value` and `manual_let_else`). Both were corrected directly; no
lint was suppressed. The next bare `bin/ci` exited 0 with 287 Rust tests, five browser TAP tests,
strict formatting/Clippy, schema/document checks and optimized release build. `git diff --check`
and `git diff --cached --check` were clean before commit.

DeepSeek Pro review at `/tmp/rdashboard-access-consult` returned CONCERNS and identified the real
fail-open installation ordering risk plus minor issuer logging and temporal-clarity points; all
were corrected. DeepSeek Free review of the corrected target at
`/tmp/rdashboard-access-consult-free` returned READY. Its only low availability note proposed
keeping SSE open briefly if the system clock becomes unreadable; that was rejected because the
current immediate close is fail-closed and the same clock failure makes token verification
unavailable. No authentication bypass, false acceptance or sensitive health-detail exposure
remains in either review.

The user supplied the exact allowed identity and completed the Cloudflare self-hosted application.
Atomic activation installed the exact locally gated `rdashboardd` SHA-256
`4fdc85a3756e1e0fd3eaea2122ed460485411f3c41b6d3971bb79a29f1e35829`, the production-required
Access configuration and the private systemd socket bridge. The controller, executor and bridge are
active with zero restarts. The only listeners are `127.0.0.1:3100` and the private `kamal` gateway
`172.19.0.1:3100`; loopback and bridge health probes return 200, and protected requests without an
Access assertion return 403. No access secret or operator email is recorded in repository or
workflow artifacts.

Kamal Proxy accepted the healthy `dev.4u.ge` target, and unauthenticated public traffic reaches the
exact Cloudflare Access login and audience. Authenticated traffic is not yet usable because Kamal
Proxy has no certificate for the new hostname. A local TLS reproduction produced the exact error
`acme/autocert: ... no viable challenge type found`. The proxy's local HTTP ACME handler correctly
returns 404 for an unknown token, so the backend, route and challenge handler are healthy; Cloudflare
Access is intercepting validation before the origin. The remaining external action is a separate,
more-specific Access application for `dev.4u.ge/.well-known/acme-challenge/*` with Bypass/Everyone.
After that policy exists, retrigger automatic issuance, verify the certificate and authenticated
snapshot/SSE behavior, then record the final public smoke evidence.

The user created the exact path-scoped Bypass/Everyone application. A public HTTP request to an
unknown ACME token then reached Kamal Proxy and returned its expected 404, while the root still
returned the exact Cloudflare Access login redirect and application audience. The next local TLS
request completed ACME issuance. Kamal Proxy now stores a Let's Encrypt certificate with
`CN=dev.4u.ge`, the sole SAN `DNS:dev.4u.ge`, issuer `YE2`, and validity from 2026-07-16 through
2026-10-14. With certificate verification enabled, an internal TLS request reached the protected
origin and returned 403 without an Access assertion. Kamal Proxy lists the route running with TLS,
and the controller, executor and bridge remain active with zero controller/executor restarts. The
only remaining activation evidence is the operator's real browser login plus snapshot/SSE
rendering; that identity-bound smoke is intentionally not simulated or bypassed.

## Cloudflare Access denial diagnosis

The operator completed the real OTP flow and the protected origin returned the generic fail-closed
`access_denied` response. The verifier now maps each rejection boundary to a fixed, non-sensitive
category and logs only that category. It does not log the assertion, JWT header or claims, operator
identity, configured allowlist, request path or library error payload. Response status and body are
unchanged, and all verification checks remain fail closed.

DeepSeek Pro reviewed the diagnostic change at `/tmp/rdashboard-access-diagnostic-review/out`
against state fingerprint `5be273385e294173b3fccbf26a529e21e9034b6f1b7956b832aa420134dca54e`
and returned `ANSWERED/CONCERNS`. Its important finding, missing unit coverage for the complete
library-error mapping, was accepted and fixed with table-driven assertions that also prove every
category is fixed lower-case ASCII. Its low-severity observation that the custom `Debug`
implementation revealed the allowed-email count was accepted and fixed by fully redacting that
field. Its suggestion to merge `subject_claim_invalid` and `subject_mismatch` was not applied:
the former is the explicit malformed/empty/oversized claim check, while the latter precisely maps
the library's configured expected-subject mismatch. The final regression pins both categories.

The first bare `bin/ci` attempt failed only on formatting and was followed by mechanical
`cargo fmt --all`. The next failed only on strict Clippy identical-match-arm structure; the mapping
was consolidated without a suppression. After the review-driven test was added, another gate run
failed only because the single test exceeded the strict line limit; its tables were factored
without reducing coverage. The final fresh bare `bin/ci` exited 0 with 288 executable Rust tests
(131 library, one `rdashboardd`, 156 integration), five browser TAP tests, strict formatting and
Clippy, schema/document checks and the optimized release build. No test was ignored or skipped;
`git diff --check` is clean. Commit `e72137f` (`fix: diagnose Cloudflare Access denials`) contains
only `src/web/access.rs`; workflow artifacts and `.idea/` were excluded.

Before deployment, the production controller hash was revalidated as the expected prior
`4fdc85a3…e35829`, both controller and executor were active, controller restarts were zero, health
returned 200 and an assertion-free protected request returned 403. Deployment backed up the exact
prior binary, installed release SHA-256 `34fabbc64…da7a27`, restarted only
`rdashboard.service`, and required bounded health plus fail-closed 403 smoke before accepting the
new binary; rollback was armed and not needed. The installed hash matches, the controller is active
with zero restarts, and the public route still redirects an unauthenticated request to the exact
Cloudflare Access application. The only denial observed after installation is the deliberate
assertion-free origin probe (`assertion_missing`). Production diagnosis now requires one real
authenticated request from the operator's existing browser session.

### JWT `typ` compatibility remediation

The identity-bound request after diagnostic deployment produced the fixed category
`header_algorithm_or_type_invalid` twice. Cloudflare documents application tokens as RS256-signed
JWTs with `kid` and a typical `typ: JWT` header, while RFC 7519 section 5.1 defines `typ` as optional
and its media-type value as case-insensitive. The verifier's exact uppercase-and-required `typ`
comparison was therefore a stricter local compatibility condition, not an authentication
requirement.

The remediation keeps an exact RS256 algorithm gate, bounded `kid` selection, JWKS signature,
issuer, audience, required timestamps and bounded lifetime, application-token type, non-empty
subject and exact normalized email allowlist. It accepts an absent `typ` or a case-insensitive
`JWT`, rejects every other present value, and records algorithm and type rejections separately.
Regression coverage authenticates absent, uppercase and lowercase forms and rejects a different
present type.

Fresh bare `bin/ci` exited 0 with 289 executable Rust tests (132 library, one `rdashboardd`, 156
integration), five browser TAP tests, strict formatting/Clippy, schema/document checks and the
optimized release build. No Rust or browser test was ignored or skipped. `git diff --check` is
clean; the owned diff is 44 insertions and three deletions in `src/web/access.rs` only. Release
SHA-256 is `c8e1a6fa33a0f60326d49cb605a98b91a250f32cc3f967c5d991aafafd702230`.

Both focused consultations used state fingerprint
`2be07b4d0c1f00b35ad15e359e11fb2dc20ceec30c942da294281453164936d0`:

| Route | Status | Output | Verified disposition |
| --- | --- | --- | --- |
| `deepseek-free` | `PARTIAL/CORRECT` | `/tmp/rdashboard-access-typ-review/free` | Confirmed optional/case-insensitive `typ`, preserved downstream validation and adequate tests; no defect or open question. Its mixed-case-test note relies entirely on the standard-library primitive already exercised by lowercase and is not a material missing boundary. |
| `deepseek-pro` | `ANSWERED/PASS` | `/tmp/rdashboard-access-typ-review/pro` | Confirmed no algorithm-confusion, key-selection, token-class, issuer/audience, identity or validation-order bypass. Its optional `cty` idea is not a current defect: nested content cannot deserialize into the required claims and fails closed, while Cloudflare's application-token contract does not require a local `cty` policy. |

No review finding requires remediation. Commit `823c5cc` (`fix: accept standard Cloudflare JWT
headers`) contains only `src/web/access.rs`; workflow artifacts and `.idea/` were excluded.

Immediately before deployment, the installed controller hash matched the prior diagnostic release,
the service was active with zero restarts, health returned 200 and a protected assertion-free probe
returned 403. The rollback-armed deployment backed up that exact binary, installed release SHA-256
`c8e1a6fa…702230`, restarted only `rdashboard.service`, and accepted the release only after bounded
health 200 plus fail-closed 403 smoke. Rollback was not needed. The installed hash matches, the
service is active with zero restarts, and the unauthenticated public route still returns the Access
login redirect.

The operator then supplied the real authenticated browser smoke. The production page renders fresh
host CPU, memory, disk, network and PSI telemetry; the snapshot is current; the sequence is
advancing; and the SSE indicator and update-delivery panel both report connected. The operation
controls remain disabled with the truthful authorizer-unavailable message, so this observation-only
activation did not enable mutation authority. Server-side reconciliation matches the screenshot:
installed controller SHA-256 is `c8e1a6fa…702230`; controller and executor are active/running with
zero restarts; loopback and private-bridge health both return 200; listeners remain only
`127.0.0.1:3100` and `172.19.0.1:3100`; Kamal Proxy lists `dev.4u.ge /` as running with TLS; and no
authenticated denial was logged after deployment. The sole denial is the deliberate
assertion-free origin probe.

The visible `rimg` Unknown state is also truthful. Production inspection found no `rimg` container,
systemd service or TCP listener; only the enabled/running `actions.runner.mrDenai-rimg.rimg-deploy`
GitHub Actions runner exists. Therefore there is no safe internal origin to place in
`RDASHBOARD_RIMG_BASE_URL`. Deploying `rimg`, then installing its read-only health origin, is a
separate external mutation explicitly excluded from the observation-only authorization. No `rimg`
deployment, mutation credential, provider effect, push or destructive action was performed.

Verdict: the requested observation-only `rdashboard` public activation is complete and usable at
`https://dev.4u.ge` behind Cloudflare Access. The next production milestone is blocked only on
fresh authorization to deploy `rimg`; it is not missing work that can be completed by changing the
dashboard alone.

## rimg production deployment preflight

U026 explicitly authorizes the separate first `rimg` production bootstrap and subsequent internal
health integration. Read-only host evidence found the dedicated `rimg-deploy` runner online, Docker
29.4.1 and Buildx 0.33.0 available, the private `kamal` bridge present, and about 15 GiB free. There
is no rimg container, image, TCP listener, `/var/lib/rimg`, bootstrap marker or incomplete recovery
state. The only configured client storage currently present is the readable Sartuli upload root;
the Umove path in the earlier draft does not exist on this host.

The prior upstream push run `29275193155` never reached deployment: hosted CI failed because Debian
libvips did not provide the required libjxl 0.12 development contract. The current remediation
builds the pinned native test toolchain in CI, exports headers/pkg-config metadata from the
development assembly rather than the pruned runtime stage, and makes bare `bin/ci` use that exact
pkg-config root. A real local `bin/update` rebuilt the toolchain; libjxl resolves as 0.12 from
`.titanium/opt/4u/lib/pkgconfig`; the following bare `bin/ci` exited 0.

Production configuration now mounts only the source that actually exists and sets the webhook URL
empty. The Sartuli repository has neither the documented `/internal/rimg/events` receiver nor a
stable `4u-ge-web` Docker alias, so enabling that URL would falsely represent an integration that
does not exist. `rimg` health will therefore truthfully expose `webhook.enabled=false`; receiver
integration remains separate application work.

DeepSeek Pro reviewed the migration/boot/recovery state at fingerprint
`eea5f63b6db376351b9442e0b96af5471676f632d3ab6efe25ef7eb22d889642` and returned
`ANSWERED/CONCERNS` in `/tmp/rimg-deploy-review/pro`. Its recommendation to keep an unmarked first
candidate running after marker failure was rejected: there is no prior service, and accepting an
unpersisted bootstrap would be false success. Its recommendation to discard recovery state after a
failed restore was also rejected because that would erase the fail-closed reconciliation boundary.
The claimed root smoke container was disproved by the image's fixed `USER rimg`. Its useful rollback
finding was accepted: restarted prior containers now must converge to exact Docker `running healthy`
within 12 bounded checks, otherwise recovery state remains and new deployment stays blocked.
`bin/test-operational-scripts` covers both healthy cleanup and unhealthy state retention.

DeepSeek Free was required and attempted twice on the same fingerprint, but both provider runs
timed out (`ERROR`, exit 124) after inspecting the target; the immediate route health check still
reported `OK`. It is recorded as an unavailable completed perspective, not represented as a
successful review. Fresh bare `bin/ci` after the accepted hardening exits 0 with the operational
script behavior check and 34 executable Rust tests; one benchmark is intentionally ignored, and the
gate explicitly reports local `cargo-audit` unavailable while GitHub CI installs and requires it.
The focused DeepSeek Pro closure ran against the exact remediated target in
`/tmp/rimg-deploy-review/closure` and returned `ANSWERED/CONCERNS`. Its claim that a successful
Bash `ERR` trap masks the original command failure was disproved with a direct `set -e` reproduction:
the shell retained exit 1 and did not continue. Its related double-trap concern omitted that the
inner predeploy trap captures the original status and exits with it, while the outer recovery trap
cannot turn that status into success. No change was made for either disproved concern.

The closure's remaining observation was valid: recovery behavior had covered the no-migration path
but not a persisted migrated state. The operational harness now proves that successful recovery
invokes the exact `migration restore --report ...` contract before clearing state, while a failed
restore retains both container and migrated recovery files, does not restart the old container and
returns failure. Together with the existing healthy/unhealthy restart scenarios, the shell harness
now covers all material recovery branches.

Fresh bare `bin/ci` on the final target exited 0: native manifest validation, operational-script
syntax and behavior, strict formatting/Clippy, and all 34 executable Rust tests passed. One
benchmark remains intentionally ignored. Local `cargo-audit` remains unavailable and explicitly
reported; GitHub CI installs it and requires the audit. No source changed after this gate. The
production-safe dashboard route will not publish a rimg port: after the service is healthy, a
loopback-only per-connection systemd socket proxy will resolve the current Kamal container and
provide the read-only health origin to the native dashboard without nginx or public exposure.

Commit `429c1f6` (`feat: harden rimg production operations`) records the exact 37-file production
candidate. The repository commit hook repeated the same complete `bin/ci` gate successfully, and
the rimg working tree is clean with `main` one commit ahead of `origin/main`. No push or production
mutation has occurred yet; the repository workflow starts only from an explicitly authorized push.

U027 confirmed both repositories were pushed. Remote reconciliation found `origin/main` at exact
rimg commit `429c1f6`, and GitHub Actions run `29539612292` executed CI for the full SHA
`429c1f65fdf0bdfad9b90edf292c1150712bd9f3`. CI failed after 26 minutes and the dependent deploy
job was correctly skipped, so production retained no rimg container, bootstrap marker or partial
state.

The failure reproduced the native dependency symptom but exposed a different remaining root cause.
`bin/update` successfully exported the development toolchain, including `libjxl.pc`, yet `bin/ci`
set `PKG_CONFIG_PATH` to a repository-relative value. Cargo dependency build scripts run outside
the repository root, so `jpegxl-sys` could not resolve that path on a clean hosted runner. Local
verification had been falsely insulated by a separate system libjxl 0.12 installation under
`/usr/local/lib64/pkgconfig`. The remediation derives an absolute native sysroot/prefix after the
script enters the repository, fixes `PKG_CONFIG_PATH` and `PKG_CONFIG_LIBDIR` to the exact exported
directory, sets `PKG_CONFIG_SYSROOT_DIR` so `/opt/4u` metadata relocates into `.titanium`, and
asserts exact libjxl 0.12 resolution from that directory before compilation. `bin/bench` now uses
the same clean-host environment. A fresh required gate is pending on this corrected target.

DeepSeek Free reviewed the corrected native-path diff at `/tmp/rimg-ci-native-path-review` and
returned `ANSWERED/CORRECT`. It confirmed the absolute path, exact `PKG_CONFIG_LIBDIR` and sysroot
close both dependency-build-script cwd drift and host fallback. Its material observation that
`bin/bench` lacked the same exact toolchain assertion was accepted. Its low direct-Cargo gap was
also real because the README documents `cargo run`; a repository `.cargo/config.toml` now forces
the same config-relative absolute pkg-config directory and sysroot for every Cargo build script.
The Cargo path semantics were checked against the official Cargo configuration contract.

Fresh bare `bin/ci` on the review-remediated target exited 0. It validated the exact pinned
pkg-config directory and libjxl 0.12 before strict formatting/Clippy, then passed all 34 executable
Rust tests and the operational shell behavior suite. One benchmark remains intentionally ignored;
local cargo-audit remains explicitly unavailable while hosted CI installs and requires it. No
production mutation occurred.

Commit `87bcc89` (`fix: pin native CI toolchain paths`) records only `.cargo/config.toml`,
`README.md`, `bin/bench` and `bin/ci`. Its commit hook repeated the full green gate. The rimg tree
is clean and exactly one commit ahead of `origin/main`; the next workflow run requires only that
rimg follow-up push. No rdashboard code change or production rollback is needed.

### rimg Titanium cache parity

U029's suspicion was confirmed from source rather than inferred from duration. Sartuli's
`bin/update` maintains per-library content directories under `.titanium/builds`, assembles the
toolchain from those immutable outputs and runs on a persistent self-hosted workspace whose
checkout deliberately preserves `.titanium`. In contrast, rimg's `bin/update` had only one final
fingerprint and final `.titanium/opt/4u` fast path, while its CI job runs on a fresh hosted runner
without cache restore/save. The Dockerfile still contains the correct independent multi-stage
library graph, but no state survived for BuildKit to reuse it across runs. Run `29541492295`
confirmed the practical effect: more than 26 minutes remained entirely inside the native build
step on the second push.

The remediation keeps hosted CI isolated from production while making its cache persistent and
content-addressed. GitHub Actions restores `.titanium/opt/4u`, the exact fingerprint state and a
BuildKit `mode=max` local cache. An exact recipe/manifest/CPU key gives unchanged runs an immediate
assembled-toolchain hit; a nearest prior key lets BuildKit reuse unaffected library stages after a
recipe change. Hosted artifacts use `x86-64-v3` rather than runner-dependent `-march=native`, so a
cache never crosses incompatible hosted CPUs. `bin/update` imports and transactionally rotates the
optional BuildKit cache, validates the libvips object plus libjxl pkg-config/header contract before
accepting or installing an export, and supports a fail-closed warm-only postcondition.

Bare `bin/ci` is now the local pre-push boundary requested by U030. It validates source manifests,
runs the real update, immediately requires a warm hit, then confirms exact relocated pkg-config
resolution before Rust compilation. The new isolated shell harness mocks only Docker transport and
proves cold export/cache creation, no-build warm reuse, stale-cache rejection, previous-cache
import and preservation of the prior toolchain/state/cache when a build fails. The real gate still
executes the actual Docker graph whenever local inputs or output completeness require a rebuild.

The first full local gate exercised that real cold path after the old export failed the new
fingerprint/completeness contract: BuildKit completed all 70 graph vertices in 230.6 seconds, the
immediate second update was a warm hit, the shell harness passed, and strict Clippy plus all 34
executable Rust tests passed. After review cleanup, a second fresh bare `bin/ci` again exited 0; it
reported two immediate real-toolchain warm hits, passed the expanded absolute/relative cache-path
harness, operational scripts, strict Clippy and the same 34 executable tests. One benchmark remains
intentionally ignored and local `cargo-audit` remains explicitly unavailable while hosted CI
installs and requires it. `git diff --check` is clean.

DeepSeek Free reviewed the uncommitted cache target at `/tmp/rimg-titanium-cache-review` and
returned `ANSWERED/CONDITIONAL_PASS`. It found no blocking correctness, invalidation, atomicity,
portability or test defect. Its duplicate-work finding incorrectly said the second update would
cold-build again; the first successful update has already persisted the exact fingerprint, so the
next call is a warm exit. The useful underlying simplification was still accepted: the separate
workflow update step was removed and `bin/ci` is now the sole owner. Its cache-key-versus-local-
fingerprint difference was accepted as intentional: changing cache orchestration obtains a new
hosted cache key without forcing a local native rebuild when recipe inputs are identical. Its
relative-path coverage observation was accepted and the mock harness now validates both relative
Titanium root and BuildKit cache locations.

The already-pushed runtime candidate remained independent of this delivery optimization. Remote
run `29541492295` eventually completed its native step successfully after 31 minutes 32 seconds,
quantifying the cold-hosted cost; it then proceeded to the mandatory cargo-audit installation.

Commit `0f74380` (`fix: persist Titanium native caches`) records exactly the five reviewed files:
the hosted cache integration, local update/cache behavior, gate ownership, regression harness and
documentation. Its commit hook repeated the complete warm `bin/ci` successfully. The rimg tree is
clean and one commit ahead of `origin/main`; no push was performed for this optimization, so it did
not start a competing deployment while the authorized `87bcc89` bootstrap workflow is active.

The user pushed `0f74380` while the earlier run was completing, starting run `29543108084`; it is
allowed to continue because its cold execution will populate the new Titanium cache. The prior
run's complete CI was green in 39 minutes 42 seconds, but its deploy job stopped after nine seconds
at `Prepare persistent storage`, before image build or application effects. Exact log evidence was
`install: invalid user: '10001'`: coreutils `install -o` treated the numeric string as an account
name on this host. Post-failure production inspection still found zero rimg containers, no
bootstrap marker and no recovery files.

The remediation replaces the inline privileged command with `bin/prepare-storage`. It validates a
non-root absolute target, numeric UID:GID and explicit sudo mode; creates `/var/lib/rimg` as `0755`
and the three service directories as `0750`; then applies numeric ownership using `chown`, whose
numeric contract does not require a passwd entry. Its isolated behavior harness checks exact
modes, UID:GID and write access plus rejection of root-path, named-owner and invalid-sudo inputs.
A fresh bare `bin/ci` and the commit hook both passed the new harness, all operational checks,
strict Clippy and all 34 executable Rust tests; local cargo-audit remains explicitly unavailable.
Commit `ed06435` (`fix: prepare numeric storage ownership`) contains only the workflow step, gate,
script and test. The rimg tree is clean and one commit ahead of `origin/main`; this deployment fix
requires the user push while run `29543108084` warms the cache.

Run `29543108084` did not reach a native compile and therefore did not warm the cache. Its exact
fail-closed error was `Cache export is not supported for the docker driver`; the hosted runner's
default Docker driver lacks the local cache exporter that the workstation's containerd-backed
Docker driver supports. The post-cache save correctly did not run on the failed CI, and deploy was
skipped. This is a provider integration difference, not a native graph or relocation defect.

The corrected workflow now installs Docker's official `docker/setup-buildx-action@v4` before the
cache restore, selecting a cache-capable docker-container builder. The current official release was
verified as v4.2.0. A local warm graph plus real `mode=max` export completed and measured the cache
at 1.6 GB (51 blobs), within the repository cache limit but large enough to make its cost explicit;
export took about 87 seconds while the graph itself was entirely cached. The exact assembled
toolchain remains cached separately for the common immediate-hit path. Fresh bare `bin/ci` and the
commit hook both passed after the workflow correction. Commit `3ac57a0` (`fix: enable hosted
BuildKit cache export`) contains only the three-line setup action and awaits push because a local
Codex PreToolUse policy blocks `git push` even after session authorization.

### rimg dependency update review

Review baseline is rimg `main` at `3ac57a009f1514b6f059defaf0f84c74160d7b51`. The pinned open
targets are PR 9 `cddb5fb265e31fa93cccadaad7b573e54fa80227` (libffi 3.7.1), PR 10
`ecd74ce0ab5fe2d3747854bf3c5e5ac92c2800d7` (rustls 0.23.42), PR 11
`c6bc74e1eeef3b0bea9b1cbaa6c6d660b0fdd240` (actions/checkout v7), PR 12
`56e7f620ae97cc3b264c3f0c8fb367bf4474c464` (GLib 2.89.2), PR 13
`7894f61f795f198279eb74f4451e78add308c899` (Sentry 0.48.5), PR 14
`d0bbd319c70c10e9729dc9772879ca4e8a4e6815` (Tokio 1.52.4), and PR 15
`018b4600542d103e5bd2d8a6172735910a9f077b` (toml 1.1.3). All seven PRs are
single-file patch updates. Their historical red checks are not accepted as compatibility evidence
because the branches predate part or all of the corrected Titanium cache workflow.

The native PRs are incomplete as submitted: PRs 9 and 12 change Dockerfile versions without the
matching `config/native-checksums.sha256` entry that the build intentionally requires. They must be
completed with independently downloaded upstream archive digests before integration. PR 9 fixes
memory corruption on AArch64 plus non-production platform defects; no upstream security advisory
was claimed. The remaining release-note and runner-compatibility review is in progress. No PR has
been merged and no dependency update has been applied to current main yet.

The seven updates were therefore applied to current main as one coherent batch rather than merging
the stale PR branches and triggering seven production deploys. Upstream review classified GLib
2.89.2 as the direct security update because it bounds pre-authentication GDBusServer SASL input;
libffi 3.7.1 fixes AArch64 memory corruption and other platform defects; Sentry 0.48.5 prevents a
panic/double-panic abort path; Tokio 1.52.4 fixes skipped runtime-driver work; rustls 0.23.42 keeps
the prior default while adding RFC 9149 ticket requests; toml 1.1.3 fixes writer overflow; and
checkout v7 includes its current Node dependency and fork-checkout hardening. The production
self-hosted runner is `2.335.1`, which satisfies checkout v7's Node 24 runner requirement. GitHub
reported no open Dependabot alerts, so the batch is preventative and bug-fix hardening rather than
a response to an undisclosed repository alert. The libffi and GLib archives were independently
downloaded and matched upstream SHA-256 values
`d5e9a6638ddbd2513ddb54518eb67e4bbe6fa707bcc01c10f6212f0a088d819d` and
`894fd527e305041f7723071297d79a78af4719dbd0d8fb77f6b1a85c9f5475b9`.

The first local batch gate exposed the real cause of the user's full Titanium rebuilds. All native
version arguments and `CPU_FLAGS` were redeclared in the shared build-base stage, and one aggregate
checksum manifest was copied there. Changing any single version or checksum therefore invalidated
the common ancestor of every library stage. The remediation scopes each version and CPU argument
to only the stage that consumes it, splits integrity metadata into stable per-library checksum
files, copies only the matching file into each archive stage, and keeps `native-git-refs` scoped to
libjxl. Strict `sha256sum --check` remains fail-closed and the permissive `--ignore-missing` mode is
removed. A new gate check rejects shared mutable inputs, missing stage-local arguments, aggregate or
mis-scoped manifests, permissive checksum verification, incorrect manifest counts and missing
CPU-flag declarations.

The final bare `bin/ci` passed the native source and cache-layout contracts, the real toolchain
build followed by the mandatory warm hit, operational syntax/behavior, strict formatting and
Clippy, and all 34 executable Rust tests; one benchmark remains intentionally ignored and local
`cargo-audit` remains explicitly unavailable while hosted CI installs and requires it. Three
libheif download attempts initially failed with wget network exit 4 while all completed stages were
preserved. A host-network container diagnostic downloaded the exact asset through the machine's
VPN/TUN path and verified its pinned digest. The next complete gate succeeded and provided a live
selective-reuse proof: every independent completed stage was `CACHED`, then only libheif and its
dependent libvips stage ran before the warm postcondition. Local `bin/update` already defaults to
`--network host`; hosted CI intentionally selects `default` on its separate runner.

DeepSeek Free reviewed the exact final uncommitted target at `/tmp/rimg-final-review` and returned
`ANSWERED/PASS` with no material deploy blocker. It independently confirmed Dockerfile ARG and
per-library manifest isolation, deterministic GitHub cache hashing, benign Linux impact of the
transitive Windows-only resolver changes and safety of the Rust patch updates. Its only LOW note
was that the structural test checks presence rather than textual instruction order. This does not
create a green false positive because the same mandatory gate parses and executes the real
Dockerfile before any Rust check; an invalid ARG/COPY/RUN order fails that build. No source change
was warranted after this review, so the green bare `bin/ci` remains the final target verification.

Commit `126f27b` (`fix: isolate native caches and update dependencies`) records the exact reviewed
27-file batch. Its commit hook repeated the complete warm `bin/ci` successfully. The rimg tracked
working tree is clean, and U035's manual push was reconciled: local `main` and `origin/main` both
equal full SHA `126f27be578bb4b5f0b112ef869f1820c1ce999b`. Exact push run `29546207917` entered CI.
Superseded run `29543709811` had completed its cold hosted CI but was still rebuilding obsolete
`3ac57a0` in the deploy job while the exact run remained pending. It was cancelled before any rimg
container existed; its mandatory cleanup released the Kamal lock and completed the 1 GB BuildKit
prune, after which the exact run started. No PR was merged through an API.

### Private rimg health integration

The production observer keeps rimg unpublished. `rdashboard-rimg-health.socket` binds only
`127.0.0.1:18080`; its short-lived root service queries the fixed local Docker socket for full
container IDs with exact Kamal labels, revalidates running plus Docker-healthy state and accepts
only a private IPv4 address on the named `kamal` network. It then replaces itself with the fixed
`/usr/lib/systemd/systemd-socket-proxyd`, capped at eight connections and one idle second, to the
selected container's port 8080. The controller has no Docker socket and loads a source-controlled
loopback origin after the optional operator environment so that file cannot accidentally retarget
health collection. Live production inspection confirmed systemd 259 provides the exact proxy
binary/options and that `kamal` is `172.19.0.0/16` with gateway `172.19.0.1`.

DeepSeek Pro's first focused review found a real Kamal rolling-deploy race between `docker ps` and
per-container `docker inspect`, plus missing discovery-path tests. The helper now skips an inspect
failure only after an exact filtered `docker ps --all` confirms that full container ID was removed;
an existing candidate or any other Docker failure still aborts fail-closed. A scripted Docker
client test covers both branches end-to-end, while separate tests bind output limits, exact socket
proxy argv, metadata gates and systemd authority separation. Its environment-precedence note is
covered at the actual boundary by ordering the two systemd EnvironmentFiles and a source assertion;
simulating that precedence inside rdashboard would only retest systemd. Its suggested preflight
`stat` was rejected as a redundant TOCTOU check because executing the fixed Docker path and querying
the fixed socket already produces the authoritative fail-closed result. DeepSeek Free route check
was healthy but the provider skipped the final response; it is recorded as `SKIPPED`, not a pass.
After the race remediation, bare `bin/ci` exited 0 with strict fmt/Clippy, 132 library tests, seven
helper tests, all integration/browser/schema checks and the optimized release build. Final
DeepSeek Pro verification returned `ANSWERED/PASS`; no material blocker survived. Its useful minor
note about the empty and all-ineligible discovery paths was accepted as an eighth helper test. Its
private-prefix concern was rejected because the template reads only the address under the exact
network name `kamal`, independent of what other networks are attached. The code-level timeout idea
was not applied because the installed unit already enforces an absolute five-second start timeout
and duplicate process-level timing would add cancellation complexity without a stronger boundary.
The final post-review bare `bin/ci` again exited 0 across the complete gate.

Commit `4ac31c7` (`feat: observe private rimg health`) contains exactly the seven reviewed
source/systemd/documentation paths; workflow artifacts and `.idea` were excluded. The global Codex
PreToolUse hook rejected the authorized `git push origin main`, so the commit remains local pending
the user's manual push. Production installation must wait for that remote provenance, but rimg's
independent exact CI/deploy continues.

### Exact rimg production bootstrap and webhook drift

U035's exact push workflow `29546207917` completed successfully: hosted CI took 32m05s and its
native step about 28 minutes after restoring the old cache, compared with 37m26s on the prior cold
layout. The post-cache save succeeded. Self-hosted Kamal deploy took 20m31s, released its lock and
pruned the persistent BuildKit cache to 1 GB. Exact image tag
`ghcr.io/mrdenai/rimg:126f27be578bb4b5f0b112ef869f1820c1ce999b` is running as the sole rimg
web container with image/repository digest
`sha256:0f9fb40dd79be2bd44dc0ae54e42bf5e43fa2fece68429a5ebe6a44a621d625a`, Docker
`healthy`, zero restarts, exact labels and no host port bindings. It uses only the private `kamal`
network at `172.19.0.14`. Sartuli uploads are mounted read-only; data, derived and masters mounts
are writable. Their host directories are exact UID:GID `10001:10001` mode `0750` under root-owned
`/var/lib/rimg` mode `0755`.

Independent live probes returned 204 for both `/health/live` and `/health/ready`. Status schema v1
was ready with normal mode, open intake, no active epoch/token/leases/jobs/deliveries and writable
database/uploads/masters. Schema inspection returned current/latest application schema 4/4,
zero pending migrations and integrity `ok`. `/var/lib/rimg/.bootstrap-deployed` records exact SHA
`126f27b...` at `2026-07-17T01:54:48Z`; no `.containers` or `.migrated` recovery file remained.

The same status contradicted the intended production contract by reporting `webhook.enabled=true`.
Kamal 2.12 source confirmed the root cause: `Kamal::Utils.argumentize` emits only an env key when a
clear value is empty, so Docker copied the deploy-host's nonempty `RAILS_WEBHOOK_URL`. Hotfix commit
`b923636` replaces that ambiguous input with nonempty `RIMG_WEBHOOK_ENABLED=false`; the parser
applies it after URL/secret overrides, clears both on false, preserves absent/true behavior and
rejects every other spelling. Bare `bin/ci` passed before and after DeepSeek Free's `ANSWERED/PASS`
review, and the commit hook passed again; native validation hit the same cache immediately each
time. The global hook blocked its push. The live service remains ready with zero work but webhook
enabled until the hotfix is pushed and a deliberate replacement is authorized; the existing
bootstrap marker correctly prevents silently treating a second automatic deploy as safe.

### Private rimg health production activation

U036 reconciled the pushed rdashboard commit: local and remote `main` are exact full SHA
`4ac31c712f089a36e259fb00edabce72fb4efe67`. A fresh bare `bin/ci` exited 0 with 132 library
tests, eight helper tests, one controller-binary test, all integration suites, five browser TAP
tests, schema/document checks and the optimized release build. No test failed or was ignored.

Production preflight revalidated the prior controller SHA-256 `c8e1a6fa…702230`, zero restarts,
healthy loopback service and the sole old rimg container as running, Docker-healthy, zero-restart
and private at `172.19.0.14`. The rollback-armed installation then placed helper SHA-256
`c6128e1886cc7519c40c62a2af52822cb3f0d62c5e3d38d4d61daf60ea7ea81e`, the fixed loopback
environment and exact systemd units, enabled the socket and restarted only the controller. Every
installed file digest matches the local gated target. `systemd-analyze verify` accepted these
units; it emitted only the host's unrelated pre-existing warning that `CPUAccounting=` in
`system-xfs_scrub.slice` is obsolete.

The final production observable is green: controller, executor and health socket are active;
controller `NRestarts=0`; listeners remain the protected `127.0.0.1:3100`, private Kamal gateway
`172.19.0.1:3100`, and new loopback-only `127.0.0.1:18080`; loopback and bridge health return 200;
an assertion-free protected request returns 403. The helper returns the exact live rimg status,
and five consecutive `project_samples` rows at the five-second collection interval report
`rimg` as fresh `healthy`. Their detail still reports `webhook_enabled=true`, truthfully exposing
the known runtime drift until the separately authorized hotfix cutover.

### Titanium-owned cargo-audit cache

U037 identified the remaining hosted CI delay from exact run `29575934981`: Titanium cache restore
took 17 seconds, but the separate unpinned `cargo install cargo-audit --locked` compiled for 5m29s
on every fresh runner. The complete repository check step then took only 2m42s. This was not a
remaining native-library cache miss.

The corrected workflow uses the existing Titanium Actions cache rather than adding a second cache.
The first implementation added `.titanium/tools`, bumped the combined key to schema v2 and retained
the prior native key as a restore prefix. Exact pushed run `29577464028` proved that this was
insufficient: `actions/cache` scopes entries by a version derived from both compression and the
path set, so the fourth path made the old three-path archive ineligible and the log reported
`Cache not found` before beginning a full native rebuild. The run was cancelled after 12m08s,
before post-save or deploy, instead of completing irrelevant work.

Follow-up `c270a33` keeps the original three-path set and stores the tool below the already cached
`.titanium/state/tools` subtree. The exact key still hashes `bin/ensure-cargo-audit`, so a pinned
tool/version change creates a new cache key while the prior-key fallback remains version-compatible
and preserves unchanged native outputs.
The installer pins current stable cargo-audit 0.22.2, serializes local use, installs into a staging
root, requires exact `cargo-audit 0.22.2` output before publication, preserves the old directory on
install failure and removes only exact interrupted staging/rollback names. `bin/ci` now owns the
installer and always runs `cargo audit` locally and in hosted CI; the former optional local skip is
gone. The stored binary is 23 MiB.

The behavior harness proves cold install arguments, warm no-install reuse, cleanup after an
interrupted publication, replacement of a wrong-version binary, preservation on failed install,
and the single-cache workflow/key/fallback contract. The first bare `bin/ci` performed the one-time
real cold installation and passed all native, operational, fmt, Clippy, 35 executable Rust tests
and RustSec audit checks; the existing benchmark remains intentionally ignored. An immediate
second bare gate reused the exact cached binary with no install and passed. A final fresh bare gate
after review remediation was also warm and exited 0 with the same complete result.

DeepSeek Free initial review at fingerprint
`c6a0bc7216ea0369229397fd8c1f8f3d183680d7a78474921afd4d397ff1115b` returned one P2: workflow
tests were tied to exact YAML indentation. It was fixed by checking distinctive semantic values
without full-line spacing anchors. Its useful lower-severity orphan-cleanup and wrong-version-test
notes were also accepted. The exact remediated closure at fingerprint
`ea344ae37f7c6a3df1fef1157cc6c9fad92cdf5efd37706e6afbec429aa5c8a7` returned `ANSWERED/PASS`
with no P0/P1/P2 or open question. Its remaining P3 hard-crash micro-window can cause one cold
rebuild on the next run but cannot skip audit or accept a wrong tool, so it is an explicit bounded
performance residual rather than a correctness defect. No production command or deployment was
performed by this optimization. Commit `4845fd0` (`fix: cache cargo-audit in Titanium`) records
exactly the five reviewed workflow, installer, test, gate and documentation paths; its commit hook
repeated the complete warm `bin/ci` successfully.

The compatibility follow-up passed bare `bin/ci` after a one-time local cargo-audit fill (44.33s),
then an immediate complete warm gate in 3.9s with no tool or native build. The commit hook repeated
that warm gate. Commit `c270a33` records the four-file correction and a regression assertion that
rejects reintroducing `.titanium/tools` into the workflow path list. The global Codex PreToolUse
hook rejected `git push origin main`, so the hosted fallback and subsequent exact-key warm-hit
timings initially remained pending the user's manual push.

U039 reconciled local and remote `main` to exact full SHA
`c270a338372dbd116cba2a67a2aeaccf7dfb5d79`. Push run `29578601776` attempt 1 restored the prior
1,691,046,582-byte native archive from exact key
`rimg-titanium-Linux-x86-64-v3-88cda7ac03409a6ae6bd3aad593d863d5f2401b9df5bcbf66699a60acb9421f4`,
reported both native checks current, compiled cargo-audit exactly once in 5m19s and saved the new
1,699,203,266-byte combined cache under exact v2 key
`rimg-titanium-v2-Linux-x86-64-v3-73161ae825d7e23945e955e3504d897d1c5a9a4a50c16c61039964194c0a7af1`.
The complete check step passed in 7m53s.

Attempt 2 restored that exact v2 key, reported both native checks current, contained no
`installing cargo-audit` line and passed the same full check step in 2m38s; total CI was 3m33s.
This is the required cross-run warm proof. Both known marker-ineligible deploy jobs were cancelled
after successful CI, and their always-run Kamal lock release plus bounded BuildKit prune completed.
Live production remained the sole original exact container `f50a4135c09b`, image tag `126f27b...`,
Docker-healthy with no recovery files; its status remains ready and truthfully reports the separate
known `webhook.enabled=true` drift. No production cutover occurred.

### Production BuildKit retention boundary

The exact hotfix deploy log exposed a separate self-hosted-runner cost after hosted Titanium was
fixed. With an unchanged Dockerfile, BuildKit no longer retained the actual
`vips-build-base` package layer: that apt/toolchain step and its dependent native RUN stages
executed again, and the registry image build took 1108.947 seconds. The former daemon
`maxUsedSpace = "1GB"` and matching always-run `--max-used-space 1gb` cannot retain that complete
graph. Live inspection after cancelled-run cleanup found only 217.6 MB in the dedicated builder;
the VPS filesystem remained bounded at 67 GB total, 45 GB used and 22 GB available.

The reviewed change raises the common maximum to 6 GB and adds a 12 GB minimum-free-space target
in both BuildKit daemon configuration and the always-run prune command. The maximum bounds normal
cache growth while the free-space target causes earlier eviction if unrelated VPS data consumes
the remaining disk. `bin/test-native-cache-layout` binds both paired values and rejects the former
1 GB workflow flag. The README records the operational contract. Bare `bin/ci` passed after the
change, and task-scoped commit `10d549e` repeated the complete gate in its commit hook.

DeepSeek Free reviewed the exact four-file diff at `/tmp/rimg-buildkit-gc-review` and returned
`ANSWERED/PASS` with no P0/P1/P2. Its only compatibility P3 speculated that the runner might not
support `--min-free-space`; the live runner's own `docker buildx prune --help` explicitly lists
that option, so no source change was required. Its suggested two-pass cache retention proof is the
correct post-push runtime acceptance test: the first marker-blocked deploy fills the newly recreated
builder once, and a rerun of the same SHA must show native stages cached before reaching cutover.

The user pushed `10d549e` exactly to `origin/main`, and run `29580086966` completed that two-pass
proof. Attempt 1 passed hosted CI in 3m18s and cold-built the production image in 1140.6 seconds.
The live builder grew to 5.79 GB, proving that the former 1 GB ceiling could not retain the graph.
The pre-app-boot hook then failed closed on the unchanged bootstrap marker. Lock release and the
new 6 GB/12 GB cleanup both succeeded; prune reported 0 B deleted and the VPS still had 17 GB free.

Attempt 2 reran the identical `10d549e3c5c999c831c10017a2c716920fee64df` source. Hosted CI again
passed in 3m18s, while BuildKit reported the expensive package base, libaom, libjxl, libheif,
libvips, jpegli and Rust build stages as `CACHED`. The image build fell from 1140.6 to 14.0 seconds,
and the complete production job fell from 19m16s to 25 seconds before the same intentional marker
failure. The second cleanup again deleted 0 B and retained the exact 5.79 GB cache. Production
remained on sole healthy container `f50a4135c09b` / image `126f27b...`; the marker timestamp and
contents were unchanged, there were no recovery files, and the loopback health contract remained
`ready=true`. No production cutover occurred; the known `webhook.enabled=true` drift remains until
an explicitly authorized one-time replacement.

### Authorized rimg cutover and observer recovery

U041 authorized exactly one replacement. Preflight reconciled local and remote rimg main to full
SHA `10d549e3c5c999c831c10017a2c716920fee64df`; the sole prior `126f27b...` container was healthy
with zero restarts, schema 4/4, no active work and the expected private mounts. The exact candidate
image was already present, the 5.79 GB BuildKit graph remained intact and the old bootstrap marker
was copied to an owner-only deploy state file before any mutation.

Run `29580086966` attempt 3 reran only the failed production job after reusing the already green CI
dependency. The marker was removed only after that exact job entered `in_progress`. BuildKit
reported every graph step cached; Kamal stopped the old container, persisted the migration report,
started exact tag `10d549e...`, observed Docker health, passed both consumer-network checks 120
seconds apart, renewed the marker and cleared its `.containers`/`.migrated` recovery state. The
job completed successfully in 2m36s, with Kamal itself reporting 144.2 seconds; lock release and
the 6 GB/12 GB prune succeeded and prune deleted 0 B.

Post-cutover evidence shows sole running container `b47bcd787470...` on private `kamal` address
`172.19.0.12`, exact four mounts with Sartuli uploads read-only, zero restarts and Docker healthy.
Live and ready return 204; status schema v1 is ready/normal with zero active work, all writable
probes true and `webhook.enabled=false`; no `RAILS_WEBHOOK_URL` remains in the container
environment. Schema inspection is current 4/4 with zero pending migrations and integrity `ok`.
The exact marker records `10d549e...` at `2026-07-17T13:01:56Z`, and the persisted migration report
is owner `10001:10001`, mode `0600`.

The rolling gap exposed a directly coupled rdashboard service defect. At `12:59:47Z`, while no
healthy container existed, the collector's parallel probe burst triggered five expected
fail-closed helper exits in one second. systemd exhausted its default service start limit and marked
both `rdashboard-rimg-health.service` and its listening socket failed, so observation did not resume
when the candidate became healthy. Resetting only those failed states and restarting the socket
immediately restored the exact new status. Eight consecutive five-second SQLite project samples
then reported `healthy`, live/ready 204 and `webhook_enabled=false`; the controller remained active
with zero restarts.

The source correction adds `StartLimitIntervalSec=0` under the helper's `[Unit]`, pins it in the
installed-unit test and documents why transient fail-closed activations must not permanently fail
the socket. It does not change helper exit semantics, Docker target validation, the loopback-only
listener, five-second start/stop deadlines, empty capability sets, address-family restriction,
32-task/256-fd/32-MiB limits or the controller's lack of Docker authority. The installed host's
`systemd.unit` manual explicitly defines zero as disabling start rate limiting. Bare `bin/ci`
passed this exact three-file source diff with exit 0: 132 library tests, all binary/integration,
five browser tests, schema/document checks and optimized release build.

Required DeepSeek Free consultation used fresh runtime evidence and state fingerprint
`95c2d42e8ade423fbe8002c1727f964d7f17fc0c9ee681fe843d1f9d3be8ee95` at
`/tmp/rdashboard-rimg-health-start-limit-review`. The route check was `OK`, but both dispatcher
attempts ended `ERROR` without a response: the model ignored the requested working-tree diff,
expanded `HEAD~1` (the entire prior health integration commit) and exhausted its bounded attempt.
It is not represented as a pass. Adversarial local review found no material regression: unlimited
start attempts remain reachable only through a loopback socket, every activation is systemd-
bounded, and preserving failed exits keeps signal loss explicit while allowing the next bounded
collection to recover automatically.

Commit `1ce0e3c` (`fix: recover rimg health socket after cutover`) records exactly the service unit,
installed-unit contract test and deployment documentation after the green gate. The global
PreToolUse hook blocked the authorized `git push origin main`; production installation of the
durable unit change therefore awaits manual remote provenance. The live socket remains restored
and healthy in the meantime. After all candidate, marker, migration, health and dashboard evidence
passed, the temporary old-marker copy was removed; the bootstrap state directory is empty and the
new exact marker remains.

### Production control-center history and project overview

U042 was implemented as three coherent local vertical slices without enabling an unconfigured
external integration. Host history now combines durable minute sketches and remaining raw samples
into completed-minute median windows for one hour, one day, one week and 30 days with explicit
coverage. The generic Intent/Attempt observation workspace was removed from the page while its
fail-closed API remains available for the later concrete deploy journey. The first reusable project
overview shows rimg health, bounded durable deploy/rollback/backup history and truthful unavailable
states for container resources, dependency updates and GlitchTip rather than fabricated data.

The accepted-repository path is bounded across both privilege boundaries. Source protocol v2
measures only the exact accepted Git tree, revalidates the accepted ref before and after `ls-tree`,
and returns logical tracked-file bytes and count without disclosing repository paths or Git command
authority to the controller. Control protocol v2 carries that observation through the root
executor. Metrics schema v4 stores at most one durable point per project per hour across restarts,
preserves errors alongside last-known data and exposes a 31-day query capped at 745 points so the
UI can calculate a covered 30-day change. Collection failures retry after five minutes without
increasing the successful hourly sampling rate.

DeepSeek Free reviewed the complete 29-path non-workflow diff and returned `PASS`. Its host-history
double-count concern is not reachable: rollup insertion and raw deletion share one SQLite
transaction, so the independent history connection observes either state, never the intermediate
state. Its project-index question is already answered by
`UNIQUE(project_id, target_key, operation_kind)`, whose SQLite index has `project_id` as its leading
column. The corrupt-metric case already returns a typed store error rather than panicking, and the
fixed 30-day window matches U042. Its one valid P2 was fixed: completion of a single project's
operation or repository request now replaces only that project article instead of rebuilding every
project. The open systemd reachability question is pinned by an installed-unit contract proving the
base executor keeps `rdashboard-source` and the mutation drop-in adds its two groups without an
empty `SupplementaryGroups=` reset.

The final bare `bin/ci` exited 0 after review remediation: 132 library tests, all binary and
integration suites including nine executor-socket and 19 store/web contracts, seven browser tests,
documentation/schema checks and the optimized release build. A preceding final-gate attempt found
only a 101-line collector function against the deny-level 100-line Clippy limit; dependency setup
was extracted into a cohesive helper and the full gate was rerun. In-app browser automation was not
available in this session, so no screenshot claim is made; semantic/responsive markup is covered by
the browser contract suite and source inspection. Container resource history, dependency-update and
GlitchTip adapters, Telegram failure delivery and the concrete authorized deploy UI remain explicit
next slices; this change does not claim or deploy them.

Task-scoped commit `16d61b9` (`feat: add production control center history`) records exactly the 26
reviewed product, contract, deployment and documentation paths. The three authoritative workflow
artifacts remain intentionally uncommitted. The commit is local only; no production deployment or
external integration mutation was performed for U042.

### Control-center production deployment

U043 reconciled local and remote `main` to exact full SHA
`16d61b9a8c87ab3062afbc8f5ae0586d8d3ca05b`; `1ce0e3c` is its direct parent. U044 explicitly
authorized installing that pushed target. Read-only production preflight found 17.29 GB free,
active zero-restart controller and executor services, active private bridge and rimg observer, a
ready rimg container at exact deployed head `10d549e...`, and no active writes/jobs/deliveries.
The source service, source config/credential/state, mutation drop-in and tmpfiles config were all
absent. Existing Access values were inspected only by key names and remain unchanged.

Source-broker preflight then found a real missing contract before any service or data mutation:
`rimg` is private, while production has no broker-scoped Git credential. The source boundary
deliberately clears the credential helper, interactive prompting, HOME and global/system Git config;
the deploy user's existing SSH identity is therefore neither reachable nor an acceptable implicit
workaround. The failed preflight left the old binaries, units, active services and data hashes
unchanged, created no release state and installed no source file. The already-created isolated
source/build identities are inert. Supporting the private remote requires a source-controlled,
auditable credential and pinned-host contract followed by the full gate and review.

Consultation fingerprint `5a29a043355d943d6eb4379b86751fdcbbd6e20a2a572aaa7046e595b16375ac`
used `/tmp/rdashboard-production-deploy-review.md`. DeepSeek Free returned `ERROR` after two attempts
despite an immediate healthy route check and is not represented as a review. DeepSeek Pro returned
`ANSWERED/CONCERNS` at `/tmp/rdashboard-production-deploy-review-pro`. Its valid minor rollback
ordering finding was fixed by stopping both rimg health service and socket before restoring their
old unit. The tmpfiles finding assumed an old file contradicted by live preflight; exact rollback
must restore its original absence. The direct successful `127.0.0.1:18080/health/status` request is
stronger than checking the intentionally short-lived socket service as active. Socket units are
unchanged and their exact installed hashes were part of preflight. The reviewed source-install form
was consequently not executed.

The narrowed rollback-armed script has SHA-256
`8fd2ce7643d4ce35d1e37f6c6c489709596411456c9cca47020deb4ea482d620`; it stops the controller
before copying the entire StateDirectory and restores that pre-v4 directory with the exact prior
controller, executor and units on any trapped error. It completed for exact pushed SHA
`16d61b9a8c87ab3062afbc8f5ae0586d8d3ca05b`. Installed controller and executor SHA-256 values are
`09e1ac4aedb2df49ce5744a9cb4bb80f97c53a005b8dfec48666ae0b519da5a7` and
`82187836f9d8dc4eb98e9d78f709ef44c70fcdc9181126f35ffb7b7dfb290680`; the executor and rimg-health
unit hashes are `60c9d618…1fc9` and `482ec765…fb99`.

Controller and executor are active/running with zero restarts, their loopback and private-bridge
health both return 200, the assertion-free snapshot returns 403, and no warning-or-higher journal
entry exists for either service after cutover. The sole rimg container remains exact image
`10d549e…`, running/healthy and ready/idle with no active writes, jobs or webhook delivery. Normal
controller startup migrated metrics to schema v4. Independent inspection found advancing host and
rimg project series (24 points each in the preceding two minutes at inspection time), while
`project_repository_samples` remains empty because source config, credential, state, unit and socket
all remain absent. That is a truthful partial production state, not fabricated repository data.

Public `https://dev.4u.ge/` returns the expected Cloudflare Access 302 and assertion-free internals
remain closed; the authenticated render still requires the user's browser identity. The root-only
deployment state records the exact commit, schema v4 and
`repository_source=unavailable_private_remote`; the staging bundle and unused generated seed were
removed after post-cutover verification.

### Compact operator overview and traffic totals

U045 replaces the expanded project articles with one native table row per project and explicit
columns for state, resources, deployments, backups, repository, updates and errors. The table has a
caption, scoped column and row headers, DOM order equal to visual order, text state labels alongside
symbols, a sticky project column and native horizontal overflow. These choices follow the bundled
`modern-web-guidance` accessibility and CSS-layout guides. Successful history accumulation prose,
the redundant current-node label and the primary PSI row are gone. Raw `contract_v1` health detail
and raw executor/source failures are deliberately excluded from the overview; concise unavailable
states and valid last-known repository data remain visible.

Host-history API schema v2 carries received and sent byte totals plus their independent covered
durations. The durable minute rollup accumulates only deltas between monotonic counter samples. A
counter decrease excludes that unknowable interval from both total and coverage instead of
fabricating traffic, and the mixed raw/rollup path is covered by focused store contracts. Current
traffic uses the host counters directly; hour/day/week/month cells render counter-derived volume,
while CPU, memory and disk continue to use completed-minute medians.

DeepSeek Free reviewed the complete product diff and returned `PASS` with fingerprint
`27d553fec5abdaeb7e2cc4e274860dc6d9723cd6a089288ec2c00984507abd74`; its output is retained at
`/tmp/rdashboard-compact-review`. Its valid safe-integer formatting observation was fixed, and the
table minimum width was aligned with the explicit column widths. Its theoretical overlap concern is
bounded to conservative undercounting in a defensive merge and cannot invent bytes. The final bare
`bin/ci` then exited 0: 132 library tests, all binary and integration suites including 20 store/web
contracts and seven browser tests, documentation/schema checks and the optimized release build.
In-app browser automation was unavailable in this session, so no screenshot claim is made. This
slice changes no production service or external integration. Task-scoped commit `8de0a3d`
(`feat: compact production overview`) records exactly the seven reviewed
product/test/documentation paths; the workflow artifacts remain intentionally uncommitted.

### Compact-overview production deployment

U046 reconciled local and remote `main` to exact full SHA
`8de0a3dd9b4f2351f3a7e316b6c80674d9bcb10c`. Bare `bin/ci` reran on that exact target and exited 0
with 132 library tests, all binary/integration suites including 20 store/web contracts, seven
browser tests and the optimized release build. The existing DeepSeek Free `PASS` applies to the
same unchanged product target; deployment introduced no new code or configuration scope requiring
another consultation.

Read-only preflight found 16.79 GB free, active zero-restart controller and executor services,
active private bridge and rimg-health socket, metrics schema v4 with advancing host and rimg
samples, no repository samples, and one sole healthy exact `10d549e...` rimg container. The prior
controller hash was `09e1ac4aedb2df49ce5744a9cb4bb80f97c53a005b8dfec48666ae0b519da5a7`.
Only the controller was in scope: the candidate binary hash was
`7cf5a9f97c775a4842219a33352a6da043c00dff6c64a77012afefd8c6871d18` and matched again after
upload and installation.

The rollback-armed installation stopped the controller before copying its complete StateDirectory
and retained that copy plus the prior binary under root-only release
`/var/lib/rdashboard-releases/20260717T154924Z-8de0a3dd9b4f`. Any install, startup or health error
would have restored both. Candidate health succeeded, so no rollback ran. The controller is now
active/running with zero restarts; loopback and private-bridge health both return 200, an
assertion-free protected request remains 403, metrics schema remains v4, and 36 host plus 36 rimg
samples advanced during the initial soak. Latest network counters are populated. The unchanged
sole rimg container remains healthy on exact `10d549e...`.

The installed binary contains the requested semantic project table and history API v2 browser
contract. Public `https://dev.4u.ge/` returns the expected Cloudflare Access 302. There are zero
controller error lines after cutover. One repository-observation warning is expected because the
private source service remains uninstalled, and the deliberate assertion-free smoke generated one
fixed authorization warning. Browser setup was attempted through the bundled in-app-browser skill,
but this session exposes no required browser-control JavaScript tool, so the authenticated visual
render was not claimed. Repository samples remain zero, and no source broker, mutation authority,
project-resource collector, dependency update, GlitchTip or Telegram integration was installed or
enabled.

## 2026-07-17 rimg failed push-deploy diagnosis

GitHub Actions run `29592074146`, job `87924148149`, did not fail while compiling or
publishing the image. The deploy reached `.kamal/hooks/pre-app-boot`, where
`bin/predeploy-migrate` rejected the cutover because the production bootstrap marker exists.
That marker is an intentional contract: automatic push cutovers remain disabled until the
stable rdashboard-owned release path is installed. The current production container stayed
healthy and no candidate boot occurred.

The rimg workflow now evaluates the same marker immediately after checkout. When stable cutover
is required, all effectful steps are skipped and the job emits a notice instead of creating a
known-failing deployment. The lower-level predeploy hook remains unchanged as defense in depth.
Operational tests cover both marker states and verify that the builder, storage, deploy, lock
cleanup, and cache cleanup share the same decision. Bare `bin/ci` passed. DeepSeek reviewed the
frozen change and reported no P0-P2 findings; its minor exact-count and test-seam observations
were either intentional contract checks or clarified before the final gate.

## 2026-07-17 first real project-resource source

The visible host heading/status and both nested table scroll containers are removed. Native tables
remain in normal document flow with captions, scoped headers and one project row. Percentage column
widths replace the forced 64/98-rem canvases, so the operator uses the page scrollbar rather than a
second table viewport. Browser control could not be initialized because this session exposes no
required JavaScript control tool; no visual screenshot claim is made. Static HTML and browser
contracts assert that the removed heading/status/scroll classes do not return.

The rimg resource cell now has a real source. A private mode-`0600` Unix socket owned by the
`rdashboard` account starts one short-lived root template service per request. Its fixed protocol
accepts only `resources-v1`; the existing helper selects only full Docker IDs with exact
`service=rimg` and `role=web` labels, revalidates running/healthy state and the private Kamal
address, then executes one fixed bounded `docker stats --no-stream` format for that ID. The
controller receives only versioned numeric CPU, memory, network and block-I/O values and never
receives Docker socket or command authority. The socket waits for the executor-created runtime
directory, and all request/response, process, time and memory bounds fail closed.

Metrics schema v5 transactionally adds resource fields to production v4 project samples. The exact
v4-to-v5 migration is exercised with an existing project row before the first resource write. Raw
fresh/partial samples are compacted into mergeable minute sketches; stale cached values remain
visible but are not counted again. Monotonic network/block counter decreases omit the unknowable
restart interval. The project-scoped API returns completed hour/day/week/month windows with medians,
totals and independent coverage, and the compact cell renders current CPU/RAM, all four CPU/RAM
medians and one-hour traffic without exposing raw health text.

Bare `bin/ci` passed after the v4 migration contract: Clippy with warnings denied, 134 library
tests, 10 root-helper tests, 23 store/web tests, all other integration suites, seven browser tests,
the schema/document checks and optimized release build. DeepSeek Free consultation first returned
`ERROR` with empty responses, then `PARTIAL` after reading the narrowed high-risk files; its only
response was a request to continue reading, so it is explicitly not treated as PASS or as a
finding. Local risk review subsequently tightened the runtime-directory ordering and browser
contract validation. Repository, dependency-update and GlitchTip integrations remain disabled and
truthfully unavailable pending their real production identities and credentials.

## 2026-07-17 project-resource production deployment

U049 paused further source work and explicitly authorized deploying the already gated revision.
Direct remote reconciliation found both commits already present: rdashboard
`5961b63b4b4cf6f843619ba4e03f469690ea2fe5` and rimg
`00cdcbfd9df53d2565efca0b394e82586158f480`. The local Codex push attempt was blocked by the
operator's `PreToolUse` hook before execution; no bypass was attempted. The subsequent remote read
confirmed the operator-side push had completed.

Read-only production preflight found 16.77 GB free, an active zero-restart controller, active
executor/health socket, no resource units yet, one healthy rimg container on exact image
`10d549e...`, and prior controller/helper hashes `7cf5a9f...1d18` and `c6128e1...ea81e`.
The uploaded six-file bundle passed SHA-256 verification on the host before installation.

The rollback-armed installation stopped the controller before copying its complete schema-v4
StateDirectory. It retained that directory plus every replaced binary, unit and fixed environment
file under root-only release `/var/lib/rdashboard-releases/20260717T174409Z-5961b63`. The trap would
stop the new socket, move aside candidate state/files and restore the old state, binaries and units
on any install, startup, health or exact-hash error. No error occurred and no rollback ran.

Production now runs controller SHA-256
`53474403a072596704d48247f09aee1ea17705f7a0a9b60e8b4f8abca88ff425` and resource-helper SHA-256
`5243aa45b64c4ecd3b2916c8f54616992ed5445b19a6d1f90ada4d0d64f968bf`. The controller and both
observation sockets are active; controller restarts remain zero. The resource socket is exactly
`rdashboard:rdashboard` mode `0600`, its direct fixed-protocol response reported real numeric CPU,
RAM, network and block-I/O values for the healthy rimg container, schema migrated transactionally
to v5, and successive fresh project samples advanced at five-second timestamps. Loopback and the
private Kamal-network bridge returned 200, a protected request without an Access assertion remained
403, and public `https://dev.4u.ge/` returned the expected Access 302. Warning and error journal
counts after cutover were both zero.

The bridge smoke initially pulled the 9.56 MB `curlimages/curl:8.13.0` image because it was absent.
After confirming the disposable container had already been removed and no container referenced the
image, the exact newly pulled image was deleted; it is not retained as production state.

The pushed rimg correction is independently proven by run `29600740331`. CI passed, the deploy job
completed successfully in nine seconds, `Check automatic deployment mode` passed, and builder,
storage, Deploy, Kamal-lock cleanup and cache cleanup were all skipped. The existing production rimg
container was not replaced. This is the intended successful no-op until the rdashboard-owned stable
cutover path exists.

## 2026-07-17 private source credential boundary

U050 clarified that missing production credentials block activation, not continued implementation.
The source boundary now removes the first such blocker without borrowing the deploy user's identity.
Canonical installed-source schema v3 binds each SSH project to project-derived credential names and
the exact SHA-256 identities of its OpenSSH private key and known-hosts file. An SSH remote without
that binding, a binding attached to HTTPS, a renamed/cross-project credential, unsafe file metadata,
digest change, malformed OpenSSH framing or missing exact host pin fails before reconciliation.

The Git adapter receives a validated per-project command rather than one global identity. It clears
the environment and disables HOME/global/system configuration, credential helpers, terminal
prompting, SSH agents/default identities, passwords, keyboard interaction, global known hosts and
host-key updates. Strict host checking uses only the project credential copy loaded by the separate
`rdashboard-source-git-ssh.conf` systemd drop-in. The base unit remains usable for credential-free
HTTPS projects, and the web controller receives neither the credentials nor a Git command surface.

The new fixed-pilot `rdashboard-source-config` reads the three root-owned rimg files only from
`/etc/rdashboard/credentials`, derives the attestation public identity and credential digests, and
emits canonical JCS without putting private bytes in argv or stdout. It keeps auto-deploy disabled
and requires the exact installed owner-policy identity instead of inventing one. Future repositories
receive separate credential names; extending generation remains typed rather than hand-editing a
digest-covered document.

DeepSeek Free independently reviewed the complete source/transport/config/systemd diff at
`/tmp/rdashboard-source-ssh-review`, fingerprint
`a0b72b1cac948516e079af4c60cdd3210cf45a97fd595fbe4036d3839570b095`, and returned `ANSWERED/PASS`
with no P0-P2 finding. Its key-isolation, per-project binding, host-pinning, no-agent environment and
secret-free config observations match the locally inspected code.

The first bare `bin/ci` correctly failed Clippy because `parse_arguments` took an owned vector it did
not consume. The implementation was changed to accept a slice; no lint was suppressed. The complete
bare gate then passed: Clippy with warnings denied, 137 library tests, all binaries including 10
root-helper and two source-config tests, every integration suite including 23 store/web contracts,
seven Node browser tests, schema/document checks and the optimized release build in two minutes.
No production key, credential file, source config, repository state, service/drop-in activation,
GitHub permission or source fetch was created by this local slice.

## 2026-07-17 stable installed-deploy review

DeepSeek Pro reviewed the uncommitted installed-update/router/rollback diff through the global
`consult` dispatcher at `/tmp/rdashboard-stable-deploy-consult`. Route
`deepseek-pro` (`deepseek/deepseek-v4-pro`) returned `ANSWERED/CONCERNS` for repository fingerprint
`0d18979d7bf79eebe18380fcfcd993fbb97c36e51a0aa6cbd592c03912bf215c`.

Its high-confidence alias-exclusivity finding was valid: checking the owned router's own alias did
not exclude a second container advertising `rimg` on the same Docker network. The adapter now
enumerates the bounded exact network membership after bootstrap adoption, reopens each full Docker
container ID without a shell, and fails closed unless the exact owned router is the sole `rimg`
alias holder. The medium backup-freshness question was already enforced by
`resolve_base_backup_chain` against trusted boundary time and `code_only_backup_max_age_ms`; a new
cross-attempt installed-deploy contract test now proves stale historical backup rejection. The
low-confidence expiring-spec concern describes an intentional fail-closed recovery boundary: an
expired immutable phase authority is never silently refreshed after a crash because effect absence
may be ambiguous; it remains an operator-visible reconciliation failure rather than a repeated
privileged effect.
