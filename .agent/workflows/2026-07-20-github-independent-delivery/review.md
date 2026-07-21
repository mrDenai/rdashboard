# GitHub-independent delivery implementation review

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: slices 1a-4g complete locally; fixed OCI execution/handoff and separately authorized live gates remain pending
- Review date: 2026-07-21
- Baseline HEAD: `d20cf342dac204c51d30a32009eeb9c58097c8aa`
- Local implementation commits: `64e64f2` (`Add persistent resource observer`), `581a432`
  (`Add adapter execution receipts`), `25dff26` (`Add durable workflow scheduler`), `8b72141`
  (`Add authenticated workflow gateway`), `2973847` (`Add workflow dashboard projection`),
  `9598582` (`Add durable source delivery`), `1a076e8` (`Add durable GitHub source ingress`),
  `bfb887b` (`Add sealed workflow preparation store`), `a44b279` (`Add signed workflow launch boundary`),
  `d306521` (`Add generic workflow worker`), `3a3e426` (`Add sealed workflow input composition`),
  `ef952c9` (`Add fixed Cargo dependency preparation`) and `6962f58`
  (`Add bounded compiled operation state`)
- Slice 1a staged diff SHA-256: `ca9712b8517e0a7c42c6672d81abed2e8c74165337306dca0ded2bc5c36e6432`

## Reviewed scope

Slice 1a replaces the five-second `rdashboard-rimg-resources@.service` lifecycle with one persistent,
bounded, root-owned resource observer. The staged diff contains exactly these task-owned paths or
hunks:

- new typed observer protocol/client/server and socket lifecycle in `src/observer.rs`;
- new fixed Docker collector runtime in `src/bin/rdashboard-observer.rs`;
- rimg resource-client migration in `src/projects/rimg.rs`;
- removal of the legacy resource mode from `src/bin/rdashboard-rimg-health-proxy.rs`;
- new observer systemd service, controller ordering/environment changes, and deletion of the legacy
  resource socket/template units;
- observer contract/socket tests and narrow module, controller-constant and documentation wiring.

Pre-existing dashboard-notification work remains unstaged and outside this review. The exact staged
diff contains 14 paths, 1,746 insertions and 433 deletions. Production installation, Docker queries
against the VPS and the planned one-hour old/new observation comparison were not run.

## Independent consultation

- Route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`
- Dispatcher/CLI: status `ANSWERED`, one successful attempt, CLI `1.18.3`, 282 seconds
- Reviewed repository state fingerprint:
  `83c7e1e290462a3df3ef243e80eaa4cd8eb9b05a7864b2390661206b116f4524`
- Review brief SHA-256: `b97c6386682123263538cd029744d7dd6ff3e80ec07f85c6f47276499739590b`
- Response: `/tmp/rdashboard-observer-review-deepseek-2/response.md`

An earlier consultation attempt produced no review because the provider sandbox rejected an attempted
read of the repository `.env`. The successful brief supplied the already inspected non-secret
environment contract and explicitly prohibited reading `.env`.

## Findings and dispositions

1. **Accepted P1 — invalid handler evidence lost its diagnostic.** `handle_request` now logs the exact
   validation error and project ID before returning the bounded `internal_failure` rejection.
2. **Accepted P2 — a timed-out `spawn_blocking` collector could detach from the connection limit.** The
   connection now owns one absolute deadline and, after expiry, drains the same blocking task before
   returning and releasing its semaphore permit. A regression test proves the handler completes before
   the slot is released. Shutdown already drains all connection tasks.
3. **Accepted P2 — signal registration failure could look like a clean shutdown.** SIGINT and SIGTERM
   handlers are now registered before the shutdown future is passed to the server; registration failure
   propagates from `main` as startup failure.
4. **Reviewed P2 observation — a controller restart before the observer starts can briefly show
   `signal_lost`.** No code change: last-success evidence is intentionally process-local today, the old
   socket-activated design had the same cold-start property, and the next bounded poll repairs it.
   Persisting the last sample is a separate product/storage decision, not a regression in this slice.

No P0 was reported. After the accepted fixes and final self-review, no P0-P2 finding remains unresolved
inside the locally implemented slice.

## Verification

- Final post-review bare `bin/ci`: **passed**, exit code 0.
- Covered formatting and clippy, 176 library tests with 2 live-provider tests explicitly ignored,
  5 observer binary tests, 5 observer protocol/socket integration tests, all remaining Rust suites,
  schema validation, 8 browser tests and the optimized release build.
- Final release build completed in 2 minutes 20 seconds.
- `git diff --cached --check`: passed.
- The staged diff was inspected separately from the dirty worktree; notification implementation and
  workflow artifacts are not part of the staged observer change.

## Verdict

Slice 1a is production-worthy as a local implementation and may be committed. It is **not activated**:
installing/restarting units, removing the installed legacy units, executing live VPS measurements or
changing any provider remains behind explicit external authorization. Step 1 remains open for Failure
Capsule V2, terminal workflow receipts and the authorized live baseline/comparison at this review
checkpoint; the slice 1b review below closes the first two items.

## Slice 1b: Failure Capsule V2 and adapter execution receipts

### Reviewed scope

Slice 1b adds a reusable execution-evidence contract and applies it to the existing fixed transient
adapter boundary without adding a second security-journal truth or touching the unrelated notification
projection:

- `src/domain/execution.rs` defines canonical digest-bound terminal and cleanup receipts, typed process/
  cgroup/storage evidence and exact explicit-gap invariants;
- `src/execution_receipt.rs` and `rdashboard-adapter-receipt` persist exact start evidence, capture the
  terminal cgroup before systemd collection, bind start-to-terminal-to-cleanup and reject unsafe files,
  ambiguous replay, substituted starts and incomplete new results;
- `src/adapter.rs` installs one fixed root-owned `ExecStopPost`, validates its executable and requires
  terminal/cleanup proof while preserving completed legacy jobs without start evidence;
- `src/domain/failure.rs` adds a 64 KiB canonical Failure Capsule V2 with cause-first deterministic
  Markdown, typed resource/artifact/release context and V1 JSON compatibility;
- `src/domain/redaction.rs` records a stable ruleset digest and replacement count while stripping ANSI,
  control characters and secret forms before any bounded evidence is persisted;
- controller validation, fixed profile IDs, contract tests and the narrow systemd installation note
  complete the slice. Shared dirty `src/lib.rs` and systemd README hunks were staged selectively.

Production installation and a real transient-unit drill were not run because they mutate the VPS and
remain behind explicit external authorization. The local cgroup fixture covers parser, binding,
capture-before-cleanup, canonical replay, permission and start-substitution behavior.

### Independent consultation

First round:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 318 seconds;
- state fingerprint: `e488e464c4c1fe7530819ba9fd6b384cf8ccbabeea88fde53e4c74fc5347143c`;
- brief SHA-256: `e727bfbbdffbc3d42b6f07214ac859dd2ee6b557c69039ae4dd80f824bffd34e`;
- response: `consult-slice1b-deepseek/response.md`;
- verdict: `SAFE`, no P0/P1 blocker.

Final post-fix round:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 145 seconds;
- state fingerprint: `5a092d1d21cee383b912421c832fa61671cd082e988730a8d9ed130e4c74da7e`;
- brief SHA-256: `9eaac7ba29921b895c62c0cdd5a6c3b28f77d7b0721ac041a12bb852cb6482ae`;
- response: `consult-slice1b-deepseek-final/response.md`;
- verdict: `SAFE`, no P0/P1/P2 blocker; exact staged diff approved for local commit.

### Findings and dispositions

1. **Verified no-finding — ExecStopPost cgroup identity.** The helper executes inside the same service
   cgroup, whose cumulative counters remain readable until `ExecStopPost` completes; no change.
2. **Accepted P2 — terminal receipt did not chain the exact start document.** The terminal receipt and
   its digest now include `start_evidence_digest`; every read revalidates the canonical start and exact
   request binding. The cgroup fixture replaces the start with another valid digest-bound document and
   proves reconciliation rejects it.
3. **Verified no-finding — unknown scratch cleanup delta.** It remains `None` with an exact
   `scratch_removed` evidence gap rather than a fabricated zero.
4. **Accepted P2 — zero reserve obscured a deficit.** Storage evidence now carries a validated
   `(required, remaining, deficit)` tuple. A 5 GiB available / 8 GiB required contract test proves a
   3 GiB deficit and rejects an inconsistent zero deficit.
5. **Declined P2 hygiene — shared token validator.** The similar validators protect different domain
   contracts and remain deliberately local; a shared abstraction would couple their future evolution
   without removing a current defect.
6. **Final P3 observations — no blocker.** Reopening start evidence at authorization, capture and final
   read boundaries is intentional fail-closed revalidation, not an unsafe cache omission. A successful
   systemd service result denotes clean main-process completion for this fixed `Type=exec` unit; no
   concrete inconsistent state was identified. Termination intent canonicality is enforced on every
   production read; a standalone encode/decode helper would duplicate that tested path.

### Verification

- Final post-review bare `bin/ci`: **passed**, exit code 0.
- Covered formatting, Clippy with `-D warnings`, 181 library tests with 2 credentialed live-provider
  tests ignored, all binary and integration suites, 4 failure/receipt contract tests, schema validation,
  8 browser tests and the optimized release build.
- Final release build completed in 2 minutes 49 seconds.
- Exact staged code/doc/test diff SHA-256 (workflow artifacts excluded):
  `588f374c0aeb2f93988789ccda02c659ed0ac7e1f87b99f7238e9bae2a9bce23`.
- Exact staged manifest and shared-file hunks were inspected separately from the dirty worktree;
  unrelated notification implementation remains unstaged.

### Verdict

Slice 1b is production-worthy as a local, inactive implementation and may be committed. It does not
install the helper, restart systemd, run against the live VPS, activate deployment authority or complete
the one-hour baseline/comparison. Step 1 therefore remains open only for that separately authorized live
evidence; Step 2 remains the next local implementation dependency.

## Slice 2a: installed workflow contract and durable scheduler journal

### Reviewed scope

Slice 2a adds the inactive repository-agnostic scheduling core without installing a worker or duplicating
the existing privileged effect journal:

- `ProjectManifestV2` and the generated V2 schema add a strict finite workflow DAG while preserving the
  V1 manifest and schema. The root-installed loader accepts only stable owner-private canonical `.jcs`
  files and binds the complete manifest to its workflow-policy digest.
- The workflow domain names only fixed node kinds, adapters, worker pools, network/cache classes,
  timeouts, resource envelopes and artifact contracts. Canonical leases bind the complete execution
  profile, exact source/policy/preparation/input identity, worker, host, generation and deadline.
- Control schema version 2 atomically adds strict request, trigger, head, attempt, node/dependency,
  lease, receipt, reduction, mutation-lock, transition and fairness-cursor tables, with a tested V1
  reopen migration.
- The scheduler implements stable cross-channel admission identity, source high-water checks,
  pre-mutation supersession, project mutation single-flight, weighted cross-project claims,
  generation-bound lease expiry, late/conflicting receipt rejection and deterministic reduction.
- Required preparation and release builds stay in the VPS-required pool. Optional i9-style compute can
  claim verification only and therefore cannot own a required preparation or deployment artifact.
- Two different project fixtures exercise the same catalog, queue and protocol model. The `ralert`
  source manifest is upgraded to inactive V2, but no installed canonical mirror, worker runtime or
  deployment is enabled.

The exact staged code/config/test diff contains 17 paths, 6,025 insertions and 38 deletions. Shared dirty
`src/lib.rs` and `tests/store_and_web.rs` were staged by hunk; notification implementation and its
workflow artifacts remain outside this review.

### First independent consultation and self-review disposition

- Route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`.
- Status: `ANSWERED`, one attempt, CLI `1.18.3`, 270 seconds.
- Reviewed state fingerprint:
  `2421725e8399f541d2e00044f48a3b502bb1868d96200a65026bb099da856884`.
- Brief SHA-256: `b5e6bd86b9cc8a6ae406b7854cf6cd074bb3ac09188102ed0026ad3b109f336c`.
- Response: `consult-slice2a-deepseek/response.md`; verdict `SAFE`, no P0-P2 finding.

The first response reviewed staged hash
`d749fd30d8fe1df1d129cddf62816b8f9f0f8bcbf892c504634851ed0e4ee9c8`. Independent self-review did
not stop at that verdict and found hardening gaps the consultation had missed:

1. Canonical leases named a profile but did not carry its full runtime envelope. They now digest-bind
   network, cache, timeout, resources and input/output artifact contracts and reject a controller-managed
   or kind-inconsistent worker lease.
2. The optional build-compute pool could own the only host-preparation node. Authoritative preparation
   now remains VPS-required; optional compute can claim verification but neither preparation nor release.
3. A previously persisted reduction replayed its cached receipt without re-reading source receipts.
   Replay now reconstructs the complete evidence set, validates row/document/node bindings and rejects a
   reduction timestamp earlier than its latest committed input.
4. Several conditionally updated rows were assumed rather than counted. Lease, node, attempt, request and
   mutation-lock transitions now require the exact affected-row count; terminal success fails atomically
   when the held project lock is missing.

The hardening changed the reviewed source. Its exact staged code/config/test diff SHA-256 is now
`ce07e41ae6aba45c499900fdded60b2eecb5bd8a4e5be56ba6707807e4da862e`; therefore a fresh final
consultation was started rather than reusing the first `SAFE` response.

### Verification after hardening

- Bare `bin/ci`: **passed**, exit code 0.
- Covered formatting, Clippy with warnings denied, 184 library tests with 2 credentialed live-provider
  tests ignored, all binary/integration suites, the V1-to-V2 migration, 10 scheduler contract tests,
  schema drift checks, 8 browser tests and the optimized release build.
- The final optimized release build completed in 2 minutes 55 seconds.
- New regression evidence covers optional accelerator placement, non-monotonic reduction rejection and
  source-receipt tamper detection on persisted reduction replay after restart. Two end-to-end tests also
  prove terminal success releases the mutation lock and wakes the newer head, while a missing held lock
  rolls the entire terminal-receipt transaction back and leaves the observation node leased.
- `git diff --cached --check`: passed.

### Final consultation, findings and closure

Full post-hardening round:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 177 seconds;
- state fingerprint: `3d2955ae9c1bc1bb1e2f88679771bf509b1a39ae9e02e68eb2ef2e7398d901f7`;
- brief SHA-256: `d73d0a228457e22b98a118371cce4e286a0a673966b7fa4da9ffb001a664400a`;
- response: `consult-slice2a-deepseek-final/response.md`;
- verdict: `SAFE`, no P0/P1, with one actionable low-confidence P2.

Finding dispositions:

1. **Accepted P2 — non-mutation expiry did not count the guarded node update.** The active lease,
   `leased -> ready` node and attempt timestamp updates now each require exactly one affected row.
2. **Partially accepted latency suggestion — combine expiry with its following operation.** `claim_next`
   now expires and claims inside one immediate transaction. The same change for receipt submission was
   tested and rejected: the expected late-receipt error rolled back the expiry and left the node leased.
   `commit_node_receipt` therefore intentionally commits expiry first, then validates the receipt in a
   second transaction; a regression test proves the expired node remains ready after rejection.
3. **Verified no-finding — terminal receipt replay.** Exact receipt replay exits through the persisted
   receipt branch and does not rerun lock release; no idempotency defect exists.
4. **Verified no-findings — reduction ordering and lease generation.** Both are canonical and monotonic
   by construction and persisted checks.

Exact closure round:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 67 seconds;
- state fingerprint: `61a57a32bb45af11165c4ea96f4119fbd16b1924f6ea22fb945c20fcef3496a1`;
- brief SHA-256: `92e1f67ba173ff10ff8bfbba823134b5deb2a69410be4f07c131348af25bc934`;
- response: `consult-slice2a-deepseek-closure/response.md`;
- verdict: `SAFE`; the P2 is fixed, the deliberate receipt transaction boundary is correct, and no
  P0-P2 regression remains.

The final exact staged code/config/test diff SHA-256 (workflow artifacts excluded) is
`cf105882140ff6d8b57806823ee6e27cbda9497fc9ee806099bc0df3a204b2df`.

### Verdict

Slice 2a is production-worthy as an inactive local foundation and may be committed. It does not expose
an unauthenticated scheduling surface or activate a deploy: the worker protocol/runtime, cleanup
reconciliation, controller/web projection and source ingress remain explicit subsequent work. No VPS
installation, GitHub/provider mutation, push, service restart or deployment was performed.

## Slice 2b: authenticated worker gateway, renewal and cleanup reconciliation

### Reviewed scope

Slice 2b completes the unprivileged transport and cleanup portion of the scheduler boundary without
installing a worker or granting deployment authority:

- Canonical cleanup receipts bind the exact lease and, when required, its exact terminal-pending node
  receipt. A new schema-V3 journal accepts exact replay, rejects conflicting evidence and preserves
  expired, revoked and terminal-pending cleanup debt across restart.
- Lease renewal keeps the assignment, lease ID and generation stable, changes only expiry/digest,
  never crosses the installed node timeout and returns the current canonical lease when a prior
  renewal response was lost.
- `claim_next` expires leases, checks cleanup debt for the exact worker/host and claims the next node in
  one immediate transaction. Cleanup therefore cannot be bypassed through another scheduler caller or
  a race between gateway polling and claiming.
- One typed AF_UNIX protocol serves every installed project through a fixed worker identity. Peer UID
  is checked before frame decoding; frames, request deadlines, connections, socket paths and stale
  socket reconciliation are bounded. Unprivileged registrations cannot name controller or privileged
  executor pools.
- The separate gateway binary owns `control.sqlite` access and controller-node reconciliation. Its
  inactive systemd unit has no network namespace, Docker/source/executor socket, production volume,
  capability or credential authority. The actual worker executor, sealed preparation store and hard
  storage fence remain step 4.

The exact staged code/config/test diff contains 12 paths, 2,711 insertions and 31 deletions. Shared
dirty `src/lib.rs`, `tests/store_and_web.rs` and `deploy/systemd/README.md` were staged by hunk; all
notification implementation remains unstaged and outside this review.

### Self-review correction and verification

Self-review found that cleanup-before-reuse was initially enforced by the gateway but not by the
scheduler API itself. This left an alternate caller and a narrow concurrent transition able to claim
new work after cleanup debt appeared. The invariant now lives inside the same immediate transaction as
lease expiry and claim. The first full gate after that correction exposed one prior test whose old
expectation reissued an expired node without cleanup. The test was corrected to prove reopen, blocked
claim, exact cleanup receipt and generation-2 reissue; no production behavior was weakened to make the
gate pass.

- Bare `bin/ci`: **passed**, exit code 0, after the final correction.
- Covered formatting, Clippy with warnings denied, 184 library tests with 2 credentialed live-provider
  tests ignored, every binary and integration suite, V1-to-V3 and V2-to-V3 control-store migrations,
  13 scheduler contracts, 3 worker-socket contracts, 8 browser tests and the optimized release build.
- The optimized release build completed in 2 minutes 50 seconds.
- `git diff --cached --check`: passed.

### Independent consultation

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 196 seconds;
- state fingerprint: `eb61db5ad5fd401f8449bef53023fbdca6eb89dfb11b884d735c815dbfe99d1d`;
- brief SHA-256: `2fcf732ee993d803d3fa96752f7477515f5edde3e69a03713f6bd5aadd5e6cc6`;
- response: `consult-slice2b-deepseek/response.md`;
- verdict: `SAFE`, no P0-P2 finding and no open question.

The reviewer independently traced cleanup binding/replay, restart durability, the atomic
cleanup-before-reuse transaction, bounded renewal/lost-response replay, peer authentication, socket
lifecycle, systemd least privilege and both schema migrations. The exact staged code/config/test diff
SHA-256 (workflow artifacts excluded) is
`6f34022a5bd8ec926e14183c713d7a6151f1cba18171c66aefec09aa280d48bb`.

### Verdict

Slice 2b is production-worthy as an inactive local gateway contract and may be committed. It does not
install or enable the service, run generic worker jobs, grant Docker/root mutation authority, project
workflow state into the controller/web UI, complete source ingress or deploy anything. No VPS,
GitHub/provider or other external system was mutated.

## Slice 2c: read-only workflow journal projection

### Reviewed scope

Slice 2c closes the local controller/dashboard projection for implementation-plan step 2 without
adding workflow mutation authority:

- `WorkflowJournalReaderV1` exposes one bounded read-only journal capability. It reads attempts and
  nodes through a deferred SQLite transaction, validates the exact persisted snapshots, accepts limits
  1 through 50, reads one extra attempt for truthful truncation and orders newest-first with stable
  tie-breakers.
- GET `/api/v1/workflows` defaults to 20 attempts, validates the bound, moves blocking SQLite work off
  the async runtime and captures its response time after the consistent read. Every server-side failure
  logs its exact value and returns one fixed generic HTTP 500 problem.
- The browser polls every five seconds without overlap, strictly validates the exact V1 response,
  preserves the last valid snapshot on refresh failure and renders loading, empty, truncated, success,
  recovery, cleanup-required and stale/error states. Failed or reconciliation-required nodes take
  priority over merely ready work.
- The dashboard uses a native refresh button, semantic caption/headers/row headers, centralized live
  announcements, `textContent` insertion and keyboard-focusable real overflow scrolling. It introduces
  no experimental browser API, credentials, raw logs, mutation tokens or repository-specific path.

The exact staged product/test diff contains 11 paths, 969 insertions and 2 deletions. Shared dirty web,
route and test files were staged by hunk; notification implementation and its workflow artifacts remain
unstaged and outside this review.

### Self-review and first consultation

Self-review corrected two concurrency/presentation defects before consultation: `generated_at_ms` is
now captured after the journal read so a concurrent newer row cannot invalidate an otherwise successful
response, and failed nodes now take current-step priority over ready nodes. Both have regression
assertions.

The first exact-staged consultation returned `SAFE` with two actionable P2 findings:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 211 seconds;
- state fingerprint: `feaa4ea4c7c8db46788f23f4eba6de8f41530d45cfdd76a208d129c9b1b901a0`;
- brief SHA-256: `c90f8ee1dc5fb2b6f745f739e4228653e0b9fa4f02919f92dd63dae862663e83`;
- response: `consult-slice2c-deepseek/response.md`.

Finding dispositions:

1. **Accepted P2 — journal errors leaked internal SQLite/validation detail and returned mutation-style
   HTTP 400.** A dedicated `workflow_overview_problem` logs the real store error and returns HTTP 500,
   code `workflow_overview_failed` and the fixed detail `Workflow overview could not be loaded.`
2. **Accepted P2 — the clock failure exposed `SystemTimeError::Display`.** Clock and blocking-task join
   failures now use the same sanitized mapper. A corrupt persisted project ID containing an internal
   marker proves the response contains neither that marker nor an internal validation fragment.

### Exact verification and final consultation

- A refreshed exact `git checkout-index` staged export passed bare `bin/ci`, exit code 0, after both
  accepted fixes.
- It covered formatting, Clippy with warnings denied, 167 library tests with 2 credentialed live tests
  ignored, every binary/integration suite, 29 store/web contracts, 14 scheduler contracts, 8 browser
  contracts, schema checks and the optimized release build.
- The final optimized release build completed in 2 minutes 49 seconds.
- `git diff --cached --check`: passed.
- Exact staged product/test diff SHA-256 (workflow artifacts excluded):
  `c33ee2422411e306b023cb12f2f69ed5f5b3a907a72260237b1ebd7d52d261df`.
- Modern web guidance was applied for table semantics, error announcements, native controls and real
  overflow behavior. The in-app browser-control surface was unavailable, so no visual browser QA is
  claimed; executable JavaScript contracts and static semantic assertions passed.

Final post-fix consultation:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 251 seconds;
- state fingerprint: `4061e3dc96bd80922fbd087ce191914d96efa18e26e8845595b9121dcf8214c4`;
- brief SHA-256: `210bc7370be221b263984ec1d880c13da0120de547cbcde8f6d0f5193981e17f`;
- response: `consult-slice2c-deepseek-final/response.md`;
- verdict: `SAFE`, no actionable finding and no open question.

The reviewer independently verified the sanitized store/clock/join failure boundary, bounded consistent
snapshot, deterministic ordering, post-read response time, strict browser schema/cardinality/order,
non-overlapping stale-preserving polling, recovery-state priority and semantic DOM behavior.

### Verdict

Slice 2c is production-worthy as an inactive local read-only projection and may be committed. It closes
implementation-plan step 2 locally, but does not install or restart services, expose source ingress,
execute worker jobs, activate deployment authority, write to GitHub or deploy anything. The authorized
live resource baseline remains a separate activation gate; the generic worker and sealed preparation
store remain step 4 after source-ingress work.

## Slice 3a: signed source outbox and isolated scheduler delivery

### Reviewed scope

Slice 3a implements the durable middle of implementation-plan step 3 without activating an ingress or
deploy:

- Source schema V3 adds a canonical signed accepted-head outbox committed in the same immediate
  transaction as the completed deployable source delivery. Newer project sequences supersede older
  pending rows; lost acknowledgements replay a digest-derived scheduler delivery ID; settled history
  is capped at 2,048 rows.
- `rdashboard-source` serves the outbox through a second versioned AF_UNIX protocol. The server checks
  the installed controller UID before decoding; the client checks the source UID before writing. The
  request, response, frame, deadline, connection, batch, stale-socket and inode-cleanup contracts are
  bounded and fail closed.
- A separate networkless `rdashboard-source-dispatcher` verifies canonical entry binding, Ed25519
  signature/expiry, current auto-deploy enablement, repository identity, installed source policy and
  exact workflow-manifest digest before idempotent scheduler admission. It acknowledges only durable
  admission or a provably stale scheduler sequence and applies bounded transient/permanent backoff
  without allowing one rejected project to block later batches.
- Installed source config schema V4 binds both peer identities and socket paths. The root-owned
  workflow catalog has an exact group-readable installation contract for the unprivileged dispatcher.
  The source process does not join the controller group; the dispatcher receives no network, source
  credential, source database, Git, Docker, root or arbitrary-command authority.

The exact final staged product/test diff contains 14 paths, 2,699 insertions and 76 deletions. Shared
dirty `src/lib.rs` and `deploy/systemd/README.md` were staged by hunk; all notification code and its
workflow artifacts remain unstaged and outside this review.

### Verification and self-review correction

The first complete live-worktree bare `bin/ci` passed before consultation with 184 active library
tests, every binary/integration suite, 30 store/web contracts, 14 scheduler contracts, 9 browser
contracts, schema checks and the optimized release build in 2 minutes 50 seconds.

The first exact-staged consultation returned `SAFE` with no P0-P2 finding or open question:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 212 seconds;
- state fingerprint: `7dd4a950d4ae46035743077681739f9505df9b01471d27b81131c71bcd6e4ba3`;
- brief SHA-256: `5947b0706b9c9c7f33aaf53c722956c54091ac2a290a8c3d615e50de200531f5`;
- response: `consult-slice3a-deepseek/response.md`;
- reviewed product/test hash:
  `dbe21b0364dcfacc5d51986989ae2efd1b9c230ca3b6dd5525893bc9cb3979da`.

Post-review self-audit then found a stale-policy path the reviewer missed: a row enqueued while
`auto_deploy=true` could remain pending after source restarted with that project disabled or removed.
A dispatcher still holding the old enabled config could fetch it after restart because auto-deploy is
not part of the signed accepted-head payload.

The correction derives the exact enabled-project set during broker construction and reconciles the
outbox under the current broker epoch and one immediate transaction after source recovery but before
any socket can bind. Disabled/removed pending rows become superseded. Re-enabling an unchanged current
head reactivates only the exact undelivered row; delivered rows remain delivered. ACK now also prunes
settled retention, and supersession timestamps cannot precede enqueue time. A restart regression proves
enabled pending -> disabled broker has no pending delivery -> re-enabled reconciliation restores the
same sequence-1/current-SHA delivery.

A refreshed exact `git checkout-index` staged export passed bare `bin/ci` after that correction:

- 167 active library tests, with 2 credentialed live-provider tests ignored;
- every binary and integration suite, including 7 source-delivery, 29 store/web, 14 scheduler and
  8 browser contracts;
- strict formatting, Clippy with warnings denied, both manifest schema checks and the optimized release
  build in 2 minutes 38 seconds;
- `git diff --cached --check`: passed;
- final product/test diff SHA-256:
  `0c5f01a1d2c32dc261e586cc8bac0d000275daf18cf7538eaa6ea4cc318c54a8`.

### Final independent consultation

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 242 seconds;
- state fingerprint: `d786fa4392c1031442329164b30c36ed3b6b773ce4e7c695fd5372b7828b79fa`;
- brief SHA-256: `c7beb3fae77873920a1dc32ced31368234a5266dfe85d41fccc3de76a4a7a241`;
- response: `consult-slice3a-deepseek-final/response.md`;
- verdict: `SAFE`, no actionable P0-P2 finding and no open question.

The final reviewer independently recomputed the exact product/test hash and traced disable/removal
revocation before socket bind, safe undelivered reactivation, delivered replay, epoch fencing,
transactional outbox admission, signature/policy/repository verification, bounded cross-project drain,
socket peer authentication, schema migration and systemd authority separation.

### Verdict

Slice 3a is production-worthy as an inactive local source-to-scheduler delivery boundary and may be
committed. It does not install/start either service, enable auto-deploy, expose HTTP webhook or
forced-push ingress, generalize the fixed rimg config generator, run a VPS timing drill, execute a
workflow, contact GitHub/providers, push or deploy. Those remain explicit later parts of plan step 3.

## Slice 3b: durable multi-project GitHub webhook ingress

### Reviewed scope

Slice 3b completes the local GitHub push-ingress portion of implementation-plan step 3 without
activating it:

- Installed source schema V5 is generated from every exact project in the installed workflow catalog.
  It binds the GitHub repository, webhook-secret digest, optional project-scoped read-only SSH
  credential digests, source controls and distinct source/ingress/controller/build identities. Secret
  bytes are loaded into zeroizing buffers and never serialized into the generated catalog.
- A generated systemd credential drop-in replaces the fixed rimg-only SSH wiring. The example catalog
  contains only inactive `ralert`; adding another repository is a root-owned installation action, not
  a code or worker-topology fork.
- A separate loopback-only HTTP ingress validates exact project routes, media type, GitHub event,
  delivery ID and bounded raw body before forwarding the unchanged body over a versioned,
  peer-UID-authenticated AF_UNIX protocol. It has no webhook secret, source database, Git, Docker,
  controller, executor or production-volume authority.
- The source broker verifies GitHub HMAC, repository identity and main-ref binding before committing a
  content-bound, idempotent and secret-free SQLite wake-up. The queue is capped at 2,048 rows globally
  and 128 per project; restart recovery re-signals retained work and retires wake-ups for removed or
  rebound projects.
- Project coordinators drain the full pending batch after one foreground fetch, retry delayed remote
  visibility from 250 ms to five seconds and preserve the accepted delivery until resolution.
  Webhook priority is durable and project-aware: it interrupts active periodic network work, prevents
  new periodic work from queuing ahead of it and retries deferred periodic work without starving other
  projects. Periodic network fetches retain a two-second ceiling.

The exact final staged product/config/test diff excludes workflow artifacts and contains 21 paths,
4,768 insertions and 406 deletions, with SHA-256
`5b2808f5e304074cced07397d5600c2b554d7c7af87e652fddcf4310ee5a62d3`. Shared dirty `src/lib.rs`
and `deploy/systemd/README.md` were staged by hunk; all pre-existing notification code, notification
workflow artifacts and earlier untracked consultation logs remain unstaged and outside this review.

### Verification

An exact `git checkout-index` export of the staged product state passed bare `bin/ci`:

- formatting and Clippy with warnings denied;
- 171 active library tests, with two credentialed provider tests ignored;
- every binary and integration suite, including 8 source-ingress, 7 source-delivery, 29 store/web,
  14 scheduler and 8 browser contracts;
- both manifest schema checks and the optimized release build, which completed in 3 minutes 41 seconds
  from the cold isolated export;
- `git diff --cached --check`: passed.

Focused real-Git coverage also passed all 34 repository tests; the ingress protocol suite passed all
8 contracts outside the filesystem sandbox; and the source config/HTTP binaries passed their 0/4/2
unit-test sets. A full live-worktree library run passed 188 active tests with two ignored, but includes
unrelated unstaged notification work and is not used as the exact-slice gate.

### Independent consultations and dispositions

The first exact-staged review returned a complete `SAFE` response with no P0-P2 defect or open
question, although the dispatcher classified the attempt as `PARTIAL` after 150 seconds:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- state fingerprint: `245a840cf011310a7b7709949a153c389ee403a5d4b3b479a91e676f0cd0d6a4`;
- brief SHA-256: `d6d8913435b21ffa7a27a5f86da0f7cab90d6c0d3f41eff2d87b89cdd23e93a2`;
- response: `consult-slice3b-deepseek/response.md`.

That response contained five P3 observations. Its first was factually invalid: the cited
`enqueue_github_wakeup` query already scopes duplicate delivery IDs by `project_id`,
`SourceChannel::GithubWebhook` and `delivery_id`. The remaining four describe a deliberate 503 on a
failed socket negotiation, bounded staging work discarded by fetch preemption, harmless interval
drift after deferred work and a documented clear/re-read race whose concurrent ingress signal prevents
loss. None changes correctness or requires code churn in this slice.

A concise fresh final review independently rechecked the staged source and returned `ANSWERED` and
`SAFE — no P0-P2 defect found`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- one successful attempt, CLI `1.18.3`, 395 seconds;
- state fingerprint: `245a840cf011310a7b7709949a153c389ee403a5d4b3b479a91e676f0cd0d6a4`;
- brief SHA-256: `c2112573b923b7b5ee108ff9a9ad42b37fcedc70a09b4c1bbd54281089c0bbe3`;
- response: `consult-slice3b-deepseek-final/response.md`.

The final reviewer explicitly confirmed the earlier P3 #1 was invalid and traced the loopback and
peer-auth boundaries, HMAC/repository verification, bounded idempotent queue, cross-project
preemption, two-second periodic ceiling, one-fetch batch drain, restart/remap recovery, V5 secret-free
configuration and absence of project-specific worker topology.

### Verdict

Slice 3b is production-worthy as an inactive local GitHub source-ingress boundary and may be committed.
It does not install or start services, expose the loopback route through a public proxy, register a
GitHub webhook, add credentials, enable auto-deploy, contact a provider, mutate the VPS, push or deploy.
Forced-push ingress and the separately authorized live latency/recovery drill remain in plan step 3;
the generic worker and sealed shared preparation store are the next local implementation step.

## Slice 4a: exact workflow source binding and sealed preparation store

### Reviewed scope

Slice 4a completes the inactive preparation foundation needed by the repository-agnostic worker without
executing repository code or installing a service:

- New workflow leases digest-bind the admitted source sequence and attestation. Legacy leases without
  this optional identity remain canonically decodable so persisted history survives the upgrade, but
  `required_source_identity` refuses to start work from them. Claim and renewal contracts retain the
  exact identity across scheduler restart.
- `SourceArchiveReaderV1::exact` opens only the immutable project/head/sequence publication named by
  the lease and verifies its manifest; the preparation API cannot substitute mutable `latest` source.
- `PreparationStore` provides policy-bound typed keys for exact source snapshots, dependency snapshots
  and prepared runs, same-key single-flight, atomic staging/rename/sealing, recursive checksum and
  ownership validation on every open, durable bounded pins and cold LRU eviction.
- Production admission requires the CAS root itself to be a dedicated mount, rejects work below a
  12 GiB root-filesystem reserve and applies the initial 6 GiB/100,000-inode persistent ceiling.
  Reservations include manifests, directory inventory and access sidecars; symlinks, hard links,
  special files, unsafe paths, oversized files, excessive depth and entry counts fail closed.
- Startup removes orphan staging, validates and seals an interrupted post-rename publication, finishes
  durable journaled evictions, removes stale access records, recreates a missing sidecar for a complete
  publication and cleans expired pins before admitting work.

The exact staged product/test diff contains 6 paths, 3,230 insertions and 10 deletions. The shared dirty
`src/lib.rs` was staged by hunk; unrelated notification implementation and its workflow artifacts remain
unstaged and outside this review.

### Verification

- Targeted preparation regressions passed 10/10 after the crash-recovery correction. They cover typed
  deterministic keys, same-key concurrency, producer failure, orphan staging, interrupted publication,
  interrupted eviction after manifest removal, checksum tamper, unsafe links, pins/LRU, emergency
  reserve enforcement and exact sequence selection while a newer source is `latest`.
- Full-project Clippy passed with warnings denied after the correction.
- A fresh `git checkout-index` export of the final staged state passed bare `bin/ci`: formatting,
  Clippy, 182 active library tests with 2 credentialed live-provider tests ignored, every binary and
  integration suite, 14 scheduler contracts, 8 browser contracts, schema checks and the optimized
  release build in 2 minutes 58 seconds.
- The first final-export attempt stopped only because its duplicate 4.3 GiB Cargo target exhausted the
  `/tmp` quota. The two task-created temporary targets (17.2 GiB reported by `cargo clean`) were removed;
  the rerun used the same exact source export with the existing Cargo target only as a dependency/build
  cache and completed successfully. No tracked, application or user-owned state was removed.
- `git diff --cached --check`: passed. Final exact staged product/test diff SHA-256:
  `5b7aa36503b7347749e71f9cfb88764d63488f34640e52073a9c9720fbdaed74`.

### Independent consultations and finding dispositions

The first exact-staged review returned a complete `SAFE` response except for one high-confidence P2,
although the dispatcher classified the response as `PARTIAL` after 200 seconds:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- state fingerprint: `70156753af3b5a55b7f28f4045b926bcd23deb0abbb89362404d562029350145`;
- brief SHA-256: `5cf82435a9accc373972bdb7bc11c1456d4aaa1c55e66754d0161d2e80be1c0e`;
- response: `consult-slice4a-deepseek/response.md`.

The P2 was valid: recursive removal first changed the sealed entry root from 0555 to 0700. A crash after
unlinking `manifest.jcs` could leave a partial 0700 tree which startup misclassified as an incomplete
publication, making the whole store fail to reopen. Removing the manifest last would only move the crash
window, so eviction now persists a kind/key marker by atomically moving the existing access sidecar into
`evictions/` before any destructive change. Startup completes those idempotent evictions before examining
incomplete publications. A regression reproduces the exact crash after manifest removal and proves reopen
removes both the partial object and marker.

The fresh post-fix review again produced a complete response with dispatcher status `PARTIAL` after
195 seconds:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- state fingerprint: `490995c927b78f6be45d6060b3e4c769562b1648c8643ad99ac94d9d4474ed43`;
- brief SHA-256: `14f80afbfc2982fa5d5032f79383d8151fac92fa863f05c150cb238942609c3a`;
- response: `consult-slice4a-deepseek-final/response.md`;
- verdict: `SAFE`, no P0-P2 correctness, security, concurrency, crash-safety, compatibility or resource-
  accounting defect.

Final P3/open-question dispositions:

1. A crash between pin unlink and directory fsync can only retain the exact validated pin until its
   already-bounded expiry; startup expiry cleanup and conservative eviction remain correct. No change.
2. Rechecking pathname identity after reading intentionally converts concurrent pathname substitution
   into a fail-closed `EntryChanged`; replacing it with only descriptor metadata would weaken that check.
3. The comparator's invalid-base64 fallback is unreachable after strict manifest validation; changing
   it to a panic would reduce robustness without fixing an observable path.
4. An eviction marker replaces, rather than adds to, the counted access sidecar. Startup drains every
   marker before usage scanning and the commit lock permits only one live marker; no capacity bypass.
5. The scheduler columns questioned by the reviewer are not a missing migration: existing control schema
   V2 already defines non-null `workflow_requests.source_sequence` and
   `workflow_requests.source_attestation_digest`, and reopen integration passed in the exact gate.

### Verdict

Slice 4a is production-worthy as an inactive local foundation and may be committed. It does not execute
repository commands, prefetch dependencies, create mutable build slots, install/start a worker, grant
root authority, mutate the VPS, contact GitHub, push or deploy. The signed execution boundary, fixed root
launcher and generic worker consumption of this exact CAS are the next local slice of plan step 4.

## Slice 4b: signed execution grants and fixed root launcher

### Reviewed scope

Slice 4b completes the inactive privilege boundary needed before the generic worker may execute a
sealed input:

- Concrete workflow leases now carry the exact sorted dependency node, artifact kind and output digest
  set used to calculate `expected_input_digest`. Historical leases remain canonically decodable, but a
  signer or launcher refuses any lease without exact source and input-artifact identity.
- The workflow gateway issues canonical, purpose-separated, short-lived Ed25519 execution grants bound
  to the exact lease, request, attempt, project, worker, host, adapter, nonce, issuer, audience, key ID,
  key epoch and validity interval. Its raw 32-byte seed is loaded only from a root-owned systemd
  credential, zeroized after use and required to match the configured public key.
- The root launcher authenticates the configured worker UID before request decode, verifies the grant,
  reopens and revalidates the exact sealed `PreparedRun`, and constructs the complete `systemd-run`
  invocation itself. The worker cannot provide argv, a host path, credentials, a network mode or a
  systemd property.
- The derived transient unit uses the fixed build UID/GID, read-only `/workspace`, a private byte/inode-
  bounded `/job` tmpfs, no network, no capabilities, no controller/source/gateway/launcher/runtime
  sockets, fixed CPU/memory/task/output/runtime limits and one fixed adapter-to-script mapping. A
  sorted root-policy allowlist keeps uninstalled native/OCI adapters disabled.
- A canonical root-private journal persists acceptance before spawn, deduplicates lease renewal by
  stable execution identity, turns ambiguous accepted/running startup state into `needs_reconcile`,
  persists cleanup before stop and replays terminal/cleanup evidence idempotently. The record count and
  concurrent active set are bounded.
- The gateway and launcher protocols are independently versioned, frame/concurrency/time bounded and
  peer-UID authenticated. The new service and tmpfiles declarations remain inactive and grant neither
  Docker nor deployment authority.

The exact staged product/config/test diff contains 19 paths, 5,349 insertions and 78 deletions. Shared
dirty `src/lib.rs` and `deploy/systemd/README.md` hunks were staged selectively; all notification code,
notification workflow artifacts and earlier consultation logs remained outside the reviewed diff.

### Verification

- The first live-worktree bare `bin/ci` passed, including the optimized release build in 3 minutes 9
  seconds, but was not used as the final exact-slice evidence because unrelated notification work is
  present in that tree.
- The first exact staged export exposed a parallel restart-test race: a concurrently forked child could
  briefly retain the journal directory's open-file-description lock until exec. The journal inner now
  explicitly unlocks at final drop before closing; the restart test passed 100 focused repetitions and
  the next exact full gate.
- After the independent review correction, a refreshed `git checkout-index` export passed bare
  `bin/ci`: formatting, Clippy with warnings denied, 190 active library tests with two credentialed
  live-provider tests ignored, every binary and integration suite, 3 launcher-socket contracts,
  3 worker-socket contracts, 14 scheduler contracts, schema checks, 8 browser contracts and the
  optimized release build in 3 minutes 0 seconds.
- Five focused launcher tests cover fixed authorization/sandbox derivation, renewal without duplicate
  spawn, terminal evidence and idempotent cleanup, restart ambiguity, waiter exhaustion before runtime
  effect, and a post-spawn journal failure that stops the exact unit and reaps the process.
- `git diff --cached --check` passed. Final exact staged product/config/test diff SHA-256:
  `93bcaad8b25b666587a75a539f056c15d3271c80328af78538a0f6ec6a153d0f`.

### Independent consultations and finding dispositions

The first complete exact-staged review inspected all 19 paths and returned otherwise safe with one
concrete P2:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 244 seconds;
- state fingerprint: `794ff70eb2c84cd3656cf2cf30aa6f555bf62c120908caa5b1e696dc988d784f`;
- brief SHA-256: `1e89167a0b59fdbf37afb93098da4d28347f8b54ff376dc40b06fa2cb4560d0d`;
- response: `consult-slice4b-deepseek/response.md`.

Finding dispositions:

1. **Accepted P2 — a successful runtime spawn could lose process ownership after a journal write or
   waiter-thread failure.** Dropping `std::process::Child` neither stops the transient unit nor reaps it.
   The waiter is now created before any runtime effect, so waiter exhaustion records `SpawnRejected`
   with zero spawns. After spawn, journal failure hands the child to that waiter, records reconciliation
   debt where possible and stops the exact unit. If process handoff itself fails, containment eagerly
   attempts both exact-unit termination and direct-child abort/reap. Two injected regressions prove the
   pre-effect and post-effect branches.
2. **Accepted P3 — verify before sealed-store I/O.** Grant signature/lifetime/lease verification now
   precedes reopening the prepared entry, avoiding unnecessary sealed-CAS work for an invalid token.
3. **Reviewed P3 — stop rejection remains explicit debt.** If `systemctl stop` itself is rejected, the
   direct client is still aborted/reaped where unowned and the journal remains `needs_reconcile`; the
   bounded unit is retried through cleanup/startup rather than falsely reported as stopped.

A broad post-fix rereview produced no response before its 420-second dispatcher timeout and is recorded
truthfully rather than counted as review evidence:

- status: `SKIPPED`, exit 124, one attempt;
- state fingerprint: `f7cbc903259ac1977b007535c023696aff001e3fd4500f5590062a657c549619`;
- brief SHA-256: `91e738c0d2098973ea4c4f818e299ec68cb35c642611c1ac9100d9a654ffad25`;
- output directory: `consult-slice4b-deepseek-final/`.

The route remained healthy. A fresh focused review then checked every post-review process-ownership
change and the five launcher tests against the same final repository fingerprint:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 119 seconds;
- state fingerprint: `f7cbc903259ac1977b007535c023696aff001e3fd4500f5590062a657c549619`;
- brief SHA-256: `377ea1490b7ab1cad06311b49398f99c18959eebe213eec632fa59e25a42544e`;
- response: `consult-slice4b-deepseek-final-focused/response.md`;
- verdict: `SAFE`, with no open question or P0-P2 finding.

### Verdict

Slice 4b is production-worthy as an inactive local execution boundary and may be committed. It does
not yet materialize a source/dependency snapshot, run the generic worker loop, submit scheduler
receipts, install/start either unit, execute repository code, mutate the VPS, contact GitHub/providers,
push or deploy. The unprivileged generic worker that consumes the exact source and preparation
contracts, renews leases, drives this launcher and commits receipts is the next local Slice 4c.

## Slice 4c: repository-agnostic worker and offline source-tree preparation

### Reviewed scope

Slice 4c completes the inactive source-only worker path without claiming that external dependency
preparation or the live host boundary already exists:

- one non-root `rdashboard-worker` serves every installed project through the existing typed,
  peer-authenticated gateway with 1-16 bounded shared slots, same-lease deduplication, short renewal,
  panic containment, graceful drain and cleanup-debt-first startup/recovery;
- `source_tree_v1` validates and extracts the exact attested Git-style archive once, rejects traversal,
  links, special files, collisions and byte/inode overflow, preserves executable bits, and publishes
  immutable `SourceSnapshot`, no-external-dependency `DependencySnapshot` and `PreparedRun` objects
  through the sealed store's single-flight path;
- the scheduler and manifest bind the typed host-preparation policy into HostPrepare leases, require its
  network class to be `offline`, and leave the catalog `ralert` project inactive. The adapter supports
  only dependency-free or fully vendored source; Cargo, Ruby, npm and system dependency prefetch remain
  explicit future adapters rather than a silent empty-cache fallback;
- verification pins the exact prepared run, receives a renewed signed grant, asks the fixed root
  launcher to run bare `bin/ci`, observes its journaled state, cleans the transient unit and releases the
  CAS pin before committing the terminal receipt. Every launcher ambiguity, renewal/observation failure,
  shutdown and restart obligation routes through idempotent cleanup;
- the worker service is networkless, capability-free and has no runtime socket, credentials, controller
  state or production volume. It has fixed memory, CPU, task and stop bounds. The transient job hides
  host `/run`, uses only sealed read-only `/workspace` plus a byte/inode-bounded executable `/job` tmpfs,
  and forces Cargo state and network-offline behavior below `/job`;
- startup and installation documentation require an exact dedicated preparation mount, 6 GiB store/
  100,000-inode limits and 12 GiB root-filesystem reserve, but do not create, enable or start a service.

The exact staged product/config/test diff contains 21 paths, 3,480 insertions and 19 deletions. Shared
dirty `src/lib.rs` and `deploy/systemd/README.md` hunks were staged selectively. Notification code,
notification workflow artifacts and earlier consultation stderr logs remain outside the reviewed diff.

### Verification

- A fresh exact `git checkout-index` export of the staged product/config/test state ran bare `bin/ci`
  successfully. It covered formatting, Clippy with warnings denied, 204 active library tests with two
  credentialed live-provider tests ignored, every binary/integration/socket/scheduler/worker suite,
  both schema checks, 8 browser contracts and the optimized release build.
- The exact gate exposed two real integration defects before the final pass: Git archives represent
  directories with one trailing slash, and compiled Rust test binaries cannot execute from a `noexec`
  `/job` tmpfs. Archive validation now permits only that exact directory spelling; `/job` remains
  private, byte/inode bounded, `nodev` and `nosuid` but executable for the fixed gate adapter.
- The final optimized release build completed in 3 minutes 15 seconds.
- `git diff --cached --check` passed. The exact product/config/test diff SHA-256, excluding workflow
  review artifacts, is `e79d6974873df78894ebb200c3cf7887ecbb75e11ecced9fe23c3f4101b6fdc5`.
- Focused contracts cover unsafe and real Git-style archives, single-flight publication, replay,
  lease renewal, unsupported adapters, non-retryable gateway failure, launch/observe/cleanup/unpin,
  shutdown draining, receipt-renewal outage ordering, restart cleanup obligations, adapter-policy
  rotation cleanup, worker configuration and the installed systemd boundary.

### Independent consultation and finding dispositions

A fresh complete exact-staged review inspected all 21 product/config/test paths and returned `SAFE`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 408 seconds;
- state fingerprint: `9441838fdc05779553f7b2832096f8c0cd1697c8b5b471fd075f6766e83273f6`;
- brief SHA-256: `ac28887fa58281df1e0df7b6a5775f8e7ce6323404cacddf79fafc9ddfbc334f`;
- response: `consult-slice4c-deepseek/response.md`;
- verdict: no open question or P0-P2 finding.

The three P3 notes were dispositioned as follows:

1. **Reviewed — pin expiry cannot trail a valid scheduler lease.** The pin ends at the node's absolute
   installed timeout (`leased_at_ms + timeout_ms`); scheduler renewal is bounded by that same deadline
   and cannot extend work beyond it. Missing-pin cleanup is also idempotent.
2. **Reviewed — renewal intentionally reuses the launch operation.** A renewed lease must deliver its
   new signed grant to the root launcher. The fixed launch journal treats the same execution identity as
   an authorization renewal and does not respawn; focused tests prove that contract.
3. **Reviewed — blocking host preparation drains safely.** It has no launcher/runtime effect and cannot
   be cancelled safely mid-filesystem publication. Graceful worker shutdown drains the assignment;
   process crash leaves only bounded staging that the sealed store reconciles at startup.

### Verdict

Slice 4c is production-worthy as an inactive local source-only worker path and may be committed. It
does not implement networked lockfile/dependency preparation, operation-owned COW layers, rootless
integration/OCI adapters or the live dedicated-filesystem/quota/concurrency proof. It does not install
or start a service, run repository code, mutate the VPS, contact GitHub/providers, push or deploy.
Those remaining step-4 boundaries and the first authorized `rimg` shadow candidate stay pending.

## Slice 4d: sealed input composition and private writable workspace

### Reviewed scope

Slice 4d closes the input-composition boundary needed before a real dependency adapter can populate
shared state:

- every new `PreparedRun` contains a canonical digest-protected composition binding its own typed key,
  exact `SourceSnapshot`, exact `DependencySnapshot`, installed workflow-policy digest and versioned
  generated-input digest;
- controller metadata and repository bytes occupy separate sealed paths. Only `source/` becomes the
  job workspace, while a repository-owned `.rdashboard-prepared-run.jcs` inside that source subtree is
  preserved as ordinary source without colliding with the controller document;
- the source-tree adapter's generated-input digest now includes the composition-layout purpose and
  schema. Existing Slice 4c source-only objects therefore have a different PreparedRun key and cannot
  replay as the new layout;
- a PreparedRun pin validates the composite object and both referenced sealed snapshots under the CAS
  commit lock. Its backward-compatible canonical V1 record persists the two sorted transitive keys, so
  cold LRU cannot evict a live source or dependency and admission need not repeatedly hash them;
- the root launcher rejects a composition from another workflow policy, reopens the exact dependency
  snapshot and derives read-only `/prepared` and `/dependencies` mounts itself;
- the fixed job validates both sealed roots, creates only private directories below the byte/inode-
  bounded `/job` tmpfs, copies `/prepared/source` into `/job/workspace`, preserves only executable vs
  non-executable semantics, rejects links/special files/unsafe modes/identity changes, and enforces
  100,000-entry/2-GiB secondary ceilings before executing the fixed adapter script;
- the explicitly empty `source_tree_v1` dependency marker remains the only installed dependency
  adapter. No networked Cargo/Ruby/npm/system dependency population is claimed by this slice.

The exact staged product/config/test diff contains 5 paths, 884 insertions and 43 deletions. Only the
three workflow documentation hunks in shared dirty `deploy/systemd/README.md` were staged; its unrelated
notification section and all notification code/workflow artifacts remained outside the reviewed diff.

### Verification

- A `git checkout-index` export of the exact staged state passed bare `bin/ci`: formatting, Clippy with
  warnings denied, 207 active library tests with two credentialed live-provider tests ignored, every
  binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser contracts and the
  optimized release build.
- The first sandboxed exact run allowed normal compilation but denied four existing temporary Unix-
  socket binds with `EPERM`. Re-running the unchanged export with local socket creation allowed passed;
  this was an execution-sandbox restriction rather than a product failure.
- The final optimized release phase completed in 2 minutes 43 seconds.
- `git diff --cached --check` passed. Exact staged product/config/test diff SHA-256:
  `db0c76a6916a8febcd8dfffcd6fd043bacff4887984bab59127d43a00a428e7f`.
- Focused regressions cover canonical composition and key validation, incomplete-reference rejection
  before pin creation, transitive eviction protection, legacy non-composite pin serialization,
  metadata/source basename isolation, workflow-policy substitution, exact read-only mounts, private
  workspace copying, executable-bit preservation, and link/non-empty-destination rejection.

### Independent consultation and finding disposition

A fresh complete exact-staged review inspected all five paths and returned `SAFE`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 237 seconds;
- state fingerprint: `76e0e6aec497ee8e41ca4d1fa66c683d200d6027e1b476078a4204da3866f611`;
- brief SHA-256: `05caa962d36542170bcc49063795b0089d68afb88fba5ab4135b9a8b82ec6160`;
- response SHA-256 after Markdown trailing-space normalization:
  `901c54620b1be31eeb83a56d37762014bd1fa1989470d7c5b5901c5b4a24d862`;
- response: `consult-slice4d-deepseek/response.md`;
- verdict: no open question or P0-P2 finding.

The sole P3 note observed that `PinRecordV1::validate` rejects primary-key inclusion, duplicate or
unsorted protected keys, while `PinRecordV1::new` establishes those invariants for new records. That is
the intended fail-closed deserialization boundary, not an executable defect; no correction was needed.

### Verdict

Slice 4d is production-worthy as an inactive local composition/execution foundation and may be
committed. It does not yet populate a networked dependency snapshot, expose it through a fixed package-
manager adapter, provide filesystem-level COW layers, run a real repository shadow, install/start a
unit, mutate the VPS, contact GitHub/providers, push or deploy. The next local Slice 4e is the reviewed-
lockfile dependency-prefetch boundary, starting with the measured Cargo/native requirements needed by
`rimg` without making i9 availability authoritative.

## Slice 4e: fixed Cargo.lock dependency preparation

### Reviewed scope

Slice 4e completes the first strict external-dependency boundary without giving the generic worker or
repository code network authority:

- `cargo_crates_io_v1` parses a bounded version-4 Cargo.lock and accepts only local workspace packages
  plus checksum-pinned packages from the two canonical crates.io index identities. Git inputs,
  alternate registries, missing checksums, duplicate package identities, malformed names/versions and
  more than 4096 registry packages fail before fetch.
- The exact raw lock digest, canonical sorted package-plan digest, installed workflow policy, platform
  and versioned vendor layout bind both the shared DependencySnapshot key and canonical manifest.
- A separate non-root `rdashboard-dependency-fetcher` accepts only validated name/version/checksum
  tuples from the exact worker UID over a bounded Unix protocol. It derives the sole static.crates.io
  HTTPS path, disables redirects and proxies, filters DNS answers to public routes, enforces request and
  archive limits, and verifies the Cargo.lock checksum before returning bytes. Its systemd unit cannot
  read source, CAS, controller, launcher, credential or container-runtime state.
- The networkless worker verifies every digest again, rejects unsafe or ambiguous gzip/tar input and
  writes Cargo's exact directory-source checksum documents into one sealed, byte/inode-bounded vendor
  snapshot. Matching keys single-flight and warm replay does not call the fetcher.
- Source and dependency snapshots remain temporarily pinned until PreparedRun publication, preventing
  pressure eviction between atomic commits. Lease loss and shutdown cancel fetch, inventory,
  extraction and hashing; producer failure removes staging and cannot emit a success receipt.
- The fixed networkless job validates the canonical dependency manifest, uses a private Cargo home,
  fixed highest-precedence vendor replacement and offline mode, and sees shared inputs only through
  read-only mounts. Per-job source, target and tool state remains inside the bounded transient job.
- `source_tree_v1` remains compatible without a fetcher. Missing fetcher, unsupported preparation and
  all preparation failures terminate with explicit failure evidence and complete cleanup.

The final exact staged product/config/test diff contains 17 paths, 3653 insertions and 73 deletions.
Only the task-owned systemd README hunks and task-owned `src/lib.rs` module exports are staged; the
shared notification worktree and its workflow artifacts remain outside the reviewed diff.

### Verification and self-review corrections

- A first full gate exposed a real dispatch regression: a synchronously rejected host-preparation
  adapter returned from the assignment task before `fail_without_runtime`, so the controller waited
  without a failed receipt. The dispatch now routes that error into a deterministic failed receipt with
  complete cleanup; its regression completes in 0.01 seconds instead of expiring.
- The initial corrected product fingerprint
  `ef9fee21059f9611e724f3818613e502899632c2eb28267e245402051170f789` passed bare `bin/ci` and received
  an independent `SAFE`, but that review was explicitly invalidated after further self-review found two
  archive-boundary defects. Literal backslashes could alias slash-separated Cargo checksum keys, and a
  checksum-valid compressed archive could force excessive trailing tar decompression before the final
  payload inventory failed.
- The final materializer rejects literal backslashes before filesystem/checksum conversion and rejects
  duplicate checksum-map insertion. A checked `BoundedReader` limits the gzip-expanded tar stream to
  remaining payload plus per-inode tar/path overhead, declared bytes/inodes fail during inventory, each
  entry is explicitly drained through a bounded buffer, and cancellation is checked throughout both
  passes and hashing. Focused regressions cover path aliasing, a 2 MiB expanded tail against a 64 KiB/
  16-inode envelope, and cancellation before manifest publication.
- A `git checkout-index` export of the final exact staged state passed bare `bin/ci`: formatting,
  Clippy with warnings denied, 223 active library tests with two credentialed live-provider tests
  ignored, every binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser
  contracts and the optimized release build. The final release phase completed in 3 minutes 20 seconds.
- `git diff --cached --check` passed. The final exact 17-path product/config/test binary diff SHA-256 is
  `e1b9d99cc5fc1c6e1583b270c36cf530faae34b89fde67292d56f3ca51e8bb13`.
- A separate networkless compatibility probe materialized 276 real checksum-pinned `.crate` archives
  already present in the local Cargo cache through the final implementation. Five lock-plan archives
  absent from that local cache, primarily foreign-target packages, were reported as absent rather than
  fabricated. The 314 MiB temporary vendor trees and validator were removed after the check.
- Early isolated exact-gate attempts demonstrated 17.5 GiB of duplicate per-copy Cargo target output.
  Only those disposable targets were removed; the successful gates reused one shared local Cargo target.
  This confirms the next compiled-state/cache slice is necessary and avoided hiding the resource issue.

### Independent consultation and finding disposition

The first complete review is retained only as audit evidence and is not the acceptance review:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 233 seconds;
- state fingerprint: `ef9038d95742d0303bd731921e54e8a1ab3672a529a2b7153caf801106b1cd0b`;
- brief SHA-256: `70b3ae869e9ba3894ba7c60407914c4d4571bda70ab8b315c07d72223d78447c`;
- response SHA-256: `b0ca7daf23680ea78bdd052ad33b234e6fc1c8f734ca1622d5ce3c2b992b9152`;
- response: `consult-slice4e-deepseek/response.md`;
- disposition: its `SAFE` applied to the superseded `ef9fee...` product diff and was invalidated before
  closeout by the two self-review corrections above.

A fresh final review independently verified the new 17-path manifest and exact `e1b9d99c...` hash,
inspected the full critical implementation and returned `SAFE` with no finding or open question:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 213 seconds;
- state fingerprint: `ff8f326a198ba044f80f142c829a0e99cf2bfd9d3aa7e13afe576fa10473e22c`;
- brief SHA-256: `66c3a4765bceb626b1a2d7d255a05e52830806edcbc81182627dde6ac9c664b0`;
- response SHA-256: `e2c8b3c5726bab7f6353952dab8be15250826d379f22194c9bb053bee8e724bd`;
- response: `consult-slice4e-deepseek-final/response.md`;
- verdict: no P0-P3 finding and no open question. The reviewer explicitly rechecked integer bounds,
  tar overhead, exact-limit EOF, cancellation into `spawn_blocking`, path/checksum alias prevention,
  DNS/peer boundaries, staging cleanup, offline Cargo behavior and systemd confinement.

### Verdict

Slice 4e is production-worthy as an inactive local Cargo dependency-preparation boundary and may be
committed. It does not activate a project manifest, install or start either unit, fetch a live crate,
run repository code, mutate the VPS, contact GitHub/providers, push or deploy. Whole-lock vendor source
deduplication across different lock plans, operation-owned COW/compiled state, dedicated-filesystem/
quota/concurrency proof and the first separately authorized `rimg` shadow remain pending.

## Slice 4f: bounded operation-owned compiled state

### Reviewed scope

Slice 4f closes the local writable compiled-state boundary without turning a per-worker or global cache
into correctness authority:

- `WorkflowOperationStateV1` is optional for legacy lease decoding but required for new compiled
  verification/release launches. Its canonical state key binds the attempt, project, source SHA,
  installed workflow policy, exact PreparedRun, worker/host, sorted consumer set and byte/inode limits.
- Control schema V4 persists one operation-state binding per attempt. Matching compiled VPS consumers
  are serialized and reuse that binding across lease generations/restarts. A persisted VPS binding can
  never migrate to an optional accelerator after expiry; an available i9 receives independent one-node
  state and transfers nothing back to the authoritative VPS path.
- `WorkflowOperationStateStoreV1` is a root-owned singleton over the exact
  `/var/lib/rdashboard-build/operations` mount. It rejects a non-dedicated mount or capacity outside
  6-8 GiB and 100,000-1,000,000 inodes, enforces a per-state maximum of 6 GiB/500,000 inodes, preserves
  at least a fixed admission margin and caps retained metadata at 1,024 records/newest 512 terminals.
- Canonical state records and a root lock make acquire/release replay exact. State creation is staged
  and fsynced before rename. Removal first persists `data_removal_pending`; startup completes either
  side of an interrupted unlink. Terminal record pruning renames/fsyncs a `.deleting-*` tombstone before
  removal. Failure, unknown cleanup, over-limit output and one-hour inactive partial state all remove
  data rather than allowing a later consumer to trust it.
- Usage accounting includes every entry and `max(logical length, st_blocks*512)`. The final scanner is
  fd-relative: root and child directories are opened with no-follow semantics, every entry is pinned by
  `O_PATH|O_NOFOLLOW`, directory traversal opens `.` from that pinned inode and verifies identity.
  Rename/symlink substitution cannot redirect the launcher outside state. Traversal is immediate depth-
  first with a 64-level ceiling, so wide siblings never accumulate descriptors and peak traversal stays
  about 129 descriptors below installed `LimitNOFILE=256`.
- The root launcher acquires state only after durable launch acceptance, binds only the exact data path
  at `/operation`, and stops/contains the transient unit before state release. Same-execution lease
  renewal updates the journal/grant without acquiring or spawning twice. Any launcher ambiguity becomes
  cleanup debt; legacy no-state records remain stoppable during rolling upgrade.
- `/job` continues to own only per-node workspace, Cargo configuration and temporary files. Target and
  ccache alone live in `/operation`. Copying sealed source now preserves file and directory mtimes at
  stable `/job/workspace`, which permits Cargo reuse between serialized consumers without sharing state
  across attempts, sources or hosts.
- Worker receipt reduction requires both process success and reusable operation cleanup. A process that
  exits successfully after a limit/removal/uncertain state disposition commits deterministic
  `operation_state_unusable` failure evidence instead of authorizing downstream release.
- The launcher unit gains only the fixed operation mount as writable state plus the DAC/chown
  capabilities required to create and remove build-owned data. Jobs retain an empty capability set,
  cannot see the parent operation root and receive no network, credential, Docker/containerd,
  controller/executor/source socket or production-volume authority.

The final exact product/config/test diff contains 19 paths, 3,291 insertions and 55 deletions. Shared
dirty `src/lib.rs`, `deploy/systemd/README.md` and `tests/store_and_web.rs` hunks were staged selectively.
All notification code, notification workflow artifacts and earlier consultation stderr logs remain
outside the reviewed product diff.

### Verification and hardening corrections

- Focused verification passed strict Clippy and all ten operation-state tests. Those tests cover
  sequential reuse, concurrent-owner rejection, failure/reset/limit removal, stale partial-state
  cleanup, deletion and tombstone crash windows, hard filesystem bounds, rename-plus-external-symlink
  substitution and deterministic rejection of a 65-level adversarial tree.
- Launcher tests prove renewed replay acquires/spawns/releases exactly once and cleanup is idempotent.
  Worker tests prove a successful process plus unusable state becomes a failed receipt. Scheduler tests
  prove same-key VPS serialization, schema V4 migration, expiry retry on the bound host and no migration
  to i9. Fixed-job tests prove source timestamps survive the private workspace copy.
- The first complete review of product hash
  `0445f7fa0d718eb7b2bdb076a72347cfc0bad56b02b54aea6a3e1dee76310b53` identified a theoretical
  path-based usage-walk TOCTOU. Although normal cleanup runs after the only writer stops, the root-side
  walker was hardened instead of relying on that timing assumption. Its path stack was replaced with
  the fd-relative no-follow traversal above and a deterministic path-replacement regression.
- Hash `7211b2140585ff30ef8034bab2958d3430a3849861988dbf5fd1d0d8a662ace3` passed bare `bin/ci` and a
  fresh review returned SAFE. Subsequent self-review invalidated it before closeout: the fd-safe walker
  retained one pending directory descriptor per wide sibling, which could conflict with the installed
  launcher fd limit. The final depth-first traversal processes siblings immediately and caps recursive
  depth so both width and depth are bounded.
- A fresh `git checkout-index` export of final product hash
  `9d424f47108c30e47ed4765c7a2d9736b83d65d4d6092ffa4e9847a267b3ad43` passed bare `bin/ci`:
  formatting, Clippy with warnings denied, 234 active library tests with two credentialed live-provider
  tests ignored, every binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser
  contracts and the optimized release build. The release profile completed in 3 minutes 28 seconds.
- `git diff --cached --check` passed. No live filesystem/mount quota was created or probed, no unit/job
  was installed or started, no repository job executed through the new launcher, and no VPS, i9,
  provider, GitHub, push or deployment state changed.

### Independent consultation and finding dispositions

The consultation chain is retained because each material correction changed the exact frozen review
boundary:

1. Initial review (`consult-slice4f-deepseek`) inspected hash `0445f7fa...`: route/model
   `deepseek-free` / `opencode/deepseek-v4-flash-free`; `ANSWERED`, one attempt, CLI `1.18.3`, 203
   seconds; state fingerprint `0d1221e4be794b658b751f4bc740dcaf57d71eb20aa5aa32c27da369b9b10791`;
   brief SHA-256 `9a9d1640544d0f7c9e55ef69a53e58d91d1780a50c498a542262e1964a97a201`;
   response SHA-256 `3eb4232a7b8ebbf23aef7f8f029e7db27cc118965bffba0a57102910cf446827`.
   Its path-walk observation was fixed; its acquire-before-spawn observation was traced and retained as
   fail-safe ordering because early release would permit reuse while a process stop remained uncertain.
2. First post-fix review (`consult-slice4f-deepseek-final`) inspected hash `7211b214...` and returned
   SAFE with no P0-P2: `ANSWERED`, two attempts, 398 seconds; state fingerprint
   `82453e46f1832bd17fc2e6e0303629b7254bf3b3634e220de392549cc9d712c7`; brief SHA-256
   `85d7b3810f4b2266d2d57b8b0351848df044665b1adc2de3026cf6f394757455`; response SHA-256
   `b73154d2b130d3004328e867f1126382fec2c93fa77fcb0a5961d656a294ce48`. It was invalidated only by
   the later pending-fd self-review correction.
3. The first current-hash response (`consult-slice4f-deepseek-final2`) independently verified
   `9d424f47...` and reached SAFE with no P0-P2, but dispatcher status was `PARTIAL` because the model
   included a progress/next-move block before its final verdict. It is supporting audit evidence, not
   acceptance: one attempt, 249 seconds; state fingerprint
   `f8212a004f29fa93c93c3b0b110eb448cf5542e2e9fbe87d16bc0571f94569fb`; brief SHA-256
   `137019f1d25f025b16a752cba50fe2024a09b4f2e9216c093a9771f6e67ac119`; response SHA-256
   `35e7afdfbfbc7dd5e9c1a781ea7124027ebdd5b4e2aa3e7ed890f846593846be`.
4. The final acceptance review (`consult-slice4f-deepseek-final3`) re-evaluated the unchanged exact
   `9d424f47...` product hash and returned `ANSWERED`, `VERDICT: SAFE`, `OPEN QUESTIONS: NONE`, with no
   P0-P2 finding: one attempt, 76 seconds; state fingerprint
   `f8212a004f29fa93c93c3b0b110eb448cf5542e2e9fbe87d16bc0571f94569fb`; brief SHA-256
   `90ac1fd92696446426ba61c66f7d08c639de7caf01c6c23e18537a20e92cc870`; response SHA-256
   `dfa0fdcae1db4037adcbc20d81ffba307d1b537114280aef62ccc0b14ee072e7`.

The remaining P3 observations need no product correction:

- terminal replay may report zero historical usage when the exact older release record is no longer the
  record's `last_release`; normal launcher cleanup has already journaled the accurate original release,
  and the value cannot change disposition, cleanup or authorization;
- `CAP_DAC_OVERRIDE` is deliberately broad at the Linux capability level, but the trusted fixed launcher
  has no caller-selected path and its systemd mount namespace makes only the launcher journal and exact
  operation root writable;
- Rust 1.96 `remove_dir_all` does not follow internal symlinks, while state creation also denies mount/
  namespace capability to repository code.

### Verdict

Slice 4f is production-worthy as an inactive local operation-owned compiled-state boundary and may be
committed. It does not create the dedicated filesystem, install/start the launcher, activate a project,
run a shadow job, assemble an OCI candidate, mutate the VPS/i9, contact GitHub/providers, push or deploy.
Rootless integration/OCI adapters, the authorized live systemd/filesystem/quota/concurrency proof and
the first `rimg` shadow candidate remain pending.

## Slice 4g: rootless OCI activation boundary

### Reviewed scope

Slice 4g closes the inactive host-readiness boundary required before a fixed OCI adapter may be
implemented or enabled:

- `RootlessOciRuntimePolicyV1` binds a distinct non-root daemon identity and exact SHA-256 values for
  fixed root-owned `buildkitd`, `buildctl`, `rootlesskit`, `runc` and `buildkitd.toml` inputs;
- launcher policy requires the OCI adapter and rootless contract to be present together. Existing
  canonical policies remain byte-compatible when the optional contract is absent, and native CI/
  release adapters do not depend on BuildKit availability;
- launcher startup verifies trusted file parents, stable single-link regular files, exact modes and
  digests; root-owned setuid mapping helpers; host-wide safe/non-overlapping subordinate-ID ranges;
  required kernel/AppArmor user-namespace switches; exact state/runtime ownership; a dedicated bounded
  filesystem; the 12 GiB root reserve; and a live mode-`0660` Unix socket;
- every failure produces a stable reason code, concise summary and specific remediation suitable for
  operator and LLM diagnosis;
- the inactive service isolates the daemon in a private network namespace with AF_UNIX/AF_NETLINK only,
  no credentials, application/source/workflow/executor state or Docker/containerd/Podman socket, and
  explicit CPU/memory/task/swap limits;
- the strict BuildKit configuration permits no insecure entitlement, enables only the rootless OCI
  worker with process sandboxing, uses fixed `runc`, one concurrent vertex and bounded history/GC;
- a dedicated 1.5-2.5 GiB, 50,000-500,000-inode filesystem is the hard BuildKit-state fence. The
  configured 1.5 GB GC ceiling is supplemental and the root filesystem must retain at least 12 GiB
  available to ordinary recovery processes.

The final exact staged product/config/test diff contains nine paths, 1,540 insertions and four
deletions. The only staged `src/lib.rs` change is the two-line rootless module export; unrelated
notification/dashboard work remains outside the index and review.

### Verification and finding disposition

- Focused verification passed six rootless unit tests, the launcher-policy coupling regression, three
  systemd worker contracts, formatting and Clippy across all targets/features with warnings denied.
- Bare `bin/ci` passed after the review correction: 259 library tests with two credentialed
  live-provider tests ignored by design, every binary and integration suite, schema checks, nine
  browser contracts and the optimized release build. Release compilation took 4 minutes 58 seconds.
- `git diff --cached --check` passed. The final exact staged binary diff SHA-256 is
  `32ba824c16f4ff383aa47c1cec9e49265b1812b05afe7384f609752725ace6ca`.
- `systemd-analyze verify` parsed the new unit and reported only the expected missing fixed
  `/usr/libexec/rdashboard/rootlesskit` executable. No vendor bundle was installed merely to make the
  development-host probe green.
- The first exact review correctly identified that a low subordinate range belonging to an unrelated
  account failed with the same `InsufficientSubordinateIds` category as a short BuildKit range. Its
  suggestion to ignore unrelated low ranges was rejected because setuid mapping helpers must not expose
  reserved host identities. The real diagnostic defect was fixed with a separate
  `rootless_oci_subid_layout_unsafe` category/remediation; the host-wide floor/non-overlap rule is now
  explicit in documentation and regression tests.
- The review's useful P3 test observations were implemented for optional kernel switches, invalid
  daemon identity, all supported mountinfo escapes and truncated/unknown escapes. Exact `0644` mode
  remains a deliberate fixed-installation contract, the rootless TOCTOU helper remains locally stricter
  than unrelated launcher reads, and `available_space` deliberately preserves recovery capacity usable
  without root-reserved filesystem blocks.

### Independent consultation

Initial review of superseded hash `0998ac4e...`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 207 seconds;
- state fingerprint: `9954fc89580175af7727184801fed72ce8aa86ff719f4e010655c083cd76a02c`;
- brief SHA-256: `4531753c5487f9309278799784fe1f0527c9317b3e1f3a91f76afe3a5a5dfe4b`;
- response SHA-256: `124e8180ad84767e3fc504be8f7c11313c000e9fab35ff36ab9cba8aefe41c7f`;
- verdict: `NEEDS_FIX`, with the subordinate-ID diagnostic P2 described above.

Final acceptance review of exact hash `32ba824c...`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 143 seconds;
- state fingerprint: `5718cb450804bdc5b6a5fac62c06622993f577f2c153b813725947be08fe201e`;
- brief SHA-256: `432d4555a168c35241e063086c85487f5188f0fbeb341566976ef1bd20d70225`;
- response SHA-256: `e20a01b8e40530efb171cb1b3bf0706791dcae08b3492418c1cae00cec986d69`;
- verdict: `SAFE`, no P0-P2 finding and `OPEN QUESTIONS: NONE` after rechecking the global
  subordinate-ID threat, policy XOR coupling, TOCTOU/file integrity, systemd/BuildKit confinement,
  resource bounds and error/remediation completeness.

### Verdict

Slice 4g is production-worthy as an inactive local activation boundary and may be committed. It does
not install or start BuildKit, activate an OCI adapter/project, run an OCI build, prefetch/import base
images, publish an OCI archive, mutate the VPS/i9, contact GitHub/providers, push or deploy. The next
local dependency is the fixed OCI build/archive-result handoff; live systemd/filesystem/quota/
concurrency proof and the first `rimg` shadow candidate remain separately authorized later gates.

## Slice 4h local OCI build and typed result handoff review

### Scope and outcome

This slice implements the previously missing fixed rootless OCI invocation and pre-release result
handoff without activating BuildKit or any project:

- `ReleaseBuild` now outputs a distinct `ReleaseBuildResult`; it no longer claims to produce the final
  `ReleaseBundle` before CI, reduction, resource reservation and deployment-policy evidence exist;
- a canonical per-project root policy and signed-lease-derived request bind the exact Dockerfile,
  target, `linux/amd64` platform, sorted build arguments, sealed OCI-layout base inputs and archive
  ceiling;
- the transient systemd unit invokes the installed OCI client directly with a reconstructed
  environment, sealed read-only inputs, one peer-restricted BuildKit socket and one lease-owned output
  directory. It never invokes a repository release script or exposes operation state;
- the installed client constructs fixed `buildctl` arguments, rejects external Dockerfile frontends,
  exports a local OCI archive, verifies BuildKit metadata plus the complete reachable OCI graph and
  writes canonical request/result evidence;
- root independently repeats archive, graph, ownership and lease-binding validation before atomic
  promotion. The worker commits the typed result digest, never bare process-exit evidence;
- one pre-release result per project is retained on a separate hard-bounded result filesystem. Failed,
  aborted, ambiguous and restarted work has explicit bounded cleanup, while root-side failures log
  stable reason codes and concise summaries.

The reserved domain-level native release adapter remains available for a future design, but the fixed
launcher no longer admits it or maps it to an optional `bin/build-release` script without a typed
result implementation.

### Resource and concurrency evidence

- The result store requires an exact root-owned mode-`0700` 4-6 GiB filesystem with 10,000-100,000
  inodes and refuses activation below the 12 GiB root recovery reserve. A project policy can admit at
  most a 3 GiB archive and every spawn reserves the archive ceiling plus fixed headroom before the
  build starts.
- BuildKit state, verification operation state and OCI results have separate identities and hard
  capacity boundaries. None of these maxima is eagerly allocated by this local implementation.
- OCI leases neither allocate nor mount operation state. Scheduler coverage proves that independent OCI
  assembly can run beside verification on the VPS while only verification owns the reusable compiled
  state. Optional i9 verification remains independent and cannot own release output or block the VPS.
- The root runtime tracks each live OCI `unit -> request` relationship. Promotion or successful discard
  clears it; an uncertain process wait leaves it for cleanup after `systemctl stop`; launcher startup
  reconciles any bounded staging/request/deletion debris left across process restart.

### Self-review findings and dispositions

- Discovery found that the old `rdashboard-workflow-job` path referenced a nonexistent
  `bin/build-oci-release` and reduced successful builds to the process evidence digest. Both
  placeholders were removed rather than hidden behind a fallback.
- Discovery also found that `ReleaseBundleV1::seal` requires evidence unavailable at the parallel
  release-build node. The graph and schema now use `release_build_result`, preserving `ReleaseBundle`
  for the later sealing boundary.
- The first implementation still allocated the shared 6-8 GiB operation-state contract to OCI even
  though the OCI sandbox could not consume it. Scheduler, launcher and documentation now restrict that
  state to actual compiled-cache adapters, which removes false serialization and unnecessary capacity
  admission from OCI.
- A failure-path audit found that an I/O error while waiting for `systemd-run` could leave staging until
  launcher restart. The unit/request lifecycle registry now lets explicit cleanup retry after stopping
  the uncertain unit; prepare/promote/discard failures are observable with stable log categories.
- The offline daemon could otherwise waste time resolving a Dockerfile `# syntax=` frontend. The fixed
  client now validates a stable sealed Dockerfile and rejects that directive before invoking BuildKit.
- Malformed JSON inside an OCI tar initially escaped as a generic JSON category. Archive parsing now
  maps all embedded layout/index/manifest failures to the stable archive-invalid reason code.
- The first post-guard acceptance review found that a root-owned mode-`0400` request bind could not be
  opened by the unrelated unprivileged build UID. The canonical non-secret request is now exact mode
  `0444` inside the untraversable root-owned mode-`0700` result store and remains exposed only through an
  individual read-only bind. All mutable/result output remains private mode `0400`; a filesystem
  regression asserts both the sandbox-readable request bit and stable canonical bytes.

### Verification

- Focused verification passed all eight `rootless_oci_build` tests, all nine `workflow_launcher` tests,
  all sixteen `workflow_scheduler_contracts` tests, formatting and strict Clippy across every target and
  feature.
- After the final request-permission correction, bare `bin/ci` passed again: 269 active library tests in the shared
  worktree with two credentialed live-provider tests ignored by design, every binary/integration/
  socket/scheduler/worker suite, both project-manifest schema checks, nine browser contracts and the
  optimized release build. The final release phase took 3 minutes 50 seconds.
- No live BuildKit binary, service, socket, filesystem or project policy exists as proof from this
  development run. No OCI build or import was attempted. Live systemd/filesystem/quota/concurrency
  proof remains a separately authorized activation gate and is not inferred from local tests.

### Independent consultation

The initial exact-staged-diff review inspected superseded full staged hash `adf65a56...`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 217 seconds;
- state fingerprint: `76c6e5e68ff3b545c627752456b034d8c78cefbdf8d952d938f22bdf9735200a`;
- brief SHA-256: `fe8bf61f78373a7ef26d566bb1d12640f1bd1f95f2ba2853db0fa0dff6507c25`;
- retained response SHA-256 after whitespace-only repository normalization:
  `67fdad044080789e0a3a78c4fb5e6d151d376e81b6528b5e31aa5a3bab7ca2b5`;
- verdict: `SAFE`, no P0-P2 finding and `OPEN QUESTIONS: NONE`.

Its three P3 observations were resolved explicitly:

- concurrent wait/terminate cleanup deliberately fails closed under the lifecycle/store locks; the
  losing path cannot publish unverified output, cleanup is idempotent and startup reconciliation removes
  bounded debris;
- the installed build client deliberately uses the transient unit's lease-bound `RuntimeMaxSec`,
  `TimeoutStopSec` and process-group cleanup as its outer liveness boundary rather than a second client
  timer;
- the missing `#[cfg(unix)]` on `rootless_oci_build` was a real cross-platform consistency defect and is
  fixed. The complete bare gate above passed after that correction.

The first post-guard acceptance review inspected superseded product/config/test hash `220f049f...`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 372 seconds;
- state fingerprint: `d81b54241c392b04d3df0009f7f19ce4daa5ffc93e30b8813bf2aad75479cde6`;
- brief SHA-256: `cb2c241e251c759d2f23743b502569c0e9295cd8a6286a2fe414ad68174d81f2`;
- response SHA-256: `c9585cf5031b8fc5b7723819adf5b524e242f3e9b292ddd21941747e124aafd2`;
- verdict: `UNSAFE`, one P0 and no other P0-P2 finding, with `OPEN QUESTIONS: NONE`.

That P0 correctly proved every live build would fail before BuildKit because the build UID could not
open the root-owned mode-`0400` request. Product hash `9203b951...` applies the exact mode-`0444`
read-only-bind correction described above and passed the complete post-fix gate.

Final acceptance review of exact product/config/test hash
`9203b951038298566b92ce6063cf72f8207836ac7ccae6f56461a19fdbe2f79e`:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 218 seconds;
- state fingerprint: `049d6763443bf51486487b39bdd613a9850451f62e12f8a7737def43335faabb`;
- brief SHA-256: `0be0b2d3c432892b4ee6f9f0581958b7c65dec738f5d77819349cdb29e24a9a4`;
- response SHA-256: `09cba5b9270ee074ab747e19f96adc856c9027852920b7a1d7f51577585504cf`;
- verdict: `SAFE`, no P0-P2 finding and `OPEN QUESTIONS: NONE`.

The final P3 observations need no product correction:

- the domain-level native release variant remains intentionally decodable for rolling journal/cleanup
  compatibility while policy, argv mapping and execution fail closed; removing it requires a dedicated
  persisted-schema transition rather than deletion inside this slice;
- the trusted-tree hardening re-scan occurs only after the transient build process has exited and while
  the root store remains exclusively locked; a privileged root actor could already bypass the boundary;
- unexpected device/socket/FIFO staging entries deliberately block cleanup with `InvalidStore` rather
  than authorizing deletion of an unknown inode type. They cannot promote and require explicit operator
  inspection, which is the safer recovery contract.

### Verdict

Slice 4h is production-worthy as an inactive local OCI build/result boundary and may be committed. It
does not install or start BuildKit, create the dedicated result filesystem, prepare base layouts, enable
a project policy, run an OCI build, mutate VPS/i9/provider state, push or deploy. Project-specific sealed
base preparation, final release-bundle sealing and the authorized live shadow proof remain pending.

## Slice 12a inactive A/B self-update bootstrap foundation review

### Scope and outcome

This slice implements the local trust, staging and recovery foundation for a future `rdashboard`
self-deploy without enabling it:

- a canonical Ed25519-signed self-release descriptor binds the exact accepted source sequence/head,
  source attestation, workflow policy, verification receipt, runtime contract, state schema, complete
  path/mode/size/hash allowlist and deterministic tar archive;
- root verifies the installed owner-private policy, stages only the exact immutable release tree and
  uses relative content-addressed `current` and `last-known-good` pointers;
- a bounded root-owned journal outside `control.sqlite` records backup, switch, start, health, commit,
  rollback and reconciliation phases and observes the actual pointer before replaying an effect;
- online SQLite backups are integrity-checked, hashed and operation-bound. Rollback stops services,
  restores every verified database, switches the pointer only after all restores complete, starts the
  prior dependency chain and proves prior health;
- the persistent root bootstrap has fixed paths, identities, service order, health target and systemd
  confinement. It cannot run repository-selected commands or consume an unsigned handoff.

The unit and tmpfiles contract are intentionally inactive. Generic-worker self-release production,
atomic producer publication, versioned executable-path migration, the root recovery CLI, retention,
host failure/reboot drills and explicit production activation remain later gates.

### Findings and dispositions

- The first exact review found no P0/P1 and one accepted P2: an error after creating a rollback SQLite
  temporary could leak the file. Restore now verifies while root-owned, delays `chown` until immediately
  before rename and removes the path on error only if it still names the exact opened inode.
- Self-review found a broader crash window the first review's post-fix explanation missed. Restore temp
  names are now deterministic per journal operation and database; replay rejects substituted links or
  foreign ownership, reconciles only plausible interrupted files and recreates with `create_new`.
- A later review identified an orphan `.link-*` P3 if the supervisor died immediately before pointer
  rename. Startup now validates and removes only root-owned `.link-<UUID>` symlinks to an exact
  `releases/<digest>` target and fsyncs the root; rename errors also clean their own temporary.
- Full parallel verification exposed delayed advisory-lock release from short-lived staging stores in
  the sandbox. `SelfReleaseStoreV1` is now deliberately non-clonable, owns one lock file descriptor and
  mutex directly and explicitly unlocks in `Drop`. The exact same-root second-open rejection remains a
  regression contract. Filesystem fixtures serialize only their isolated advisory locks.
- The review observation that the newest source sequence may skip intermediate commits is not a defect:
  releases must support the actual installed state schema rather than require deployment of every git
  commit. The producer slice still must bind and prove that compatibility before publication.

### Verification

- Final bare `bin/ci`: passed, exit code 0.
- It covered formatting, strict Clippy, 285 library tests with two credentialed live-provider tests
  ignored by design, every binary/integration/socket/scheduler/worker suite, both schema checks, nine
  browser contracts and the optimized release build. The release phase took 4 minutes 33 seconds.
- Focused self-update coverage passed 16 contracts for signatures/policy/archive substitution,
  immutable staging, singleton locking, bounded journal history, success, unhealthy rollback, crash
  replay, unknown pointer, exact backup/restore, interrupted backup/temp reconciliation and relative
  pointer cleanup.
- Final exact staged product/config/test diff SHA-256:
  `51ca1b73147e563b5dffa7948c90c589c8ff114d06ba6298dc945490f0a66d74`.
- No service was installed, enabled, started or restarted. No VPS, i9, provider, GitHub, push or deploy
  state was mutated.

### Independent consultation

The final acceptance review checked the exact staged hash above after the earlier finding/fix rounds:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 95 seconds;
- state fingerprint: `ac725f5e124b2af8ba60effd7708bc271dedd233d6b0d25f4081380f2ed98c99`;
- brief SHA-256: `54597a8a09239e51f84cc382d7ce454dd16471b56d4f4af848abe6a19a623bf0`;
- response SHA-256: `4f0be518ef85cb84605d7c752243873d38f106960a3cb29742d721cf303558e2`;
- verdict: `SAFE`, no P0-P2 finding and no open question. It explicitly rechecked release-link
  reconciliation, rename cleanup, non-clonable direct lock ownership, explicit unlock and singleton
  rejection.

### Verdict

Slice 12a is production-worthy as an inactive local bootstrap foundation and may be committed. It does
not make a pushed `rdashboard` commit self-deploy yet. The next local slice must let the ordinary generic
worker build, sign and atomically publish the exact self-release only after successful required
verification; executable-path migration and root recovery tooling remain subsequent activation gates.

## Slice 12b verified generic-worker self-release producer review

### Scope and outcome

This slice closes the local producer and launcher boundary that slice 12a deliberately left open:

- native release packaging is serial after the exact bare `bin/ci` verification receipt and shares the
  same VPS-owned operation state, so it reuses existing `target/release` outputs instead of compiling a
  second time;
- optional i9 capacity cannot claim verification for a native release whose output must remain on the
  required VPS. OCI projects retain parallel verification/build and optional-host verification;
- the installed unprivileged client packages only the policy-listed ready binaries into a deterministic
  tar and emits a typed unsigned result. It receives no signing key and cannot publish the final handoff;
- the root launcher independently revalidates the request, archive, manifest, ownership, modes and
  digests, signs with the separately delivered systemd credential and publishes exactly
  `<source-sha>/{release.jcs,release.tar}` by one atomic directory rename;
- startup, process failure, promotion failure, abort and explicit cleanup reconcile bounded partial
  request/staging state. The bootstrap ignores only structurally valid hidden staging directories and
  rejects flat, partial, linked, mutable or conflicting publications;
- V2 project manifests distinguish native from OCI builds and require the build kind to match the exact
  release adapter. Existing OCI JSON remains backward-compatible through the default build kind;
- the signing credential is provided only by the optional self-release systemd drop-in, so unrelated
  launcher installations do not fail because a self-release secret is absent.

The implementation is still inactive. It does not install a `rdashboard` project manifest, enable
`auto_deploy`, migrate installed executable paths to versioned release slots, provide the root recovery
CLI, install a signing key, start a service or mutate GitHub/VPS/i9 state.

### Self-review findings and dispositions

- The first scheduler design allowed an optional build-only host to run native verification, which
  would strand compiled outputs and force either a second VPS build or an unplanned artifact transfer.
  Native verification now requires a worker that also owns the required VPS pool, and a regression test
  proves verification and packaging share one state key and host while packaging waits for the receipt.
- An unconditional `LoadCredential` in the base launcher unit would have made OCI-only and
  verification-only installations depend on a self-release seed. The credential is now isolated in an
  explicit drop-in installed only with the matching native policy.
- A promotion failure after root had sealed the staging directory but before atomic rename could leave
  cleanup expecting the earlier build-owned shape. Cleanup and startup reconciliation now distinguish
  the exact build-owned, root-transition and root-sealed shapes, remove only regular single-link files
  from those bounded directories and reject every unknown ownership/mode combination. A regression
  covers both build-owned partial and root-sealed interrupted staging.
- The pre-existing project manifest model required a Dockerfile even for the native adapter. V2 now has
  a strict `native` build kind with no Dockerfile and rejects adapter/build mismatches; V1 remains
  OCI-only and both generated schemas were refreshed and checked.

### Verification

- Final bare `bin/ci`: passed, exit code 0.
- It covered formatting, strict Clippy, all library/binary/integration/socket/scheduler/worker tests,
  both generated project-manifest schema checks, nine browser contracts and the optimized release
  build. The final post-correction release phase took 4 minutes 12 seconds.
- The native scheduler regression passed among 17 scheduler contracts, and launcher authorization
  proves the installed native client receives only a read-only operation state, its exact request and a
  lease-owned output directory.
- No external service, credential, host policy, push or deployment was changed.
- Final staged product/config/test diff SHA-256:
  `d3f183e459050eb6ec338096d66e40baeafed19fad12ef5a1e7691fcc326c08b`.

### Independent consultation

The final review inspected the exact product/config/test hash above after the recovery correction:

- route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`;
- status: `ANSWERED`, one attempt, CLI `1.18.3`, 140 seconds;
- state fingerprint: `539f1325109bf2c1f37566cd40051e1751b74f66842f31c2c0386df4d9dd7478`;
- brief SHA-256: `ddebc2d228b7b3828a6ac2983639ad5568a2a5bcf758a4525b9e246b5c55fad2`;
- response SHA-256: `848d4e73f31d99cb325c2e69066400031dc203ec28dee65a2ae574c8f188a758`;
- verdict: `SAFE`, no P0-P2 finding and no open question.

Its two P3 defense-in-depth observations do not require product changes:

- build-owned staging cleanup deliberately permits regular single-link children regardless of file
  owner because a crash may occur after root has already transferred individual output files but before
  the directory ownership transition. The exact directory name, owner, group and mode are validated;
  special entries fail closed, and unlinking an entry inside that bounded root-created directory grants
  no capability or data access;
- the bootstrap deliberately performs only a structural check on hidden launcher staging because it
  neither opens nor removes those entries. The root launcher is the sole cleanup authority and performs
  the stronger ownership/mode validation; a malformed hidden entry cannot be consumed as a release.

### Verdict

Slice 12b is production-worthy as an inactive verified producer/root-publication boundary and may be
committed. Executable-path migration, recovery tooling, inactive project/policy onboarding and host
drills remain the next local/activation slices; this result alone does not make a pushed `rdashboard`
commit deploy itself.
