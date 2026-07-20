# GitHub-independent delivery implementation review

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: slices 1a, 1b, 2a, 2b and 2c complete locally; the separately authorized live baseline remains pending
- Review date: 2026-07-20
- Baseline HEAD: `d20cf342dac204c51d30a32009eeb9c58097c8aa`
- Local implementation commits: `64e64f2` (`Add persistent resource observer`), `581a432`
  (`Add adapter execution receipts`), `25dff26` (`Add durable workflow scheduler`), `8b72141`
  (`Add authenticated workflow gateway`)
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
