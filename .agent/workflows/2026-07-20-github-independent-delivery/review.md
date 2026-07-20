# GitHub-independent delivery implementation review

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: slices 1a and 1b complete locally; authorized live baseline remains pending
- Review date: 2026-07-20
- Baseline HEAD: `d20cf342dac204c51d30a32009eeb9c58097c8aa`
- Local implementation commit: `64e64f2` (`Add persistent resource observer`)
- Final staged diff SHA-256: `ca9712b8517e0a7c42c6672d81abed2e8c74165337306dca0ded2bc5c36e6432`

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
