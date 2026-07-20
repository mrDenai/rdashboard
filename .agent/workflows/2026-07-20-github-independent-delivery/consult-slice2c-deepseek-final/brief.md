GOAL
Perform the final exact-staged review of the read-only workflow journal projection and operator
dashboard after the two P2 error-sanitization findings from the first review were corrected.

QUESTION
Do the accepted fixes fully remove internal error disclosure and incorrect client-error mapping, and
does the exact current staged diff retain every previously verified safety, consistency, resource and
browser contract without introducing a new actionable P0-P2 defect? Return SAFE if yes. Otherwise
report each concrete path/sequence, impact and smallest production-worthy fix.

CONSTRAINTS
- Review only `git diff --cached`; the exact product-code/test SHA-256, excluding workflow artifacts,
  is `c33ee2422411e306b023cb12f2f69ed5f5b3a907a72260237b1ebd7d52d261df`, 11 paths,
  969 insertions and 2 deletions.
- Ignore every unstaged change. It is separate notification/dashboard work owned by another slice;
  the exact staged snapshot was independently exported and verified without those changes.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents or mutate any
  external system.
- Report only actionable P0-P2 correctness, security, concurrency, resource, contract, UX,
  accessibility or missing high-signal test findings. Avoid style-only suggestions.
- This slice adds no workflow mutation endpoint, worker execution, source ingress, provider write,
  service activation or deployment. The generic worker and sealed preparation store remain step 4.

FIRST-REVIEW FINDINGS AND ACCEPTED FIXES
- The first exact-staged review returned SAFE with two open P2 findings. Both are accepted and fixed.
- `workflow_overview` no longer routes journal failures through the mutation-oriented `store_problem`
  helper and no longer exposes `StoreError::Display`. A dedicated mapper logs the real error and
  returns HTTP 500 with code `workflow_overview_failed` and the fixed detail
  `Workflow overview could not be loaded.`
- The same dedicated mapper now handles response-clock and blocking-task join failures. It logs their
  real values server-side and returns the same fixed generic problem response, so
  `SystemTimeError::Display` cannot cross the HTTP boundary.
- A high-signal HTTP regression test corrupts a persisted journal field with an internal-secret marker
  and proves the response is 500, has the exact generic code/detail, and contains neither the marker
  nor the internal field-validation message.

REQUIRED INVARIANTS
- `WorkflowJournalReaderV1` is a narrow read-only capability. Its multi-statement attempt/node read
  uses one consistent SQLite snapshot, accepts only limits 1 through 50, reads one extra row for
  truthful truncation, and returns deterministic newest-first order.
- GET `/api/v1/workflows` defaults to 20 rows, rejects invalid limits, executes blocking SQLite work
  off the async runtime, maps every server failure to the fixed sanitized 500 problem, and captures
  `generated_at_ms` after the consistent read.
- The browser accepts only the exact V1 response/attempt/node key sets, bounded identifiers,
  timestamps, digests, states, ordering and uniqueness. It rejects malformed data rather than
  rendering it as healthy or current.
- Five-second polling cannot overlap. A failed refresh preserves the last valid snapshot and visibly
  marks it stale/error; loading, empty, truncated, success, recovery, cleanup-required and unknown
  states remain truthful.
- Recovery and failed nodes take display priority over merely ready work. DOM insertion uses semantic
  elements and `textContent`; the native refresh button, row headers, caption, keyboard-scrollable
  overflow and centralized live announcements remain usable without experimental browser APIs.
- The projection remains repository-agnostic and bounded across installed projects. It reveals no
  credentials, raw logs or mutation tokens.

KNOWN EVIDENCE
- Bare `bin/ci` passed from a refreshed exact `git checkout-index` staged snapshot after both P2 fixes:
  167 library tests with 2 credentialed live tests ignored, every binary/integration suite, 29
  store/web contracts, 14 scheduler contracts, 8 browser contracts and the optimized release build
  in 2m49s.
- The new corrupt-journal sanitization contract passed inside that exact gate. Formatting, Clippy,
  schema checks and `git diff --cached --check` also passed.
- The earlier full live-worktree gate passed after the response-timestamp race and failed-node display
  priority corrections; the exact staged gate independently excludes notification code.
- Modern web guidance was applied. The in-app browser-control surface was unavailable, so no visual
  browser QA is claimed; static semantic and executable JavaScript/Rust contracts passed.

PRIMARY INSPECTION TARGETS
- `src/scheduler.rs`
- `src/store/control.rs`
- `src/web/hub.rs`
- `src/web/routes.rs`
- `web/status.js`
- `web/app.js`
- `web/index.html`
- `web/app.css`
- `tests/workflow_scheduler_contracts.rs`
- `tests/store_and_web.rs`
- `tests/browser_status.test.js`
