GOAL
Review the exact staged read-only workflow journal projection and operator dashboard before a local
commit that closes implementation-plan step 2.

QUESTION
Does the exact staged diff expose a bounded, consistent and strictly validated workflow overview
without adding mutation authority, hiding recovery/cleanup failure states, or creating a material
resource, concurrency, security, accessibility or stale-data defect? Return SAFE if yes. Otherwise
report each concrete path/sequence, impact and smallest production-worthy fix.

CONSTRAINTS
- Review only `git diff --cached`; the exact product-code/test SHA-256, excluding workflow artifacts,
  is `949c5b24ac1b64380b3c29dd5d964cbbc5ac5d82508e44f06f49a537d5f8540e`, 11 paths,
  919 insertions and 2 deletions.
- Ignore every unstaged change. It is separate notification/dashboard work owned by another slice;
  the exact staged snapshot was independently exported and verified without those changes.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents or mutate any
  external system.
- Report only actionable P0-P2 correctness, security, concurrency, resource, contract, UX,
  accessibility or missing high-signal test findings. Avoid style-only suggestions.
- This slice adds no workflow mutation endpoint, worker execution, source ingress, provider write,
  service activation or deployment. The generic worker and sealed preparation store remain step 4.

REQUIRED INVARIANTS
- `WorkflowJournalReaderV1` is a narrow read-only capability. Its multi-statement attempt/node read
  uses one consistent SQLite snapshot, accepts only limits 1 through 50, reads one extra row for
  truthful truncation, and returns deterministic newest-first order.
- The HTTP surface exposes only GET `/api/v1/workflows`, defaults to 20 rows, rejects invalid limits,
  executes blocking SQLite work off the async runtime, maps failures without sensitive details, and
  captures `generated_at_ms` after the consistent read so a concurrent write cannot create a valid
  row newer than the response timestamp.
- The browser accepts only the exact V1 response/attempt/node key sets, bounded identifiers,
  timestamps, digests, states, ordering and uniqueness. It must reject malformed data rather than
  render it as healthy or current.
- Five-second polling cannot overlap. A failed refresh preserves the last valid snapshot and visibly
  marks it stale/error; initial loading, empty, truncated, success, recovery, cleanup-required and
  unknown states remain truthful.
- Recovery and failed nodes take display priority over merely ready work. DOM insertion uses semantic
  elements and `textContent`; the native refresh button, row headers, caption, keyboard-scrollable
  overflow and centralized live announcements remain usable without experimental browser APIs.
- The projection must remain repository-agnostic and bounded across multiple installed projects. It
  may reveal immutable operational identifiers/digests but no credentials, raw logs or mutation
  tokens.

KNOWN EVIDENCE
- Bare `bin/ci` passed in the live worktree after the final race correction: 184 library tests with
  2 credentialed live tests ignored, every binary/integration suite, 29 store/web contracts,
  14 scheduler contracts, 9 browser contracts and the optimized release build in 2m51s.
- Bare `bin/ci` also passed from an exact `git checkout-index` staged snapshot with no notification
  code: 167 library tests with 2 ignored, every binary/integration suite, 28 store/web contracts,
  14 scheduler contracts, 8 browser contracts and the optimized release build in 2m59s.
- Self-review moved response time capture after the journal read to close a concurrent-write race and
  changed current-step priority so a failed node cannot be hidden by a ready node. Both have regression
  assertions and the exact staged gate passed afterward.
- Modern web guidance used semantic-table, accessible-error-announcement, native-button and real
  overflow-scroll guidance. The in-app browser control surface was unavailable, so no visual browser
  QA is claimed; static semantic and executable JavaScript/Rust contracts passed.
- `git diff --cached --check` passed, and the staged diff contains no notification/notifier hunk.

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
