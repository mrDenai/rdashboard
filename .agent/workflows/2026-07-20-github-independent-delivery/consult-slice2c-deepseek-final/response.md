**VERDICT: SAFE**

**FINDINGS** (none actionable):

1. **Sanitization fix verified** — `workflow_overview` routes all failure paths (journal read, `SystemTimeError`, `JoinError`) through `workflow_overview_problem`. The corrupt-journal test at `tests/store_and_web.rs:1011-1220` proves HTTP 500 with fixed generic `code`/`detail`, and no internal value or error fragment leaks into the response body. `tracing::error!` captures the real `Display` server-side.

2. **`WorkflowJournalReaderV1` narrow capability** — `src/scheduler.rs:302-348`: accepts limits 1–50, reads `limit+1` row for truthful truncation, deferred transaction for consistent snapshot, `ORDER BY updated_at_ms DESC, created_at_ms DESC, attempt_id ASC`. Error type `CorruptWorkflowJournal("project ID")` discards the corrupt value before it reaches the response path.

3. **HTTP surface** — `src/web/routes.rs:471-527`: limit defaults to 20 (`u8` deserialized → `usize` validated 1–50), `spawn_blocking` for SQLite, `generated_at_ms` captured after snapshot. All error arms call `workflow_overview_problem`. Single-step `from_page` avoids exposing the intermediate `WorkflowAttemptPageV1` wire format.

4. **Browser contract** — `web/status.js:255-380`: `validWorkflowOverview` enforces exact V1 key sets (4 top-level, 17 per-attempt, 9 per-node), verified `uuidPattern`/`commitPattern`/`digestPattern`/`workflowIdentifierPattern`, known states/kinds/pools, timestamp ordering (`created_at_ms ≤ updated_at_ms ≤ generated_at_ms`), unique IDs, cardinality ceilings (50 attempts, 64 nodes). Rejects unknown keys, `schema_version ≠ 1`, non-integer timestamps.

5. **Polling, state, DOM** — Five-second interval guarded by `runtime.workflowLoading`. Previous valid snapshot preserved on failure. All 5+ states (loading, empty, truncated, success, stale/error, recovery) truthfully rendered. `needs_reconcile`/`failed` precede `ready`/`blocked` in `workflowCurrentStepLabel`. Semantic table, `textContent` (no `innerHTML`), `overflow-x: auto` + `tabindex`, native button, `aria-labelledby`, centralized `announce()`. No credentials, logs, or mutation tokens.

**OPEN QUESTIONS**: None.

**INSPECTED**: `src/scheduler.rs:289-348`, `src/store/control.rs:330-341`, `src/web/hub.rs:43-46`, `src/web/routes.rs:452-527`, `src/web/routes.rs:1115-1137`, `web/status.js:64-380`, `web/app.js:199-370` (and interval/dispatch wiring), `web/index.html:102-144`, `web/app.css:232-650`, `tests/workflow_scheduler_contracts.rs:1063-1133`, `tests/store_and_web.rs:1011-1220` + `1722-1738`, `tests/browser_status.test.js:144-220`.
