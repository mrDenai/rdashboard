GOAL
Validate the production-worthiness of the staged local slice that introduces rdashboard's strict installed workflow contract and durable repository-agnostic scheduler journal. The slice is intentionally inactive: worker sockets, source ingress, production installation, and deployment activation are later steps.

QUESTION
Does the exact staged diff contain any concrete P0, P1, or P2 correctness, security, concurrency, migration, durability, or contract gap that must be fixed before a local commit? Focus on invariant-breaking counterexamples, not style or future features. Return SAFE if no such issue exists; otherwise identify path/symbol, triggering sequence, impact, and smallest coherent fix.

CONSTRAINTS
- Review only `git diff --cached`; its SHA-256 is `d749fd30d8fe1df1d129cddf62816b8f9f0f8bcbf892c504634851ed0e4ee9c8` and it contains 17 paths, 5,660 insertions, and 38 deletions.
- Do not review or rely on unstaged notification/dashboard work. Do not read `.env`, credentials, user memory, conversation transcripts, or unrelated historical workflows.
- Keep repository access read-only. Do not edit, build, test, invoke agents, or mutate external systems.
- Legacy `ProjectManifestV1` remains byte/schema compatible. V2 is the only manifest with the installed workflow DAG.
- The scheduler is a durable local core, not yet wired to a worker socket or production runtime.
- Existing security/mutation journals remain the sole privileged-effect authority. The new workflow journal may coordinate mutation ownership but must not claim an effect succeeded without the existing adapter/executor receipts.
- A newer head may supersede only pre-mutation work. A mutation owner or ambiguous mutation lease must retain the project lock until explicit reconciliation.
- All projects share the same queue, protocol model, and fixed adapter catalog. Optional i9 compute may prepare or verify, but cannot own the required release artifact or block VPS completion.
- Missing, conflicting, expired, late, wrong-host, wrong-input, or wrong-policy receipts must fail closed.
- Bare `bin/ci` is the only project gate. It passed after the staged state was formed, including formatting, Clippy, schema checks, 184 library tests (2 credentialed live tests ignored), all integration/browser tests, and optimized release build.

KNOWN EVIDENCE
- `src/domain/workflow.rs` defines the finite typed DAG, fixed adapter/pool/network/cache/artifact contracts, resource bounds, canonical leases, node receipts, and reduction receipts.
- `src/domain/manifest.rs` preserves V1 and adds canonical digest-bound `ProjectManifestV2`; `src/installed_workflow.rs` enforces private stable installed files.
- `src/store/control.rs` performs an atomic control schema v1-to-v2 migration and validates the complete STRICT table/column contract.
- `src/scheduler.rs` implements stable admission identity, channel deduplication, source high-water checks, pre-mutation supersession, weighted cross-project claims, deploy single-flight, generation-bound leases, mutation reconciliation, receipt idempotency, and deterministic reduction.
- `tests/workflow_scheduler_contracts.rs` covers two projects, strict generic contracts, channel convergence, supersession, fairness/reopen, lease generation/expiry, optional i9 restrictions, reducer binding, late receipts, mutation ownership, and restart tamper detection.
- `tests/store_and_web.rs:control_store_migrates_v1_to_the_durable_workflow_journal` covers migration/reopen; `tests/project_manifest_catalog.rs` covers the V2 catalog fixture.

INSPECT IF NEEDED
- `git diff --cached -- src/domain/workflow.rs src/domain/manifest.rs src/installed_workflow.rs`
- `git diff --cached -- src/scheduler.rs src/store/control.rs src/store/mod.rs`
- `git diff --cached -- tests/workflow_scheduler_contracts.rs tests/store_and_web.rs tests/project_manifest_catalog.rs`
- `.agent/workflows/2026-07-20-github-independent-delivery/plan.md`, especially step 2, only for intended outcome and verification criteria.
