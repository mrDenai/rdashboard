GOAL
Perform the final independent review of the exact staged, inactive rdashboard workflow-contract and durable-scheduler slice after self-review hardening.

QUESTION
Does the exact staged diff contain any concrete P0, P1, or P2 correctness, security, concurrency, migration, durability, or contract gap that must be fixed before a local commit? Try to falsify the new fail-closed guarantees and return SAFE only if no such counterexample exists. For every finding provide path/symbol, triggering sequence, impact, and smallest coherent fix.

CONSTRAINTS
- Review only `git diff --cached`; its current SHA-256 is `ce07e41ae6aba45c499900fdded60b2eecb5bd8a4e5be56ba6707807e4da862e`, with 17 paths, 5,855 insertions, and 38 deletions.
- Ignore all unstaged notification/dashboard work and workflow bookkeeping. Do not read `.env`, credentials, memory, conversations, or unrelated historical workflows.
- Repository access is read-only. Do not edit, build, test, invoke agents, or mutate external systems.
- The staged slice is deliberately inactive. Worker sockets/runtime, cleanup reconciliation, controller/web projection, production installation and activation remain later work and are not claimed complete.
- Legacy `ProjectManifestV1` must stay compatible. V2 is strict, canonical, finite, root-installed and cannot carry arbitrary shell, host paths, or secrets.
- Existing security/mutation journals remain the only privileged-effect authority. The scheduler coordinates but never fabricates effect success.
- Required preparation and release artifacts must remain VPS-owned. Optional i9 capacity may claim verification only and must never block the authoritative path.
- Newer heads may supersede only pre-mutation work. Mutation failure/expiry retains the project lock as `needs_reconcile`.
- Leases must bind complete adapter, network, cache, timeout, resource and artifact contracts. Receipts must match the exact active generation, host, input, source and policy.
- Deterministic reduction must revalidate its complete persisted source evidence even on replay/restart, reject a non-monotonic reduction time, and detect row/document/digest substitution.
- A successful terminal mutation must not commit if its held mutation lock or any guarded state transition is missing.
- Final bare `bin/ci` passed on this exact staged source after the hardening: formatting, Clippy, schemas, 184 library tests (2 credentialed live tests ignored), all integration and browser tests, and optimized release build.

KNOWN EVIDENCE
- First review: `consult-slice2a-deepseek/response.md` returned SAFE for staged hash `d749fd30...`, but self-review then found untested hardening gaps and the diff changed materially.
- `src/domain/workflow.rs:WorkflowLeaseV1` now carries/digest-binds full execution and artifact policy and rejects controller-managed or profile-inconsistent leases.
- `src/domain/workflow.rs:WorkflowNodeKindV1::expected_pool` makes host preparation and release build `vps_required`; only verification is `build_compute`.
- `src/scheduler.rs:validate_persisted_reduction` reconstructs and compares source evidence, reduction identity, node projection and timestamps on every replay.
- `src/scheduler.rs` checks guarded row counts for lease, node, attempt, request and mutation-lock transitions so missing authority fails the transaction.
- `tests/workflow_scheduler_contracts.rs` proves optional accelerator placement, monotonic reduction, post-reduction receipt tamper detection after restart, late receipt rejection, mutation lock retention and two-project generic scheduling.

INSPECT IF NEEDED
- `git diff --cached -- src/domain/workflow.rs src/scheduler.rs`
- `git diff --cached -- src/store/control.rs src/domain/manifest.rs src/installed_workflow.rs`
- `git diff --cached -- tests/workflow_scheduler_contracts.rs tests/project_manifest_catalog.rs tests/store_and_web.rs`
- `git diff --cached -- config/project-manifests/ralert.json config/schema/project-manifest-v2.json`
