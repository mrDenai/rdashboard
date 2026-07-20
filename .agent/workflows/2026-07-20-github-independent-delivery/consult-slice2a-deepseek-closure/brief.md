GOAL
Close the exact staged review of the inactive rdashboard workflow/scheduler slice after addressing the only actionable P2 from the prior review and adding terminal end-to-end evidence.

QUESTION
Do the final changes correctly close the prior non-mutation-expiry row-count finding without introducing a P0, P1, or P2 regression, and is the exact staged diff now safe for a local commit? Return SAFE if yes; otherwise give the concrete path, sequence, impact and smallest fix.

CONSTRAINTS
- Review only `git diff --cached`; exact SHA-256 is `cf105882140ff6d8b57806823ee6e27cbda9497fc9ee806099bc0df3a204b2df`, 17 paths, 6,025 insertions, 38 deletions.
- This is a closure round. Concentrate on the changes from previously reviewed hash `ce07e41a...`: `src/scheduler.rs:claim_next`, `expire_one_lease`, `commit_node_receipt`, and the two new terminal tests in `tests/workflow_scheduler_contracts.rs`. Widen only if those changes affect another invariant.
- Ignore unstaged notification/dashboard work and workflow bookkeeping. Do not read `.env`, credentials, memory, conversations or unrelated workflows.
- Read-only repository access only. Do not edit, build, test, invoke agents or mutate external systems.
- Worker runtime/transport, cleanup reconciliation, UI projection and production activation remain later work and are not claimed by this slice.
- Correctness requirement: expiry of a non-mutation lease must persist and requeue exactly one leased node. A late receipt must be rejected while the expiry remains committed.
- `claim_next` may expire and claim in one immediate transaction because it returns a normal optional claim. `commit_node_receipt` intentionally commits expiry in a preceding transaction: if expiry and a late-receipt error shared one transaction, that expected error would roll the expiry back.
- Final bare `bin/ci` passed after this exact correction: formatting, Clippy, schemas, 184 library tests (2 credentialed live tests ignored), every integration/browser suite, 10 scheduler tests and optimized release build.

KNOWN EVIDENCE
- Prior response `consult-slice2a-deepseek-final/response.md` judged the slice SAFE but identified one actionable P2: the non-mutation `leased -> ready` UPDATE ignored its affected-row count. It also suggested combining receipt expiry and commit for latency.
- `expire_one_lease` now checks exact row counts for the active lease, node and attempt updates.
- `claim_next` expires and claims inside one immediate transaction.
- An attempted single receipt transaction was rejected by the full gate: `late_receipts_requeue_non_mutating_work_instead_of_becoming_success` observed `Leased` instead of `Ready` because the late-receipt error rolled expiry back. The final code restores the deliberate two-transaction receipt boundary with an explanatory comment; the same test now passes.
- `terminal_success_releases_mutation_ownership_and_wakes_the_newer_head` proves the complete successful DAG projection and handoff.
- `terminal_success_rolls_back_when_the_held_mutation_lock_is_missing` proves terminal receipt writes roll back atomically when mutation authority is absent.

INSPECT IF NEEDED
- `git diff --cached -- src/scheduler.rs tests/workflow_scheduler_contracts.rs`
- `consult-slice2a-deepseek-final/response.md` only for the prior finding text.
