# GitHub-independent delivery research brief

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: implementation in progress
- Last updated: 2026-07-21

## User input log

### U001 — 2026-07-20

Faithful English rendering:

Review the history of previous sessions for context. GitHub has repeatedly been an unreliable operational dependency: workers fail, pipelines do not trigger, and other GitHub-side failures occur. Source code should remain hosted on GitHub, but deployment and workflow execution must not depend on GitHub runners or require reproducing all of GitHub's infrastructure.

Docker is part of the current processes but is also problematic: build caches are very large, builds, startup, and shutdown are slow, processes sometimes hang, and orphaned containers remain. Of the VPS's 67 GB, roughly 30–40 GB appears to be allocated to Docker and runners, which is excessive.

Deployments are slow because the path contains too many unnecessary intermediate steps. Research a Git-push-triggered architecture that is independent of GitHub's runner infrastructure and optimized for time and resources, including artifact/file size and deployment time. `rdashboard` should own deployments and workflows, including deploying itself, monitor resource consumption, and produce concise LLM-readable error logs when failures occur.

If anything remains unclear, ask questions one at a time until the task is fully understood. Whenever alternatives require a user choice, explain the concrete advantages and disadvantages of each option so the user can choose.

Normalized request and constraints:

- Requested outcome: read-only, evidence-backed architecture and operational research; no implementation or deployment in this phase.
- Preserve GitHub as the canonical source-code host and a push-originating signal, but remove GitHub Actions runners from the execution and deployment critical path.
- Make `rdashboard` the owner/coordinator of project workflows, deploys, self-deploy, resource observation, and bounded machine-readable failure evidence.
- Optimize the whole delivery path for elapsed time, CPU/RAM/disk/network use, retained build state, artifact size, cleanup behavior, and recovery correctness.
- Investigate current repository contracts, historical workflow decisions, current GitHub setup, Docker usage, and production VPS facts before recommending an architecture.
- Avoid pulling in a full GitHub-compatible CI platform unless evidence shows it is necessary.
- Treat self-deployment, untrusted repository content, credentials, concurrency, rollback, event loss, and `rdashboard` failure as first-class trust and availability boundaries.
- Ask only one user question at a time, and explain pros and cons when a user-owned choice materially changes the recommendation.
- Do not mutate production, GitHub, providers, or repository implementation during research. Durable workflow artifacts are the only authorized writes.

### U002 — 2026-07-20

Faithful English rendering:

The research document is for the agent's own durable understanding; technical implementation choices
should not be pushed back to the user unnecessarily. Recommendations 1-4 and 6 are accepted. Item 5 is
not understood. Item 7 is also not understood, although it may be appropriate.

The target for every deployment is under one minute, except for work that inherently cannot be made
faster; rare exceptional deployments may take two to three minutes. Five minutes is excessive.

Workers must serve all repositories rather than be dedicated to selected repositories. They must not
repeat wasteful preparation. The current pattern in which four-way parallelism causes every worker to
clone its own repository and independently build the same libraries is inefficient and must be
eliminated.

The i9 machine is only intermittently available compute capacity. It is not a VPS; transferring
deployment artifacts to or from it adds operational complexity. Historically it has therefore run CI
and pre-deployment checks only. It cannot be considered continuously available and must never block
the workflow, but it may be used opportunistically while online.

Normalized corrections and constraints:

- Do not require a user choice for worker placement. The authoritative path must work entirely without
  i9; i9 is an opportunistic, non-blocking CI/check accelerator only.
- Design one repository-agnostic worker pool for every onboarded repository, controlled by installed
  manifests and typed task contracts rather than one runner/installation/workspace per repository.
- Prepare each source SHA, dependency set, generated input, and compilable test artifact once per host
  and fan out only genuinely independent execution shards. Parallel slots share immutable prepared
  inputs and use small copy-on-write scratch areas; they do not reclone or rebuild common libraries.
- Do not transfer deployment images/artifacts through i9. It may fetch and verify the exact SHA, run
  leased CI or pre-deployment shards, and return only bounded result evidence/logs. Loss of its
  heartbeat immediately requeues unfinished work locally without blocking admission indefinitely.
- Replace the prior five-minute warm target. The intended normal deployment target is under 60 seconds;
  genuinely irreducible exceptional paths may take two to three minutes. The measurement boundary
  still requires one product clarification before a target can be made unambiguous.
- Explain item 5 as a hard per-job/shared-cache storage fence that prevents any build from filling the
  production filesystem, not as a user-facing choice. Explain item 7 as a small deterministic incident
  card generated from bounded redacted evidence for both operators and LLMs, not as AI authority.

### U003 — 2026-07-20

Faithful English rendering:

Choose option 1.

Normalized decision:

- The less-than-60-second deployment clock starts when GitHub accepts the `git push` and ends when
  production traffic is switched to the new healthy release.
- Verification, release build, artifact handling, candidate startup, health validation, and traffic
  cutover are all inside this end-to-end budget. Post-cutover observation/soak and asynchronous cleanup
  are measured separately and do not redefine when the new release begins serving production traffic.
- This supersedes U002's unresolved measurement-boundary ambiguity; all other U002 constraints remain
  unchanged.

### U004 — 2026-07-20

Faithful English rendering:

What happens next? The result was not explained: describe what is ultimately planned, how it will work,
which alternatives and choices exist, and what should be done with the research.

Normalized request:

- Provide a self-contained, plain-language operator-facing handoff in chat rather than merely pointing
  to the durable research artifact.
- Explain the end-state architecture, the lifecycle of a pushed commit, failure/degraded behavior,
  considered alternatives and their trade-offs, what has already been decided, what remains measured
  rather than user-chosen, and the recommended implementation sequence.
- This is a request to explain and hand off the research result, not authorization to implement,
  deploy, delete runner/cache state, or mutate external systems.

### U005 — 2026-07-20

Faithful English rendering:

Push to accepted SHA should take up to three seconds normally and up to 60 seconds when the webhook is
lost. Proceed with `$plan`; the details are not yet fully clear to the user, but continue if the
available information is sufficient.

Normalized decision and authorization:

- The normal webhook path retains a push-to-accepted-SHA target of at most three seconds.
- A lost-webhook repair path may take up to 60 seconds to accept the exact SHA. This is an explicitly
  degraded trigger class rather than the normal less-than-60-second end-to-end class; its downstream
  verification/build/cutover phases remain independently budgeted and must not be slowed merely because
  source discovery used reconciliation.
- This supersedes the research-derived 5-10-second reconcile / 10-second lost-webhook source-discovery
  target, while preserving U003's normal end-to-end clock boundary.
- Planning is authorized. Implementation, deployment, runner/cache deletion, and external mutation are
  not authorized in this phase.

### U006 — 2026-07-20

Faithful English rendering:

Not everything is understood yet, but proceed to implementation. If something goes wrong or a material
choice appears, resolve it along the way.

Normalized authorization and constraint:

- Local repository implementation is authorized, following the accepted plan incrementally.
- Continue autonomously through low-risk implementation details; surface material deviations, blockers,
  or choices when evidence shows that the planned direction cannot be followed safely.
- This authorization does not itself authorize production installation, deployment, GitHub/provider
  mutation, runner/cache deletion, or another external-system mutation; the explicit gates in `plan.md`
  remain in force.

### U007 — 2026-07-20

Faithful English rendering:

Proceed with it.

Normalized authorization and continuation:

- Continue local implementation from the completed persistent-observer slice into the next planned
  step-1 slice: Failure Capsule V2 and terminal workflow resource/cleanup receipts.
- The existing U006 external-mutation boundaries remain unchanged; this message authorizes repository
  implementation, verification, review and a task-scoped local commit, not installation or deployment.

### U008 — 2026-07-21

Faithful English rendering:

What is preventing you from continuing?

Normalized instruction:

- Do not stop merely to report the completion of an internal implementation slice while safe,
  authorized local work remains in the accepted plan.
- Continue autonomously from the completed GitHub source-ingress slice into the next coherent generic
  worker/shared-preparation slice, preserving the existing verification, review, local-commit and
  external-mutation boundaries from U006-U007.

### U009 — 2026-07-21

Faithful English rendering:

What is preventing you from continuing?

Normalized instruction:

- No new blocker or decision boundary has been introduced. Continue the authorized local
  implementation instead of pausing at an intermediate progress report.
- Preserve the existing rule that only a genuine architectural choice, unsafe ambiguity or external
  mutation boundary should be returned to the user for a decision.
