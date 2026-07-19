# Dashboard automation implementation plan

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: complete
- Last updated: 2026-07-19
- Depends on: `brief.md`, `research.md`

## Outcome

Complete the safe autonomous phase of the `rimg` operations surface: replace the Updates and Errors
placeholders with durable provider-backed states, preprocess only structurally anonymous GlitchTip
aggregates through DeepSeek Free, establish a typed Telegram notification contract, reuse the existing
verified backup/deploy evidence instead of duplicating it, and prove a Docker application-build path
that does not retain the multi-gigabyte native compilation graph. Production activation, push and
deployment remain explicitly out of scope.

## Ownership and change boundaries

- Primary repository: `/home/denai/RustroverProjects/rdashboard`.
- Supporting build-boundary changes may be made in `/home/denai/RustroverProjects/rimg`; its unrelated
  untracked `.agent/` tree remains untouched.
- Existing modified files under
  `.agent/workflows/2026-07-15-rdashboard-production/` are user-owned and must not be staged or edited.
- Secret values are never written to source, workflow artifacts, SQLite fixtures, model briefs or logs.
- No GitHub push, provider write, production install, service restart or deployment is authorized.

## Implementation steps

### 1. Durable integration contracts and storage

Dependencies: none.

- Add bounded, versioned domain types for project integration status, error aggregates, AI insight and
  dependency updates. Every string/count/list/URL receives an explicit limit and validator.
- Add a separate `integrations.sqlite` store rather than expanding the critical controller journal.
  Persist the latest successful safe payload plus last attempt/success/error metadata for Errors and
  Updates independently.
- Preserve the last successful payload across collection failures and restart. Never persist provider
  bearer values, raw response bodies, GlitchTip titles/culprits/event IDs or model reasoning.
- Cover schema creation/reopen, corrupt payload rejection, success->failure last-known preservation and
  per-project separation.

### 2. GlitchTip -> anonymous facts -> DeepSeek Free

Dependencies: step 1.

- Implement one fixed `rimg` GlitchTip collector for origin `https://glitchtip.4u.ge`, organization
  `4u`, numeric project `4`, unresolved issues only. Read the token from the fixed systemd credential
  name `glitchtip-read-token`.
- Bound timeout, redirect policy, response bytes, issue count and all numeric conversions. Accept only
  HTTPS/fixed-origin deep links. Use a safe local label derived from a validated exception-class token;
  otherwise display a generic label. Do not store title or culprit.
- Build the model packet from ranks, levels, event/user counts and coarse age/release facts only. Unit
  tests must insert conspicuous title/URL/ID/PII markers in the fake GlitchTip response and prove none
  occur in the OpenCode request.
- Call only `https://opencode.ai/zen/v1/chat/completions`, model
  `deepseek-v4-flash-free`, with `reasoning_effort=low`, strict JSON response format, no tools and a
  bounded completion budget. Read `opencode-api-key` from the systemd credential directory.
- Validate the returned JSON against bounded priority/summary/actions. Never use provider reasoning.
  Empty issue sets skip the model. Timeout, unavailable key, malformed/empty/oversized JSON or provider
  errors retain deterministic aggregates and yield an explicit partial AI state.
- Exercise a local credential-backed live smoke without printing provider content; fake-provider tests
  remain the deterministic gate.

### 3. Dependency update/check collector

Dependencies: step 1.

- Implement an optional fixed repository collector for `mrDenai/rimg` using a separate credential
  `github-metadata-token` and GitHub's versioned REST API.
- Select only open `main` pull requests that are dependency-labelled or use `renovate/*` heads. Fetch
  bounded check-run state for each exact head and collapse it to `passing`, `pending`, `failing` or
  `unknown` without inventing review/mergeability claims.
- Persist only bounded title, PR number, head SHA/ref, update time, URL and derived check state. Preserve
  last-known data on rate-limit/auth/network/malformed responses and expose fetch staleness.
- Keep the source-ref-only candidate design out of this slice until the broker can fetch bounded
  non-main refs safely; do not label GitHub metadata as source/deploy authority.

### 4. Authenticated dashboard journey

Dependencies: steps 1-3.

- Add authenticated project Errors and Updates routes backed by `integrations.sqlite`, including
  configured/unconfigured, attempt/success ages, last safe data and bounded failure state.
- Extend `DashboardState` with the integration store and runtime capabilities. Spawn independent
  missed-tick-safe collectors; one provider failure must not stop host/resource/repository collection.
- Replace both literal placeholder cells with strict browser validators/renderers for loading,
  unconfigured, empty, fresh, partial, stale last-known and failed states. Link only to validated HTTPS
  GlitchTip/GitHub origins and use `textContent`; expose model source/degradation without presenting AI
  output as causal fact.
- Refresh on bounded intervals, keep the current value visible on refresh failure, and update only the
  affected project row. Add accessible state text and retain native table semantics/responsive flow.
- Add API, browser-contract and failure-path tests.

### 5. Typed notification outbox and Telegram adapter contract

Dependencies: steps 1-2.

- Add a versioned notification fact packet containing only typed project/severity/transition/summary
  fields and a stable fact digest. The controller must not accept arbitrary provider-shaped payloads.
- Add bounded outbox storage with stable notification/dedup identities and explicit
  `pending`, `sending`, `delivery_unknown`, `retry_scheduled`, `delivered`,
  `delivered_possible_duplicate` and `permanently_failed` states. Preserve ambiguous acceptance across
  restart.
- Add a Telegram-gateway request adapter that maps the typed fact to bounded text plus stable
  `event_key`/`dedup_key`; keep transport credentials out of the controller types and persistence.
- Do not enqueue live notifications until an isolated notifier route is configured. Tests cover replay,
  conflicting identity, bounded backlog and unknown->possible-duplicate transitions.

### 6. Backup and deploy truth, without external activation

Dependencies: step 4.

- Reuse operation history for current compact backup/deploy summaries and improve empty wording so
  absence of a completed backup is not represented as proof that no backup is needed.
- Document that the existing verified backup chain is the implementation of the `sartuli.ge` contract;
  production remains unconfigured until its installed policy/recipient/Drive inputs exist.
- Keep GitHub Actions as hosted CI only. Do not add a GitHub deployment job or a webhook-only shortcut.
  Record the exact source/webhook/candidate/authorizer/runtime prerequisites for a future dashboard-
  owned automatic admission.

### 7. Small native artifact boundary and clean local Docker cycle (`rimg`)

Dependencies: none; can run after correctness work to avoid competing Docker load.

- Add a runtime-image Dockerfile that consumes the verified local `.titanium/opt/4u` output as a named
  build context instead of rebuilding all native libraries in the application builder.
- Extend `bin/update` to emit a deterministic bounded file manifest for that native output and add a
  verifier that checks the native fingerprint, exact manifest, path/type constraints, required ABI
  files and maximum total size before any application build.
- Add a narrow runtime-image build command and contract tests. Keep the legacy full native Dockerfile
  solely as the producer for a fingerprint change.
- Locally create a uniquely named task builder using a small app-only GC policy, build/load the exact
  runtime image, run its health/candidate smoke and remove the task container, image and builder.
  Capture `docker system df` and task-builder usage before/after. Never run global prune or remove
  unrelated resources.
- Do not lower the existing production 6 GB builder ceiling until this new artifact path is the actual
  installed candidate producer; record that activation dependency rather than claiming cleanup early.

### 8. Verification, review and handoff

Dependencies: steps 1-7.

- Run only bare `bin/ci` in every changed repository. Do not substitute targeted tests for the gate.
- Inspect both final diffs and worktree status, preserving unrelated paths.
- Obtain a fresh focused `deepseek-free` review of the exact substantive diff. Verify every finding in
  source, fix valid P0-P2 issues, rerun the affected repository's bare gate and repeat review if the
  substantive fingerprint changes.
- Create one task-scoped local commit per changed Git repository after its gate is green; stage only
  owned implementation/test/documentation paths and never amend. Do not push.
- Complete `review.md` with evidence, known limitations, blocker disposition and rollback notes.

## Blockers for activation and user follow-up

These do not block local implementation or fake-provider/Docker verification.

| ID | External input/action required | Why local work cannot complete it safely |
| --- | --- | --- |
| B001 | Create/install a dedicated GlitchTip token limited to read-only scopes under a least-privilege user and fixed credential `glitchtip-read-token`. | The existing operator environment token must not be silently promoted into a production service identity and may see multiple projects. |
| B002 | Install the existing OpenCode key as controller-only systemd credential `opencode-api-key`; confirm the accepted policy is aggregate-only use of the US-hosted free route whose data may improve the model. | The user required this model, but credential installation and acceptance of the provider's current data terms are external production actions. |
| B003 | Provision a GitHub App or equivalent short-lived/fine-grained credential with only private-repository Pull Requests/Checks metadata read access as `github-metadata-token`. | The private repository's PR/check state is not available anonymously, and the source SSH key cannot call the API. |
| B004 | Register/choose the `telegram-gateway` project, destination chat/thread and per-project API secret; install the secret only for a separate notifier UID. | The controller must not infer a chat or receive the gateway credential. |
| B005 | Supply the production `age` recipient/restore-key owner, Drive folder/service account, retention schedule and restore-drill owner. | Keys, provider mutation and retention/destruction policy are external owner decisions; no production backup files exist today. |
| B006 | Register the generated source deploy key read-only for `mrDenai/rimg`, install source config/credentials/service and validate accepted-tree reconciliation. | Production currently has no source service/config and repository access registration is an external GitHub action. |
| B007 | Create and route the narrow GitHub webhook endpoint, install its HMAC secret in the source boundary and decide the public ingress/DNS/Cloudflare route. | Public routing and secret registration are external mutations; periodic reconciliation remains the repair path. |
| B008 | Install the isolated candidate producer/signing key, mutation policies, release state, backup runtime and authorizer; then explicitly set `auto_deploy=true`. | A `main` notification cannot safely deploy without an exact signed candidate and installed rollback/backup authority. Production deployment is expressly unauthorized in this task. |
| B009 | Approve and execute production migration away from the legacy 6 GB builder, then remove only the confirmed obsolete builder cache. | The current graph is the only proven 14-second warm path; deletion before the new producer is live would be a destructive availability regression. |

## Acceptance checks

- Errors cell shows deterministic empty state for current live project 4 data and never calls DeepSeek
  for the empty set.
- Synthetic non-empty errors produce a bounded DeepSeek JSON insight while conspicuous raw title/PII/ID
  markers are absent from the request and persistence.
- GlitchTip/OpenCode/GitHub failures preserve last-known safe data and show source-specific partial or
  stale state; unconfigured credentials remain truthful.
- Updates cell reflects the two current dependency PRs in a credential-backed local smoke and exposes
  their exact check state without claiming approval/mergeability.
- Notification contracts prove idempotency and delivery ambiguity without possessing a Telegram token.
- Existing deploy/backup operation behavior and source/executor trust boundaries remain green.
- The app-only Docker cycle succeeds and task-owned builder/image/container residue is absent afterward;
  no unrelated Docker object changes.
- All changed repositories pass bare `bin/ci`; mandatory review has no unresolved P0-P2 finding.

## Plan audit ledger

- A fresh `deepseek-free` plan-audit request was started after the draft was complete. The route read
  `plan.md`, `brief.md` and `research.md` but produced no response while stalled in repository
  exploration. After more than six minutes it was treated as unavailable for planning rather than
  blocking implementation. The earlier completed research consultation and direct source verification
  remain the independent evidence for the accepted privacy, update-truth and notifier phase boundaries.

## Completion ledger

- All safe autonomous Phase 1 implementation, local provider smokes, bounded Docker-cycle validation,
  direct review and independent `deepseek-free` review are complete.
- Bare `bin/ci` passed in both changed repositories after the final review fixes.
- Production activation remains deliberately fail-closed behind blockers B001-B009; no push, deploy,
  service mutation or provider write was performed.
