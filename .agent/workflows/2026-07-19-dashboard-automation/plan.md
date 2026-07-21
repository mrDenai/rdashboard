# Dashboard automation implementation plan

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: production notification activation complete
- Last updated: 2026-07-22
- Depends on: `brief.md`, `research.md`

## Outcome

Complete the safe autonomous phase of the `rimg` operations surface: replace the Updates and Errors
placeholders with durable provider-backed states, preprocess only structurally anonymous GlitchTip
aggregates through DeepSeek Free, establish a typed Telegram notification contract, reuse the existing
verified backup/deploy evidence instead of duplicating it, and prove a Docker application-build path
that does not retain the multi-gigabyte native compilation graph. The original implementation phase
excluded production activation; U005 now authorizes only the notification activation defined at the
end of this plan. Push and every unrelated deployment capability remain out of scope.

## Ownership and change boundaries

- Primary repository: `/home/denai/RustroverProjects/rdashboard`.
- Supporting build-boundary changes may be made in `/home/denai/RustroverProjects/rimg`; its unrelated
  untracked `.agent/` tree remains untouched.
- Existing modified files under
  `.agent/workflows/2026-07-15-rdashboard-production/` are user-owned and must not be staged or edited.
- Secret values are never written to source, workflow artifacts, SQLite fixtures, model briefs or logs.
- No GitHub push or unrelated provider/deployment mutation is authorized. U005 narrowly authorizes the
  production notification install, required service restarts and one bounded delivery verification.

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
| B004 | **Resolved by U005.** Reused the existing `ops` / `sartulibot` gateway project, Sartuli chat `-5057084213`, thread `0`, and installed its existing API secret only for the separate notifier UID. | The controller inferred nothing and never received the gateway credential. |
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

## Continuation Phase 2 — isolated notification delivery

The continuation authorized by U002 resumes the same task without relaxing any activation boundary.
The next coherent local unit is the missing notifier runtime, because the Phase 1 outbox contract is
not yet deliverable and its ambiguous-success lineage currently collapses incorrectly after retry.

1. **Complete — make delivery state exact and restart-safe.** Replace internal approximation names
   with the public contract states, preserve ambiguity through
   `delivery_unknown -> retry_scheduled -> delivered_possible_duplicate`, retain an accepted gateway
   UUID for polling after restart, distinguish known retryable rejection from unknown acceptance, and
   migrate the schema-v1 local store without blessing corrupt rows.
2. **Complete — implement the isolated notifier boundary.** Add a dedicated `rdashboard-notify` binary
   that exclusively owns the notification SQLite journal and gateway credential, serves a bounded
   peer-UID-authenticated Unix protocol to the controller, and drains the outbox through the exact
   asynchronous `telegram-gateway` POST/status contract with deadlines, body limits, no redirects and
   safe error codes.
3. **Complete — connect typed producers and observation.** When the optional notifier socket is
   installed, enqueue only meaningful integration transitions with deterministic identities; expose
   bounded delivery records through the authenticated dashboard. Missing notifier configuration must
   remain `not_configured` and must not accumulate an undeliverable local queue.
4. **Complete — add the installation contract without activating it.** Ship hardened notifier systemd
   units/drop-ins and document the exact controller UID, gateway project, chat/thread and credential
   inputs still owned by B004. Do not install, start or call the live gateway.
5. **Complete — verify, review and commit.** Run bare `bin/ci`, perform direct adversarial review plus a
   fresh `deepseek-free` review of the exact changed scope, resolve verified P0-P2 findings, rerun the
   gate and create one new task-scoped local commit without push.

Phase 2 owns the `rdashboard` gateway client and notifier boundary only. Every outbound Telegram
message uses the fixed `telegram-gateway` REST contract at `https://tg.4u.ge`; `rdashboard` contains no
Bot API client or bot token. Registering/configuring/deploying the separate `telegram-gateway`
repository remains an external activation responsibility and is not part of this commit.

### Phase 2 closure evidence

- Bare `bin/ci` passed on 2026-07-22 with exit code 0 after the gateway format correction. It covered
  formatting, strict Clippy, 301 active library tests with two credentialed live tests ignored by
  design, all binary/integration/socket/scheduler suites, nine browser tests and the optimized release
  build. The release phase completed in 5 minutes 11 seconds.
- `telegram-gateway` was inspected read-only at commit `6f35bdc`. Its OpenAPI and server routes confirm
  the exact message-submit and status-poll contract used here. No gateway repository file was changed.
- Exact staged product/config/test diff SHA-256:
  `8251ab147fcc370af42df54eca29863f613c458e71f450e0f98d41c34289c479`.
- Fresh `deepseek-free` review status `ANSWERED`, verdict `PASS`, with no P0-P2 finding or open
  question. The reviewed state fingerprint is
  `974c3a0c32d85bc6a1a872a9c196f03cb599be2b3d1c530f76ed6ba71ca3e4de`.
- The local commit is authorized by U003. Push, installation, gateway registration/configuration and
  production delivery remain outside this closure.

## Production notification activation

Authorization: U005. Scope is limited to activating the committed notification slice against the
existing `ops` / `sartulibot` gateway route and Sartuli destination.

1. **Complete — resolve installed inputs without exposing secrets.** Confirm the single existing
   Sartuli destination, locate the existing `ops` API credential, validate the controller UID, current
   health, disk headroom and rollback state.
   Resolved from the live Sartuli container: `https://tg.4u.ge`, project `ops`, chat `-5057084213`,
   thread `0`; the 64-byte secret is present and will be copied server-side without disclosure.
   Controller UID is `999`, health is green and root has 12.0 GiB free.
2. **Complete — install inactive notifier prerequisites.** Preserve the current controller/data state,
   install the two verified binaries, create the dedicated notifier identity, install the root-owned
   environment/credential and notifier unit, then start and verify the notifier before controller
   wiring.
   The installed notifier is active with zero restarts, a 1.4 MiB working set, a dedicated UID/GID,
   mode-0700 state and a mode-0660 peer-authenticated socket. The secret remains root-only and was
   copied entirely within the VPS from the live Sartuli container.
3. **Complete — activate the controller transport.** Install only the notifier drop-in while preserving
   the currently deployed base controller unit, reload systemd, restart the controller and require both
   services plus the dashboard health contract to pass.
   The first current-controller start failed closed on the legacy rimg resource socket contract. The
   previous binary was immediately restored and `/health` recovered. The committed persistent observer
   prerequisite was then installed without replacing the production base unit. Production measurement
   showed `docker stats --no-stream` requires 1.10 seconds, so the one-second subprocess deadline was
   corrected to two seconds; bare `bin/ci` and an independent `deepseek-free` review found no P0-P2
   issue. The redeployed controller, notifier and observer are active with zero restarts.
4. **Complete — verify bounded delivery and rollback readiness.** Confirm configured dashboard state,
   gateway acceptance/terminal delivery without printing message content or credentials, inspect safe
   logs/resources, and retain exact disable/restore commands and backups.
   A peer-authenticated controller-UID query returned `configured=true`. One idempotent activation event
   traversed the controller-UID protocol -> notifier outbox -> `telegram-gateway` and reached
   `delivered` after submit plus status poll, with a gateway UUID, no possible duplicate and no error
   code. Eight
   consecutive five-second rimg samples were `fresh` after the observer hotfix. Rollback controller
   binaries and consistent data snapshots remain installed at the paths recorded in `review.md`.
