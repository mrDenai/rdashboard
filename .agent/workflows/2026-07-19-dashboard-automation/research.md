# Dashboard automation research

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: complete
- Last updated: 2026-07-19

## Decision to unlock

Choose the smallest coherent production architecture and implementation scope that turns project `4` (`rimg`) from `Errors: Not configured` into a processed GlitchTip insight surface, reuses the established backup mechanism, triggers off GitHub `main` without executing deployment in GitHub, exposes important operational state in the dashboard, sends bounded Telegram notifications, and keeps local/production Docker residue controlled.

## Success criteria

- The recommendation is grounded in the current `rdashboard`, `rimg`, and relevant `sartuli.ge` implementation rather than inferred from the screenshot.
- Trust boundaries remain fail-closed: the dashboard controller cannot silently acquire root, source, deployment, backup, GlitchTip, model, or Telegram authority.
- The free DeepSeek/OpenCode route is verified from current primary documentation and integrated behind a bounded, testable contract without leaking secrets or raw sensitive error content.
- Backup behavior reuses the proven mechanism only where its operational contract actually matches.
- A push to GitHub `main` can signal deployment without GitHub-hosted deployment execution.
- The plan includes complete observable states, failure/retry behavior, Telegram deduplication, local Docker cycle validation, and deterministic cleanup.
- Anything requiring production credentials, installation, registration, external mutation, or a user-owned policy choice is isolated as a blocker while autonomous implementation can proceed.

## Constraints and boundaries

- Research is read-only apart from workflow artifacts.
- No deploy, push, external write, production credential access, or production mutation.
- Existing unrelated working-tree changes are user-owned and must be preserved.
- Repository verification must use bare `bin/ci` when implementation begins.
- Current external facts must come from primary sources.
- The first implementation slice must be production-worthy and coherent, but must not pretend external integrations are live when credentials or installation are absent.

## Evidence ledger

- The authoritative prior workflow artifacts show that the source broker/export, controller/executor
  protocol, verified backup pipeline and stable installed `rimg` deploy/rollback path are implemented
  locally. The still-missing production build-candidate producer is a real prerequisite, not a UI
  detail. The old GitHub maintenance cutover now exits as a successful no-op when the bootstrap marker
  disables that path.
- Current source confirms that `web/app.js` renders both Updates and Errors with literal
  `createUnavailableCell()` calls. Project operations, resource history and accepted-repository history
  already use bounded authenticated APIs and preserve last-known data.
- The root backup path is stronger than the older `sartuli.ge` shell implementation: `rimg` creates a
  coherent SQLite+masters snapshot and manifest; `rdashboard` validates it, encrypts it with `age`,
  uploads an immutable content-addressed object through `rclone`, independently reads the remote object
  back, compares the ciphertext digest and persists a verified chain. Reimplementation would create a
  conflicting second authority. Production currently has none of the required rimg backup policy,
  runtime, age-recipient or Drive credential files.
- The production controller and executor are active, while `rdashboard-source` is absent/inactive and
  `/etc/rdashboard/source.json` is absent. The private-source credential contract is complete only in
  local source. This matches the existing truthful Repository unavailable state.
- The source broker periodically reconciles remote `main`; HMAC verification and recorded automated
  admission exist as library contracts. The installed source process exposes neither webhook HTTP
  ingress nor a controller automation handoff. The executor also requires an exact signed candidate,
  installed mutation/runtime policy and accepted grant before its worker can deploy. A webhook alone
  cannot honestly claim dashboard-owned deployment.
- The live GlitchTip organization route
  `/api/0/organizations/4u/issues/?project=4&query=is:unresolved` is authenticated and currently returns
  an empty list. Organization project discovery confirms numeric project `4` is `rimg`. A structural
  probe against another non-empty project confirmed the bounded aggregate fields used by the Sentry-
  compatible issue API (`id`, `count`, `level`, `status`, `userCount`, `firstSeen`, `lastSeen`,
  `permalink`, `metadata`, and title/culprit fields). No event bodies or stack traces are required.
- GlitchTip's current official integration documentation says API tokens can be limited to read-only
  scopes but inherit access to every project visible to their user. Production must therefore use a
  dedicated read-only, least-privilege identity; the local operator token is evidence for the API
  contract, not a credential to install.
- OpenCode's current official Zen page lists model `deepseek-v4-flash-free` at
  `https://opencode.ai/zen/v1/chat/completions`, currently priced free for a limited period. A bounded
  local probe succeeded with `reasoning_effort=low`, JSON response format and a completion budget large
  enough to accommodate hidden reasoning. The same page states that this free model is US-hosted and
  submitted data may be collected to improve the model. Issue titles, culprit strings, paths, URLs,
  event bodies, stack traces, IDs and user data must never cross this boundary, even after regex
  redaction. Only counts, levels, recency buckets and opaque fact ranks are permitted.
- The existing `telegram-gateway` supports per-project authentication plus `event_key` and `dedup_key`.
  It is a suitable provider, but `rdashboard` currently has no typed notification outbox or isolated
  notifier. Giving the controller its gateway credential would violate the documented secret boundary.
- GitHub currently has two open Renovate dependency PRs for `rimg`, both with successful CI. A local
  source-ref view can truthfully expose candidate branches but cannot expose PR, checks, review or
  mergeability state. Meeting the stated “do not open GitHub for important state” outcome requires a
  separate least-privilege metadata/checks reader (preferably a GitHub App or equivalent short-lived
  token), not reuse of the source deploy key.
- Production `docker buildx du` reports approximately 6.431 GB reclaimable in the dedicated builder.
  The current 6 GB policy is intentional: earlier evidence shows the complete native graph makes an
  unchanged image build about 14 seconds instead of about 19 minutes, while a 1 GB ceiling evicts it.
  The exported native `/opt/4u` artifact itself is only about 76 MB locally. The root cause is retaining
  BuildKit's compilation graph instead of retaining the small verified native output as an immutable
  build input. Merely lowering the limit would trade residue for a recurring 19-minute rebuild.

## Alternatives

### A. Query providers directly from the browser

Rejected. It exposes bearer credentials, bypasses durable last-known/error states, makes AI privacy
unenforceable and prevents reliable Telegram deduplication.

### B. Copy the `sartuli.ge` backup scripts into `rimg`

Rejected. The current typed backup chain already implements the relevant stream/encrypt/offsite/verify
contract with stronger operation binding and restore evidence. The correct work is activation and
observation of that chain.

### C. Send redacted GlitchTip titles to DeepSeek Free

Rejected. Regex redaction cannot prove the absence of customer identifiers, internal hosts, paths or
confidential failure text. The model packet must be structurally incapable of containing titles.

### D. Derive Updates only from fetched `renovate/*` refs

Useful as a credential-free candidate signal, but insufficient as the final operator surface because it
cannot prove CI/review/mergeability. If implemented, it must be labelled “candidate branch; PR/check
state unknown” and include fetch staleness. The complete desired surface uses a narrow GitHub metadata
reader and never grants it source or deployment authority.

### E. Lower BuildKit GC from 6 GB to 1 GB

Rejected. It has already been shown to evict the expensive native graph. Replace the retained artifact
boundary first: persist and verify the approximately 76 MB native output, build the application against
that immutable input, then use a disposable task-specific app builder and remove it after the cycle.

### F. Build the full isolated Telegram service now

Deferred, not faked. The coherent autonomous slice can add the typed outbox, idempotency/state contract
and gateway request adapter. The separate UID/socket consumer and production route require a real
gateway project, chat allowlist and credential. Until then, notification status must be visibly disabled
and no undeliverable messages should be enqueued.

## Recommendation

Implement one local, production-shaped integration slice:

1. Add a separate durable integration store for bounded last-known Error and Update snapshots so an
   external outage does not erase useful operator state or weaken the control journal.
2. Add a fixed-origin GlitchTip aggregate collector for organization `4u`, numeric project `4`, with a
   read-only credential file, strict time/body/count bounds and local-only safe issue labels/deep links.
3. Build an AI fact packet exclusively from numeric/enum aggregates. Persist deterministic facts first,
   then call the fixed OpenCode endpoint/model asynchronously. Accept only strict bounded JSON; expose
   provider failure as `partial` with a deterministic summary rather than forwarding raw data.
4. Add a least-privilege GitHub dependency-update/check collector behind its own optional credential.
   It may expose only dependency-labelled/`renovate/*` pull requests and exact check conclusions; it
   must not imply mergeability or approval. Keep a future local-ref candidate path distinct.
5. Replace the two UI placeholders with authenticated APIs and strict browser validators covering
   loading, unconfigured, empty, fresh, stale/last-known, partial and failed states. Use textContent,
   real deep links and explicit source/age labels; no raw event dump.
6. Add the bounded typed notification outbox and Telegram-gateway request/dedup contract, but enqueue
   nothing until the isolated delivery boundary is configured. Record the missing notifier activation
   inputs as blockers.
7. Reuse the existing operation/verified-chain backup implementation and make its unavailable state
   truthful. Do not activate backup or deployment externally in this task.
8. Introduce and locally prove the smaller native-artifact build boundary before changing the 6 GB
   production policy. Run the complete local Docker candidate/health cycle with a uniquely named
   builder and image, record before/after disk evidence, and delete only task-owned artifacts.
9. Treat push-triggered dashboard deployment as blocked for production activation until source, build
   candidate, authorizer, installed policy/runtime, webhook route/HMAC and rollback inputs are all
   present. Implementing or testing a webhook-only shortcut would be misleading.

## Risks and validation

- Provider JSON is untrusted: bound body size before decode, deny unknown fields where practical,
  validate every enum/count/URL/origin and use browser `textContent` only.
- A free-model response is advisory and may disappear or change behavior. Never let it gate collection,
  deploy, backup, incident truth or notification severity; retain the input digest and deterministic
  fallback.
- Do not call the AI endpoint for an empty issue set; “no unresolved issues” is deterministic and avoids
  unnecessary data transfer.
- Preserve last-known successful data on network, authentication, rate-limit, timeout, malformed-body
  and AI failures. Distinguish source failure from AI-only degradation.
- Tests must prove issue titles/IDs/URLs do not enter the model request, pagination/count bounds hold,
  duplicate notification facts remain idempotent, update checks cannot imply unobserved state, and
  credentials never serialize to SQLite/API/logs.
- Verification is bare `bin/ci` in every changed repository, followed by focused independent review.
  Docker validation must compare `docker system df`/builder usage before and after task cleanup without
  global prune or deletion of unrelated images/caches.

## Consultation ledger

- `deepseek-free` route check: healthy (`opencode/deepseek-v4-flash-free`).
- Fresh research consultation: `CONDITIONS_MET`. Accepted findings: never send issue titles even when
  redacted; label source-ref update candidates as incomplete rather than implying CI/mergeability; add
  the typed outbox/client contract now while keeping the isolated notifier activation blocked on real
  routing credentials. The consultation's evidence was checked against source before acceptance.
