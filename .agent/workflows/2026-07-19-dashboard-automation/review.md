# Dashboard automation review

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: complete for Phases 1 and 2 plus production notification activation
- Reviewed: 2026-07-22
- Scope: task-owned Phase 1 changes in `rdashboard` and `rimg`, plus the Phase 2 isolated notifier
- Excluded: user-owned `rdashboard/.agent/workflows/2026-07-15-rdashboard-production/*`
  and `rimg/.agent/*`

## Verdict

No unresolved P0-P2 finding remains in the reviewed implementation. Production activation is not
part of this verdict: every external credential, provider registration, source ingress, notifier,
candidate-authority and deployment prerequisite remains fail-closed in the blocker register in
`plan.md`.

## Findings resolved during direct review

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| R001 | P1 | Integration freshness used `Date.now()`, violating the dashboard's trusted-server-time contract. | Reused snapshot server time plus monotonic elapsed time; the existing browser contract forbids `Date.now()`. |
| R002 | P2 | Rust integration records accepted aggregate/count combinations and integers the strict browser contract would reject. | Enforced browser-safe integers, exact group count/sums/highest level and matching record timestamps in the Rust contract; added regression tests. |
| R003 | P2 | GitHub selection relied on the API query without defensively binding PRs to `main`; paginated check-runs could be reported as passing. | Added `base=main`, validated the returned base, classified incomplete check pagination as `unknown`, and bounded the whole collector by one deadline. |
| R004 | P2 | An Errors-store failure skipped persistence of the independently collected Updates result. | Persist both results independently and log failures with the exact integration kind. |
| R005 | P2 | A deserialized notification could not rederive its dedup identity because the occurrence fact was not retained. | Persist only an occurrence digest, rederive the typed dedup key on every validation, and reject semantic tampering. |
| R006 | P2 | The initial `rimg` warm migration could bless existing mutable native bytes when the exact manifest was missing. | Missing or mismatched manifests now force a rebuild; the verified staging artifact is checked before state publication. |
| R007 | P2 | The app build did not hold the native producer lock through verification/context transfer and could hide builder-cleanup failure. | Hold a shared `.update.lock` for the full build; cleanup failure is terminal and a pre-existing builder name is rejected without deletion. |

## Independent review

- Fresh `deepseek-free` review of the final `rdashboard` scope: `PASS`, no P0-P2 findings.
- First `rimg` review: `PASS_WITH_FINDINGS`; three P2 findings were confirmed:
  the runtime copied the complete native tree before pruning, state publication preceded budget
  verification, and CI checked only the first of two 2 GB GC policies.
- The runtime now copies from a separately pruned and obligatorily stripped native stage, staging is
  fully verified before state publication, and CI requires exactly two 2 GB policy values.
- Second `rimg` review: `PASS` but noted a P2 stale/fixed builder-name collision. Automatic removal was
  rejected because it could delete a live parallel builder; the command now fails explicitly without
  calling create/remove, with a regression test.
- Third fresh `rimg` review of that final policy: `NO_ISSUES` below P2. Its informational escaping-
  symlink test suggestion was also added.

## Verification evidence

- Live read-only GlitchTip project `4` plus GitHub metadata smoke passed without printing provider
  payloads. Current unresolved GlitchTip data was empty and therefore skipped the model.
- A synthetic, structurally anonymous numeric fact packet passed the live OpenCode Zen
  `deepseek-v4-flash-free` strict JSON route. Raw title, path, email, issue ID and deep-link markers are
  absent from the model packet by deterministic test.
- Focused integration, notification, store/API, browser syntax and shell contract tests passed after
  every review fix.
- Final native artifact: 76,461,440 bytes, 1,336 entries, exact manifest fingerprint
  `4bfaf4935862ac1ba47ec1b96be907f2cb1d9952af1d5973b015822b1b66fccd`.
- Final local runtime image: 49,851,164 bytes (down from 63,879,990 bytes before the prune/strip review
  fix). A network-less, read-only container completed migration and the built-in healthcheck.
- The task image, smoke container, app builder and newly pulled unused BuildKit service image were
  removed. Docker images returned to 35 / 27.99 GB and Build Cache remained 4.975 GB; no global prune
  or unrelated deletion ran.
- `rimg` bare `bin/ci`: passed in the final post-review rerun.
- `rdashboard` bare `bin/ci`: passed in the final post-review rerun.

## Visual verification limitation

The required in-app Browser control surface was not exposed in this session, so a live visual
viewport pass could not be run without violating the browser-skill routing contract. Deterministic
browser tests still cover safe DOM updates, centralized live regions, trusted-time aging, strict API
decoding and focus-visible link semantics. This is a QA limitation, not permission to claim a visual
inspection.

## Remaining activation boundary

Blockers B001-B009 in `plan.md` remain open. In particular, no service credential or Telegram
destination was installed, no message was enqueued, no GitHub webhook/source deploy key was
registered, `auto_deploy` remains disabled, production still uses the legacy Dockerfile, and no push,
deployment, service restart, provider write or production cache deletion occurred.

## Rollback

- `rdashboard`: remove the three optional provider drop-ins and revert the task commit; the base
  service remains startable without integration credentials and the separate `integrations.sqlite`
  does not participate in controller authority.
- `rimg`: keep `config/deploy.yml` on the legacy Dockerfile (the current state) and revert the task
  commit. `.titanium/opt/4u` is a local reproducible artifact and can be regenerated with `bin/update`;
  no production candidate path was activated.

## Phase 2 isolated notification-delivery closure

### Reviewed target

- Baseline HEAD: `c6a71f036b0093ca5741f98ebe96495c1851edeb`.
- Exact staged product/config/test diff SHA-256:
  `8251ab147fcc370af42df54eca29863f613c458e71f450e0f98d41c34289c479`.
- Scope: 19 paths, 4,302 insertions and 227 deletions. It contains the dedicated notifier binary,
  delivery worker, peer-authenticated socket, deterministic planner, restart-safe notification store,
  atomic controller handoff, authenticated dashboard projection, systemd contract and tests.
- Excluded: the dirty production workflow under `.agent/workflows/2026-07-15-rdashboard-production`,
  the GitHub-independent delivery workflow and consultation scratch directories.

### Gateway contract and deployment boundary

Read-only inspection of `/home/denai/RustroverProjects/telegram-gateway` at `6f35bdc` confirmed that
`POST /api/v1/messages` accepts the staged request fields and returns a gateway UUID, while
`GET /api/v1/messages/{uuid}?project_id=...` exposes the asynchronous state used by the delivery
worker. `rdashboard-notify` fixes the production origin to `https://tg.4u.ge`, disables redirects,
bounds time and response bytes, and reads only the per-project gateway bearer credential through
systemd. No `rdashboard` notification path calls the Telegram Bot API or accepts a bot token.

This commit is a client and isolation boundary only. It does not register a gateway project, choose a
chat/thread, install a credential, change the `telegram-gateway` repository, deploy that service or
activate notifier delivery.

### Findings and dispositions

1. Earlier review P2 findings for indistinguishable handoff-capacity backpressure and the
   accepted-submit/local-bind-failure crash window are fixed. The controller emits a distinct bounded
   capacity diagnostic, and the regression proves an expired unbound send becomes a possible
   duplicate rather than false clean delivery.
2. Final direct contract comparison found the request serialized an empty `format`, which the current
   gateway implementation tolerated as plain text but its OpenAPI does not declare. The request now
   sends explicit `format=plain`, validation requires it and the contract test pins it.
3. No direct Telegram client, bot token, privilege leak, event-loss path or unresolved P0-P2 finding
   remains in the reviewed scope.

### Verification

- Final bare `bin/ci`: passed, exit code 0.
- Covered formatting, strict Clippy, 301 active library tests with two credentialed live-provider tests
  ignored by design, all binary/integration/socket/scheduler suites, nine browser tests and the
  optimized release build.
- Release build completed in 5 minutes 11 seconds.
- `git diff --cached --check`: passed.

### Independent consultation

- Route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`.
- Status: `ANSWERED`, one attempt, CLI `1.18.3`, 43 seconds.
- State fingerprint: `974c3a0c32d85bc6a1a872a9c196f03cb599be2b3d1c530f76ed6ba71ca3e4de`.
- Brief SHA-256: `6ba23a2625d995cee67aee477673dc1a9e9a14f109eac72aa2955b91bef74a2b`.
- Response:
  `.agent/workflows/2026-07-19-dashboard-automation/consult-phase2-20260722-final/response.md`.
- Verdict: `PASS`, no P0-P2 finding and no open question.

### Verdict and residual activation risk

Phase 2 is production-worthy as an inactive local implementation and may be committed. Actual delivery
remains fail-closed until a dedicated gateway project, reviewed destination, notifier UID, environment,
per-project gateway credential, binary and systemd units are installed. No gateway or rdashboard
deployment, push, service change, credential write or provider call was performed.

## Production notification activation review

### Verdict

Production notification delivery is active and verified through the existing `ops` / `sartulibot`
gateway route. The controller never received the gateway secret. `rdashboard.service`,
`rdashboard-notify.service` and `rdashboard-observer.service` are active with zero restarts, and the
loopback health endpoint is green. No unresolved P0-P2 finding remains in the activation scope.

### Installed route and isolation

- Gateway origin/project: fixed `https://tg.4u.ge`, existing project `ops` and bot `sartulibot`.
- Destination: the exact live Sartuli destination, chat `-5057084213`, thread `0`.
- The existing 64-byte gateway API secret was copied inside the VPS from the live Sartuli container
  directly to root-owned mode-`0600` `/etc/rdashboard/credentials/telegram-gateway-secret`; it was not
  printed, downloaded or added to controller configuration.
- `rdashboard-notify` has its own system UID/GID, owner-only state and a mode-`0660`
  peer-authenticated Unix socket. The controller receives only the notifier group and socket path.
- The production base `rdashboard.service` was preserved. Only the notifier drop-in was added.

### Activation incident and resolution

The first current-controller start failed closed with `InvalidRimgResourceSocket`: production still
had the legacy `/run/rdashboard/rimg-resources.sock` provider, while the current committed controller
accepts only the persistent observer socket. The previous controller binary was restored immediately,
the notifier drop-in was removed from the active unit, and `/health` recovered before further work.
No database restore was required and no data was lost.

The committed persistent observer prerequisite was then installed using the hardened repository unit
plus a narrow `ExecStart` override for the existing `/usr/libexec/rdashboard` production layout. A
second consistent data snapshot was taken before the successful current-controller start. This exposed
a separate production defect: the fixed `docker stats --no-stream` command takes 1.10 seconds on this
host and was deterministically killed by the one-second subprocess deadline. `docker ps` and
`docker inspect` each measured 0.10 seconds. The observer deadline is now two seconds while the outer
request deadline remains four seconds; the error text and systemd documentation were updated with it.

Bare `bin/ci` passed after the timeout correction and again after the regression assertion; the final
run exited 0 and covered 301 active
library tests, all binary/integration/socket/workflow suites, nine browser-contract tests and release
build. The final test pins the two-second subprocess deadline and requires the four-second request
deadline to remain larger. Fresh `deepseek-free` consultation returned dispatcher status `ANSWERED`,
verdict `SAFE`, no P0-P2 finding and no open question at state fingerprint
`9daa13aa95d773bd9f4ce5c93fd03ca82ffbea617e3db008ae93a9c745762c42`. Direct review also retains one
P3 observation: three independently two-second-bounded Docker commands have a six-second theoretical
sum; the unchanged four-second request deadline still fails that case closed, and measured production
latency is 1.30 seconds total.

### Live verification

- Installed artifact SHA-256 values:
  - controller: `a322615fb8d5dcf87a3cc9d279e25ea5dc9999ed35dd97e94dde2e6b7099fa60`;
  - notifier: `df40683b204fe1b48d96dabec422751d8a786c5d88f79865f42072f19dd11989`;
  - corrected observer: `d00c205e3befc5952306222f6ef1c234ae40704fc5e88fc2f8540759e6725c8b`.
- A controller-UID peer request to the installed notifier returned `configured=true` for `rimg`.
- One stable, idempotent activation event was accepted by the notifier and reached terminal
  `delivered` after two attempts (gateway submit plus status poll), with a gateway UUID, no possible
  duplicate and no error code. Neither message text, UUID nor credential was emitted to verification
  logs.
- After the observer correction, at least eight consecutive five-second SQLite resource samples were
  `fresh`; the earlier observer warning stopped. Current controller/notifier/observer memory was about
  19/5/7 MiB respectively.
- The pre-existing repository observation warning (`executor ... InternalFailure`) remains outside this
  notification activation and was not hidden or reclassified.

### Rollback evidence

- Latest consistent pre-current-controller data snapshot:
  `/var/lib/rdashboard-backups/pre-current-ee7aa06-20260721T223412Z`.
- Earlier pre-attempt snapshot:
  `/var/lib/rdashboard-backups/pre-notifier-ee7aa06-20260721T222638Z`.
- Previous controller binaries:
  `/usr/libexec/rdashboard/rdashboardd.prev-ee7aa06` and
  `/usr/libexec/rdashboard/rdashboardd.prev2-ee7aa06`, both SHA-256
  `53474403a072596704d48247f09aee1ea17705f7a0a9b60e8b4f8abca88ff425`.
- Previous one-second observer:
  `/usr/libexec/rdashboard/rdashboard-observer.prev-1s-ee7aa06`.
- Previous legacy rimg fixed environment:
  `/usr/lib/rdashboard/rdashboard-rimg-health.env.prev-ee7aa06`.
- Notification planning can be disabled without touching its credential or outbox by moving only
  `/etc/systemd/system/rdashboard.service.d/rdashboard-notifier.conf` out of the drop-in directory,
  reloading systemd and restarting the controller. A full controller rollback must stop the service,
  restore the previous binary and legacy fixed environment, disable that drop-in, and restore the
  latest consistent data snapshot only if the old binary rejects the migrated stores.
