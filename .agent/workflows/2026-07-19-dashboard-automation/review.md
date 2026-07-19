# Dashboard automation review

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: complete
- Reviewed: 2026-07-19
- Scope: task-owned Phase 1 changes in `rdashboard` and `rimg`
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
