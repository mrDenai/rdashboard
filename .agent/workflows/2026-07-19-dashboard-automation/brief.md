# Dashboard automation brief

- Workflow directory: `.agent/workflows/2026-07-19-dashboard-automation`
- Status: complete locally
- Last updated: 2026-07-22

## User input log

### U001 — 2026-07-19

Faithful English rendering:

Start by analyzing logs from previous chats for this repository to recover the situation. Research, then plan, implement, and perform a mandatory review of the dashboard state shown as `Errors: Not configured` for project `4` (`rimg`). GlitchTip is accessible from the repository. The required result is not a raw GlitchTip export: error data must first be processed through the free DeepSeek route whose key is already available; the relevant service is exposed through OpenCode/Zen, with `https://opencode.ai/docs/en/zen/` offered as a possibly inexact documentation pointer. Backups already work in `sartuli.ge`; reuse the same mechanism here. Deployment must not run through GitHub, but must be triggered by a push to GitHub `main`. The workflow must be fast, avoid unnecessary work, and avoid leaving gigabytes of Docker cache for an application that is only a few megabytes. The broader outcome is that GitHub should not need to be opened for important operational information and Telegram should receive notifications about everything important.

Work autonomously through the first phase: perform every safe, obvious action without asking. Do not deploy. Reproduce the entire deployment cycle locally in Docker. Record anything that requires a user decision, confirmation, credentials, or external action as a blocker in a file for later resolution. Structure the work to avoid blockers and complete all safe independent work.

Normalized constraints and authorization:

- Authorized sequence: research, plan, implementation, and mandatory review, including task-scoped local file changes and local Docker validation.
- No production deployment, push, publication, or external-system mutation is authorized.
- Project identity: dashboard project `4` is `rimg`.
- GlitchTip data must be summarized/processed through the configured free DeepSeek path before display or notification; do not expose a raw dump as the product outcome.
- Reuse the proven `sartuli.ge` backup contract where compatible.
- The desired deployment trigger is a GitHub `main` push, but deployment execution must not run in GitHub Actions.
- Surface important operational state in the dashboard and important notifications in Telegram.
- Keep execution bounded and clean up task-created Docker/build artifacts so local validation does not leave multi-gigabyte residue.
- Put user-owned or external blockers in the workflow artifact set rather than stopping safe independent work.
- Secret values must not be copied into workflow artifacts, logs, model briefs, tests, or source control.

### U002 — 2026-07-19

Faithful English rendering:

Continue.

Normalized continuation:

- Resume the same dashboard-automation task after the autonomous Phase 1 handoff.
- Continue through every safe, locally verifiable step that does not require unresolved production
  credentials, user-owned policy choices, push, deployment or external-system mutation.
- Preserve the original no-deploy and blocker-recording boundaries from U001.

### U003 — 2026-07-22

Faithful English rendering:

Even if these changes were not yours, finish them through a commit. There is another repository for
the Telegram gateway; determine whether this work relates to deploying that gateway.

Normalized authorization and question:

- Take ownership of the existing uncommitted `rdashboard` notification-delivery slice, complete its
  implementation, verification and review, and create one task-scoped local commit.
- Preserve unrelated production-workflow and GitHub-independent-delivery artifacts and do not push or
  deploy.
- Inspect the separate `telegram-gateway` repository read-only to establish whether this slice is a
  gateway client integration or includes gateway deployment responsibility.

### U004 — 2026-07-22

Faithful English rendering:

If this work sends notifications, they must be sent through the gateway. Review prior session logs if
needed to understand what was implemented.

Normalized constraint:

- Every real Telegram delivery initiated by `rdashboard` must use the separate `telegram-gateway`
  service contract. `rdashboard` must not call the Telegram Bot API directly or receive a bot token.
- Recover the earlier notification-slice intent and verification evidence before changing or closing
  the implementation.
