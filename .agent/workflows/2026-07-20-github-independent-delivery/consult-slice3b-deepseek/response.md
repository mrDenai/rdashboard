## Inspected

- `src/source.rs` (webhook wake-up queue, schema V4, priority hooks, reconciler bridge)
- `src/source/git_repository.rs` (foreground/background fetch, atomic priority flags, generation cancellation)
- `src/bin/rdashboard-source.rs` (per-project coordinators, webhook drain, deferred retry, startup ordering)
- `src/bin/rdashboard-source-ingress.rs` (HTTP → AF_UNIX bridge, concurrency limits, header validation)
- `src/source_ingress_socket.rs` (protocol framing, peer auth, timing bounds, socket lifecycle)
- `src/installed_source.rs` (schema V5, credential loading, Zeroizing, identity validation)
- `src/bin/rdashboard-source-config.rs` (catalog-driven generation, systemd drop-in renderer)
- `tests/source_ingress_contracts.rs` (8 contracts: burst, restart, preemption, remote-visibility, etc.)
- Deployed systemd units (bridge, ingress, tmpfiles)
- `tests/source_delivery_contracts.rs`, `tests/controller_contracts.rs`, `tests/executor_recovery.rs`, `tests/source_build_contracts.rs` (fidelity edits)
- `src/lib.rs` (module wiring)

---

## Verdict

**SAFE** — No P0-P2 defect found.

---

## Findings

| # | Severity | Evidence | Consequence | Recommendation | Confidence |
|---|----------|----------|-------------|----------------|------------|
| 1 | P3 | `source.rs:673` — `enqueue_github_wakeup` checks `source_deliveries` table for duplicate delivery IDs but the delivery may be from a different channel (non-`GithubWebhook`). `reserve_delivery` in `process_pending_github_pushes` does scope by `SourceChannel::GithubWebhook`. | Non-webhook deliveries with matching delivery IDs across channels could cause a spurious `DeliveryConflict`. No security or data-loss impact since the channel check is applied at processing time. | In `enqueue_github_wakeup`, add `channel = GithubWebhook` to the `source_deliveries` SELECT. | Medium |
| 2 | P3 | `source_ingress_socket.rs:405-413` — `ensure_negotiated` creates a new request ID and exchanges; on a wrong response it calls `wrong_response()` which clears the negotiated flag. The client does not retry automatically. | A transient protocol mismatch on negotiate causes a `WrongResponse` error returned to the HTTP handler, which returns 503. The bridge/VPS layer can retry on 503. Graceful degradation. | Acceptable; add a single retry in the client if desired for future hardening. | High |
| 3 | P3 | `source/git_repository.rs:1200-1217` — `fetch_remote_main_locked` checks generation between three phases (start, after staging directories, after orphan cleanup). If a new priority webhook arrives between checks, `ReconciliationDeferred` is returned. The work already done (staging dir setup) is wasted. | At most one failed reconciliation cycle per webhook interrupt, wasting <2s of compute. No correctness impact—next tick retries. | Acceptable; avoidable only with a cancellable fetch. | High |
| 4 | P3 | `rdashboard-source.rs:183-185` — `tokio::select!` biased order ensures shutdown > wakeup > periodic tick. The `interval.tick()` in the periodic arm is never called while `reconciliation_deferred` is true (250ms sleep instead). The interval timer drift means after a deferred episode the next periodic tick may fire earlier than a full interval after the previous successful reconciliation. | Periodic reconciliation could fire slightly more frequently than the configured interval after a spate of webhooks. No correctness or availability issue. | After a successful reconciliation following deferral, skip one interval tick to re-synchronize the timer. | High |
| 5 | P3 | `source.rs:1993-1995` — `reconcile_priority_fetch_signal` clears the per-project flag, re-reads the queue, and re-signals. Between clear and re-read, a concurrent `notify_priority_fetch` from the ingress path may set the flag. The clear-then-re-signal pattern is correctly analyzed in the inline comment but relies on the SQLite serialization ordering between the ingress INSERT and the reconciler SELECT. | If the ingress INSERT commits after the reconciler SELECT but before the reconciler's re-signal, the ingress's own `notify_priority_fetch` already set the flag. No signal loss. Safe by analysis. | The comment already documents this. No action needed unless a future change removes the comment. | High |

---

## Open Questions

None. Every scenario enumerated in the task description (cross-project priority, webhook/reconcile races, restart recovery, raw-secret handling, the ≤3s periodic budget) was traced and found correctly implemented.

---

## Summary

The staged diff correctly implements:
- **Webhook admission:** HMAC verification in constant time, exact repository binding, content-bound deduplication, dual capacity limits (2048 global + 128/project), secret-free persistence.
- **Priority fetch:** Per-project atomic flag + global generation with guards in all three layers: guard check during network fetch, lock acquisition check, and post-lock revalidation.
- **Periodic cancellation:** Generation increment preempts active reconciliation fetches; the `CommandDiskGuard::check` aborts the Git child between operations.
- **Restart recovery:** `reconcile_github_wakeup_policy` retires orphan wakeups before socket bind; pending wakeups are re-signalled.
- **Secret handling:** `Zeroizing<Vec<u8>>` for all secrets; HMAC pads and inner digest zeroized; raw bytes never in logs, persisted tables, or serialized config.
- **Periodic budget:** `RECONCILIATION_FETCH_TIMEOUT = 2s` hard bound; deferred retry at 250ms; startup jitter ≤5s ensures no synchronized fetch storms.
- **Systemd isolation:** Three distinct Unix identities; `ProtectSystem=strict` on all units; no `LoadCredential=` in base source unit (generated drop-in); ingress has zero secrets, no writable paths, no Git/Docker/DB authority.

All five findings are P3 — correct by specification but worth documenting for future maintainability. **Verdict: SAFE.**
