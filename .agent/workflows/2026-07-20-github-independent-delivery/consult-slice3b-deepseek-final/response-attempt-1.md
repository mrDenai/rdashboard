**VERDICT: SAFE — no P0-P2 defect found**

**P3 #1 Correction: CONFIRMED INVALID**

Both the base HEAD and the staged diff query `source_deliveries` with the full three-column filter:

- Base `src/source.rs:603` — `WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3` with `channel.as_str()` binding
- Staged `src/source.rs:688` (in `enqueue_github_wakeup`) — identical pattern with `SourceChannel::GithubWebhook.as_str()` binding

The prior observation is wrong; no correction is needed.

---

**Reasoned absence of P0-P2 defects**

| Required behavior | Evidence | Status |
|---|---|---|
| Loopback-only, credential-free ingress | HTTP binary binds `127.0.0.1:3201`; forwards body via Unix socket with peer-UID check (`source_ingress_socket.rs:548`); ingress owns no secrets | ✓ |
| HMAC + route/project/repo verification | `verify_github_hmac` constant-time (`source.rs:3882`); `decode_github_push` enforces `repository_full_name` match (`source.rs:3860`); project white-listed in HTTP handler (`source-ingress.rs:110`) | ✓ |
| Content-bound, idempotent, capped | UNIQUE(project_id, delivery_id) on `source_github_wakeups`; `DeliveryConflict` on digest mismatch; global 2048 / per-project 128 cap (`source.rs:707-721`) | ✓ |
| Preemption of periodic work | `notify_priority_fetch` increments atomic generation; `fetch_remote_main_reconciliation` checks generation + `priority_fetch_project_count` at three guard points before and during fetch (`git_repository.rs:1223-1236`); biased `select!` in `run_project_source_loop` (`source.rs:464`) | ✓ |
| 2-second network ceiling | `RECONCILIATION_FETCH_TIMEOUT = 2s` (`git_repository.rs:34`); `run_command` in `fetch_staged_main` enforces it; `reconcile_failed_fetch` cleans up on timeout | ✓ |
| One foreground fetch per project | Per-project coordination mutex (`lock_coordination`, `source.rs:2674`); global `fetch_lock` serializes foreground fetches | ✓ |
| Restart / remap / concurrent drain | `initialize_all` drains all pending wakeups before server start; `Notify::notify_one()` stores permit if no waiter; `DrainProjectWebhooks` loops until empty; `reconcile_github_wakeup_policy` retires orphaned wakeups | ✓ |
| Schema-V5 config, no secrets, systemd wiring | Config carries SHA-256 digests only; `source_uid != ingress_uid != controller_uid` enforced; `SOURCE_INGRESS_SOCKET_PATH` fixed; ingress socket permissions `0o660` | ✓ |
| No new worker/service topology | `GithubWebhookWakeupV1` uses existing delivery path; no new project-specific agents | ✓ |

The sole risk class present is the acknowledged bounded-race: a `spawn_blocking` handler that commits to DB then times out before writing the response causes duplicate retry (safe via idempotency). This is not a P0-P2 defect.

**INSPECTED**: `src/source.rs`, `src/source_ingress_socket.rs`, `src/bin/rdashboard-source-ingress.rs`, `src/bin/rdashboard-source.rs`, `src/source/git_repository.rs`, `src/installed_source.rs`, `tests/source_ingress_contracts.rs`
