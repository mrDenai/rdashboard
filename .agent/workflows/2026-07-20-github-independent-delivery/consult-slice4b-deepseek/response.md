Now let me verify a few specific details in the existing domain code to cross-reference my findings:
Now let me verify one more potential issue - the `SystemdWorkflowLaunchProcessV1` Drop semantics:
Thank you. I have now examined every line of the staged diff. Here is my verdict.

---

## VERDICT: CONDITIONALLY SAFE — one P2 defect requiring fix before activation

**SAFE** for the intended repository-agnostic, inactive staging purpose. The design, state machine, TOCTOU protections, grant chain, path derivation, and sandbox construction are thorough. However, one concrete resource-bounding defect exists and must be fixed before the slice is activated (i.e., before the worker loop or live runtime drill is added). No P0 or P1 found.

---

### FINDINGS

**P2 — Orphaned child process on journal-write failure after spawn success**
*File:* `src/workflow_launcher.rs:1387–1397` and `:1405–1424`

In `WorkflowLaunchSupervisorV1::launch`, if `runtime.spawn()` succeeds but `journal.mark_running()` fails (I/O error, `PathChanged`, state race), the code calls `drop(process)` at line 1395. `SystemdWorkflowLaunchProcessV1` wraps `std::process::Child` with **no `Drop` impl and no `kill` method** on the trait. Dropping `Child` on Linux **does not terminate the child**. The orphaned `systemd-run` continues running its transient unit, consuming CPU/memory up to the lease `timeout_ms` (RuntimeMaxSec), *and* the journal state is `NeedsReconcile`, creating an inconsistency where the record says "unknown" but the process runs.

A second path exists: if the waiter `thread::Builder::new().spawn(move || ...)` fails (line 1405), `process` is moved into the closure, the closure is dropped, and the `Child` is orphaned identically. The journal gets `NeedsReconcile` (line 1419) but the orphan runs unbounded.

*Consequence:* Resource leak (CPU, memory, PID) bounded by lease timeout but violates invariant that journal state reflects runtime state. Could accumulate if spawn succeeds repeatedly but journal writes fail transiently.

*Recommendation:* Add a `fn kill(self: Box<Self>) -> Result<(), ...>` to `WorkflowLaunchProcessV1`, implement it for `SystemdWorkflowLaunchProcessV1` via `self.child.kill()`, and call it in both error paths before dropping. Alternatively, add a `Drop` impl that sends SIGTERM. This is safe because the journal already records `NeedsReconcile`, so the next reconciliation will clean up any killed unit via `systemctl stop` + `reset-failed`.

---

**P2 — Orphaned on waiter thread-pool exhaustion** (same root cause as above, covered by same fix)

---

**P3 — Grant verification order**
In `AuthorizedWorkflowLaunchV1::authorize` (launcher.rs:220–228), `preparation_reader.open_entry()` is called **before** `grant_verifier()?.verify()`. This means a valid preparation with an invalid grant causes unnecessary I/O against the sealed preparation store. No security consequence (the entry is read-only and already validated), but the grant should be verified first to fail fast. Consider swapping the order: verify the grant, then look up the preparation.

---

### ASSERTIONS THAT HELD UNDER REVIEW

| Concern | Result |
|---|---|
| Unprivileged worker escaping fixed launch policy | **Blocks.** Peer-UID check on socket, grant binds exact lease, launcher derives all argv/properties from root-owned policy |
| Substituting lease/input/path/adapter/systemd property | **Blocks.** Grant includes lease digest, payload validated, `transient_unit_arguments` is derived exclusively from policy + validated lease; no worker-supplied string reaches argv |
| Replaying or extending a grant | **Blocks.** Nonce, TTL ≤60s, key lifecycle, lease binding, re-validation of grant at each `accept`; expiry checked with `now_ms >= expires_at_ms` |
| Executing twice across renewal/restart | **Blocks.** `accept` finds existing record by exact `(lease_id, generation)` path; `same_execution_as` check prevents identity mismatch; startup converts `Accepted`/`Running` to `NeedsReconcile` |
| Losing cleanup debt | **Tombstone.** `begin_cleanup` creates a `CleanupPending` record if the directory is missing; `finish_cleanup` is idempotent (`Cleaned` state guard) |
| Peer-authentication gap | **Blocks.** `serve_launcher_connection` reads `peer_cred()` before any decode and rejects UIDs other than `allowed_uid` |
| TOCTOU on credential/policy | **Mitigated.** `read_signing_key` stats before open, re-stats after open, re-stats after read; checks nlink==1, dev+ino identity, same metadata across all three probes. Same pattern for policy file |
| Legacy lease replay | **Blocks.** `required_source_identity()` and `required_input_artifacts()` return `MissingLease*` errors for pre-existing leases lacking these fields; propagates as `UnsupportedLease` |
| `allowed_adapters` bypass | **Blocks.** Policy enforces sorted duplicate-free list; launcher verifies adapter both in `validate_launcher_lease` and `adapter_argument`; `WorkerHostPrepareV1` intentionally absent |
| Systemd property injection | **Blocks.** All property values come from `u32`/`u64` integers or `UUID` hex strings; `prepared_run_path` is digest-derived and validated as a sealed entry path |

---

### INSPECTED

`git diff --cached`: all 19 paths, 5,094 insertions, 78 deletions. Read every line of the 2,407-line `workflow_launcher.rs` (both diff and final file), `workflow_execution_grant.rs` (665 lines), `workflow_execution_authority.rs` (197 lines), `workflow_launcher_socket.rs` (902 lines), all binary entry points, all test files, all systemd units, all deployment docs. Cross-referenced `same_execution_as`, `execution_identity_digest`, `validate`, `lease_generation != 0`, and `WorkflowLeaseV1::validate()` in the existing domain file.

---

### OPEN QUESTIONS

1. Should the `WorkflowLaunchProcessV1` trait gain a `kill()` method (as recommended above), or should a `Drop` impl sending SIGTERM be preferred? The trait approach preserves testability (`ControlledProcess` can no-op); the `Drop` approach is simpler but harder to test.
