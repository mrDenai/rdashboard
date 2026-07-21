**VERDICT: SAFE**

**FINDINGS**

1. **Waiter-creation failure → no runtime effect** (severity: NONE, confidence: HIGH)
   `src/workflow_launcher.rs:1429-1434` — `spawn_waiter` failure returns `mark_spawn_rejected` before `runtime.spawn` is reached. The `process_sender`/`receiver` pair drops and the waiter thread never starts. No process, no unit.
   *Test `waiter_failure_precedes_any_runtime_effect` asserts `spawn_count == 0`.*

2. **mark_running failure → handoff + terminate** (severity: NONE, confidence: HIGH)
   `src/workflow_launcher.rs:1448-1463` — process is sent to the waiter. On successful handoff, `runtime.terminate` stops the unit; the waiter calls `process.wait()` and records exit. On failed handoff, `contain_unowned_process` calls both `terminate` (unit stop) and `abort` (kill+wait the `systemd-run` child).
   *Test `journal_failure_after_spawn_stops_unit_and_reaps_process` asserts `spawn_count==1`, `terminate_count==1`, `wait_count==1`, `abort_count==0`.*

3. **Process handoff failure after mark_running success** (severity: NONE, confidence: HIGH)
   `src/workflow_launcher.rs:1466-1473` — `contain_unowned_process` runs both `terminate` and `abort` (eager evaluation). If the waiter thread already exited, the `systemd-run` child is killed+reaped and the unit is stopped. Journal is set to `NeedsReconcile`.

4. **Minor edge case in `contain_unowned_process`** (severity: LOW, confidence: MEDIUM)
   `src/workflow_launcher.rs:1478-1488` — `terminate` and `abort` are both eagerly evaluated, but if `terminate` returns `StopRejected`/`UnitStillActive`, the `stop?` short-circuits before `abort?` is checked. The `systemd-run` child was already killed (by the eagerly-evaluated `abort`), but the transient unit in systemd may still be active. The journal record is marked `NeedsReconcile`, so a subsequent restart/cleanup re-attempts `terminate`. This is **not a P0-P2 defect** — it is a very narrow path (requires `systemctl stop` to fail on a unit that exists), self-healing, and strictly less severe than the original P2.

**OPEN QUESTIONS**

None.

**INSPECTED**

- `src/workflow_launcher.rs` lines 1268–1342 (trait impls for `SystemdWorkflowLaunchProcessV1` and `SystemdWorkflowLaunchRuntimeV1`)
- Lines 1345–1508 (`WorkflowLaunchSupervisorV1`: `new`, `launch`, `launch_with_waiter`, `contain_unowned_process`, `cleanup`)
- Lines 2198–2312 (test helpers and five named tests)
- `git diff --cached -- src/workflow_launcher.rs` (SHA-256 `bb433bf1` — differs from the prior-review hash, but the correction logic is unchanged from the description)
