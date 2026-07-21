**VERDICT: SAFE**

No P0-P2 defects found. The boundary correction is implemented coherently and the full slice satisfies every enumerated requirement.

---

### FINDING 1 (P3 — operability)
**Stale `WorkerNativeReleaseBuildV1` dead code paths remain in committed base**
- **Evidence:** `src/workflow_launcher.rs:1907`, `src/scheduler.rs:1445`, `src/workflow_execution_grant.rs:300`, `src/operation_state.rs:1726`
- **Consequence:** A lease carrying `WorkerNativeReleaseBuildV1` would be admitted by the launcher's gRPC cleanup validation but could never be launched — `transient_unit_arguments` and `adapter_argument` both reject it. No runtime or security impact: the policy's `allowed_adapters` validation and the job binary both exclude it.
- **Recommendation:** Remove the variant and its references in a dedicated cleanup slice.
- **Confidence:** High

---

### FINDING 2 (P3 — correctness/operability)
**`make_tree_trusted_private` iterates with a second `read_dir` after the first validation**
- **Evidence:** `src/rootless_oci_build.rs:1340-1357` — `validate_rootless_oci_build_output` (at line 1109) opens/reads every file, then `make_tree_trusted_private` re-reads the directory to chown. After the sandbox process has exited and the transient unit is stopped, no build-UID process can race this window.
- **Consequence:** A harmless second directory scan. If the store's host filesystem were under pathological concurrent modification from a privileged process (unlikely given the exclusive file lock on the store), a file created between the two scans would skip the owner/mode hardening.
- **Recommendation:** Accept as-is; the exclusive file lock + process-exit guarantee make this theoretical only.
- **Confidence:** Medium

---

### FINDING 3 (P3 — correctness)
**`remove_tree` rejects device/socket/FIFO entries with `InvalidStore`, blocking cleanup**
- **Evidence:** `src/rootless_oci_build.rs:1371-1398` — only symlinks (rejected), directories (recursed), and regular files with `nlink == 1` (removed) are handled; any other type causes an `Err`.
- **Consequence:** If a rogue tar entry or malfunctioning BuildKit produced a non-regular file in the staging directory, `discard` / `reconcile` cleanup would abort, leaving debris that requires manual removal. The fail-safe prevents accidental removal of unexpected types but trades automatic recovery for safety.
- **Recommendation:** Accept as a deliberate safety trade-off. Add a test confirming that non-regular staging content fails closed rather than silently propagating.
- **Confidence:** High

---

### OPEN QUESTIONS: NONE

The implementation satisfies all enumerated constraints:

- **Request mode 0o444 + root-only 0o700 store + individual BindReadOnlyPaths** makes the request readable by the sandbox build UID without exposing mutation or host-file-system traversal (FINDING 1 of the task context resolved).
- **All request-mode creation/prepare/reconcile/discard/promote/stable-open sites** are consistent — `SANDBOX_REQUEST_FILE_MODE` = `0o444`, all output files stay at `0o400`, directory at `0o700`.
- **Build UID cannot publish unverified bytes** — root re-validates every file and the full OCI graph in `promote()` with TOCTOU-safe `read_stable_file` / `open_validated_output_archive` / `same_file` triple-check.
- **No crash/replay turns failure into success** — promotion failure forces `exit_code = 1` and sets `failure_digest`; journal terminal validation requires `output_digest.is_some() ↔ succeeded`.
- **BuildKit argv fixed** — `--frontend=dockerfile.v0`, no `--allow`/`--secret`/`--ssh`/registry/cache; `# syntax=` rejected pre-buildctl; every base maps to an authorized local OCI layout.
- **Operation state excluded** — `adapter_uses_operation_state` returns false for `WorkerOciReleaseBuildV1`; the transient unit omits the `/operation` bind; the scheduler test confirms OCI + verification run in parallel.
- **Resource bounds enforced** — distinct BuildKit filesystem (1.5-2.5 GiB, 50k-500k inodes), operation state (6-8 GiB), OCI result store (4-6 GiB, 10k-100k inodes, 12 GiB root reserve, 3 GiB archive ceiling, 256 entries, 100k tar entries).
