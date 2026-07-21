Now let me read the new files and the relevant context around edits.
Let me check for a few more details needed for the review.
Now let me check the key areas of the new module more carefully.
Let me check one more critical detail in the `verify_subordinate_ids` function.
Now I have all the evidence needed. Here is the review.

---

## VERDICT: NEEDS_FIX

One P2 defect requires correction before the boundary is reliable. All other findings are P3 observations.

---

## FINDINGS

**P2 — `verify_subordinate_ids` applies `start < MIN_SUBORDINATE_IDS` to every entry, not just the BuildKit user's**

`src/rootless_oci.rs:650-656` — the `start < MIN_SUBORDINATE_IDS` gate runs inside the per-line loop before the identity match at line 658. If any other user on the system has a subordinate range starting below 65536 (e.g., a legacy `newuidmap` mapping or a second container runtime), the entire check fails with `InsufficientSubordinateIds` even when the BuildKit user's range is valid. On a production VPS with only this application's entries this is unlikely, but it couples the rootless preflight to unrelated `/etc/subuid` content, creating a brittle false-negative.

**Impact:** An operator configuring `/etc/subuid` correctly for `rdashboard-buildkit` could see baffling preflight failure because an unrelated entry (e.g., from an older installation) starts below 65536.

**Recommendation:** Move the `start < MIN_SUBORDINATE_IDS` (and ideally the non-overlapping sub-range check) behind the `if identity == daemon_user || identity == numeric_uid` guard so that only the BuildKit user's entries are subject to the 65536-minimum-start constraint. The overlap check across all entries (line 663) is correct as-is — subordinate ID files must have non-overlapping ranges globally.

---

**P3 — `read_stable_regular` requires exact permission match instead of a mask**

`src/rootless_oci.rs:560` — `metadata.permissions().mode() & 0o7777 != expected_mode` rejects any file whose mode differs, even when stricter (e.g., `/etc/subuid` mode `0600` would fail the `0o644` expectation). A sysadmin locking down the subuid file would break the preflight.

**Recommendation:** Use a mask check: `metadata.permissions().mode() & 0o7777 & !expected_mode != 0`. This accepts mode `0600` when `0o644` is expected (stricter is safe).

---

**P3 — `same_file` implementation differs between `rootless_oci.rs` and `workflow_launcher.rs`**

`src/rootless_oci.rs:820-830` includes `mtime` and `mtime_nsec` in its comparison; `src/workflow_launcher.rs:2116-2124` does not. Both serve the same TOCTOU-detection purpose. An operator or future contributor comparing the two modules may incorrectly consider the rootless_oci version as the canonical one, or vice versa.

**Recommendation:** Factor the stricter version (with mtime) into a shared helper, or document the divergence.

---

**P3 — Missing high-signal tests**

1. Kernel-switch `try_exists` branches (`unprivileged_userns`, `apparmor_userns`) are not exercised. A missing `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` on an older kernel is handled gracefully but untested.
2. `decode_mountinfo_field` edge cases (truncated escape, each escape sequence) are untested.
3. No test verifies that `daemon_user` failing `valid_workflow_identity` produces `InvalidPolicy`.
4. No test exercises the `verify_subordinate_ids` path where a *non-matching* entry has `start < 65536` — this would expose the P2 finding above.

**Recommendation:** Add the listed test cases, especially #4 which guards the P2 fix.

---

**P3 — `root_available_bytes` uses `f_bavail` (conservative) rather than `f_bfree`**

`src/rootless_oci.rs:322` — `host_root.available_space()` returns `f_bavail * f_bsize`, which excludes the ext4 root-reserved 5%. The launcher runs as root and could use `f_bfree` for an extra ~600 MiB on a 12 GiB root. This is safe (conservative), but the field name `root_available_bytes` slightly overstates the conservatism.

**Recommendation:** Use `free_space()` (which returns `f_bfree * f_bsize`) for the root emergency check, or rename to `root_avail_for_unprivileged_bytes`.

---

## OPEN QUESTIONS

- Is the controlled deployment environment expected to have pre-existing subuid/subgid entries from other container runtimes? If yes, the P2 finding must be fixed before production use.
- Should a live health check be added (post-startup) to detect BuildKit socket/mount loss after the initial preflight, or is the restart-on-failure policy sufficient?

---

## INSPECTED

`src/rootless_oci.rs` (full), `src/workflow_launcher.rs` (lines 60-210, 2116-2124, 2352-end), `src/bin/rdashboard-workflow-launcher.rs` (lines 27-46), `deploy/systemd/rdashboard-buildkit.service` (full), `deploy/systemd/rdashboard-buildkitd.toml` (full), `deploy/systemd/rdashboard-tmpfiles.conf` (full), `deploy/systemd/ROOTLESS_OCI.md` (full), `tests/workflow_worker_contracts.rs` (full), `src/domain/workflow.rs` (lines 77-91, 145-207), `src/domain/identifiers.rs` (lines 109-135).
