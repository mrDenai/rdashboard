## VERDICT: SAFE

**FINDINGS**

1. **Subordinate-ID global floor with distinct diagnostics** — P2 from prior review resolved. Every range below 65536 returns `rootless_oci_subid_layout_unsafe` with remediation "move every host subordinate-ID range above 65535". The BuildKit user's own short range returns `rootless_oci_subid_range_missing`. The activation note (`ROOTLESS_OCI.md`) documents the setuid threat explicitly. Code at `src/rootless_oci.rs:548-562` (the `< MIN_SUBORDINATE_ID_START` check), error variants at `rootless_oci.rs:275-277`. Confidence: **high** — regression test covers unrelated low ranges, global overlap, and short BuildKit range.

2. **Policy XOR coupling between adapter and contract** — At `src/workflow_launcher.rs:168-175`: `allowed_adapters.contains(WorkerOciReleaseBuildV1) != rootless_oci.is_some()`. This exactly prevents partial OCI activation and preserves native adapters with `rootless_oci: None`. Dedicated launcher test `assert_rootless_oci_policy_coupling` exercises both missing-contract and valid-contract paths. Confidence: **high**.

3. **TOCTOU integrity across all file reads** — Three-point metadata comparison (`same_file` at `rootless_oci.rs:863-872`: dev, ino, uid, gid, mode, nlink, len, mtime, mtime_nsec) applied before open, after open, and after read in `verify_tool`, `read_stable_regular`, and the config/policy paths. Combined with parent-directory root-ownership/no-write checks, this defeats swap attacks during preflight. The `nlink() != 1` rejection also prevents hard-link bypass. Confidence: **high**.

4. **Systemd/BuildKit config coherence** — Service (`rdashboard-buildkit.service`): `NoNewPrivileges=no` (required for setuid mapping helpers), `PrivateNetwork=yes` (rootlesskit `--net=host` resolves inside the isolated namespace, per documented intent), `CapabilityBoundingSet=CAP_SETUID CAP_SETGID`, `MemoryMax=4G`, no credentials/socket mounts. Config: `insecure-entitlements=[]`, `rootless=true`, `max-parallelism=1`, `cniPoolSize=0`, GC policies matching the 1.5 GiB hard boundary. All verified structurally in `verify_buildkit_config` against a hardcoded expected object (not just digest-matching). Contract test `rootless_buildkit_is_offline_separate_and_hard_bounded` asserts exact directives. Confidence: **high**.

5. **Error-to-remediation mapping completeness** — All 18 `RootlessOciError` variants have a distinct `reason_code`, a human-readable `summary` (from `thiserror`), and a concrete single-sentence `remediation`. The failure document produces canonical JCS JSON via `serde_jcs`. The `failure()` method at `rootless_oci.rs:384` assembles the three fields. Test `readiness_failure_is_canonical_and_actionable` validates the JSON shape and that remediations contain actionable instructions. Confidence: **high**.

No P0, P1, or P2 defect was found. The diff passes `cargo fmt`, `cargo clippy -D warnings`, all 7 new tests, and the existing launcher-policy coupling test.

**OPEN QUESTIONS: NONE**

**INSPECTED**: `git diff --cached` (9 files, +1540/−4), `src/rootless_oci.rs` (1272 lines), `src/workflow_launcher.rs` (validate/policy coupling/error enum), `src/workflow_worker_contracts.rs` (contract test), `deploy/systemd/rdashboard-buildkit.service`, `deploy/systemd/rdashboard-buildkitd.toml`, `deploy/systemd/ROOTLESS_OCI.md`, `deploy/systemd/rdashboard-tmpfiles.conf`, `src/bin/rdashboard-workflow-launcher.rs`, `src/lib.rs` (module gate), `src/domain/workflow.rs` (`valid_workflow_identity`), `src/domain/identifiers.rs` (`EvidenceDigest`), `Cargo.toml` (dependency verification).
