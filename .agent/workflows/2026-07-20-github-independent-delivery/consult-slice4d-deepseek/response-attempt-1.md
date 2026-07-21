Let me now read the actual staged files and trace the key concerns.
Now let me examine the `inspect_sealed_payload` and verify the basename isolation boundary.
**VERDICT: SAFE**

**FINDINGS** (none above P3)

| Severity | Count |
|---|---|
| P0 | 0 |
| P1 | 0 |
| P2 | 0 |
| P3 | 1 |

**P3 — `validate()` in `PinRecordV1` rejects `protected_keys` containing the primary `key` before the sort-dedup invariant is established**
`src/preparation.rs:2757`
The validator checks `self.protected_keys.iter().any(|key| key == &self.key)` and adjacent `windows(2)` ordering. These invariants are established by the caller (`new()` sorts and dedups at lines 2737-2738). If a future code path constructs `PinRecordV1` without calling `new()` (e.g., deserialization), the validator would catch the violation. This is architectural hygiene, not a live defect — all current constructors go through `new()`. No recommendation needed.

**OPEN QUESTIONS** None.

**INSPECTED**
- Full staged diff for all 5 paths
- `src/preparation.rs`: `PreparedRunCompositionV1` (lines 159-253, 427-506), `open_pinned` (887-932), `validate_entry`/`validate_sealed_entry` (1228-1243, 1667-1696), `evict_until_admissible`/`remove_entry` (1154-1208, 1443-1495), `live_pinned_keys` (1534-1547), `write_pin` (1549-1567), `PinRecordV1` (2706-2797), `reserve`/`commit_stage` (1061-1152), `collect_sealed_entries`/`inspect_sealed_payload` (2188-2249), `read_trusted_file` (2432-2470), `encode_relative_path`/`decode_relative_path` (2264-2279), `input_identity` (1849-1857)
- `src/bin/rdashboard-workflow-job.rs`: `main`, `copy_prepared_workspace`, `copy_regular_file`, `same_file`, `validate_read_only_root`, `validate_fixed_script`, `create_private_job_directory`, tests
- `src/workflow_worker.rs`: `prepare_source_tree` (73-181), `SourceTarInventoryV1` (1205-1365), `decode_tar_path` (1387-1412), `PreparedSourceInputV1` (214-219), test for basename isolation (2117-2139)
- `src/workflow_launcher.rs`: `authorize` (209-254), `transient_unit_arguments` (1911-2003), `PreparedRunMismatch` check, test for policy mismatch

**TECHNICAL RATIONALE**

**Eviction/pin race (P0 concern):** The execution path in `open_pinned` holds `commit_lock` throughout entry validation and `write_pin`. The only production caller of `remove_entry` is `evict_until_admissible`, which is always invoked under `commit_lock` (via `reserve`). Without `commit_lock`, no entry can be deleted while `open_pinned` runs. After the pin lands, `live_pinned_keys` propagates `protected_keys`, so `evict_until_admissible` skips the referenced source and dependency.

**TOCTOU in workspace copy:** `copy_prepared_workspace` captures `before` metadata via `symlink_metadata`, then `copy_regular_file` re-stats after `File::open` and again after `io::copy`, comparing all six identity fields (dev, ino, uid, gid, mode, nlink, len). Any file substitution, growth, or symlink injection between stat and read is detected.

**Basename collision:** `prepared_run_composition` enforces that every manifest entry is either the composition file itself or under `source/`. Repository files with the same basename are therefore always under `source/` and isolated from controller metadata. The test at `workflow_worker.rs:2117-2139` confirms a tar entry named `.rdashboard-prepared-run.jcs` passes through correctly.

**Key separation:** `generated_input_digest` is now `sha256(JCS(PreparedSourceInputV1{...}))` instead of a bare `policy_digest`, giving the composite PreparedRun layout a different content-address from the source-only Slice 4c layout. Legacy non-composite V1 pins decode without `protected_keys` (the field is `#[serde(default)]`), and their upgrade is permitted only when the new pin validates.

**Archive extraction injection:** `decode_tar_path` rejects absolute paths, `..`/`.` components, null bytes, and trailing-slash/non-directory mismatches. `SourceTarInventoryV1::extract` re-validates every entry against the inspect-time inventory, catching archive replacement between the two passes.
