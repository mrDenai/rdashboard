Diff verified: 17 paths, 3653 insertions, 73 deletions, SHA-256 matches. Now inspecting the critical source files.
Let me inspect the existing preparation store code for the interaction points with the new code.
**VERDICT: SAFE**

**FINDINGS**

*None.* Every defect class enumerated in the task — correctness, security, compatibility, concurrency, TOCTOU, SSRF, decompression, archive-path, cache-identity, cancellation, resource-bounding, offline-execution — is handled correctly in this diff.

**Key verified invariants:**

| Concern | How it's handled | Evidence |
|---|---|---|
| **Cancellation propagation into `spawn_blocking`** | Two-channel design: a `watch::Receiver<bool>` is checked both via `cancel.borrow()` (in `ensure_not_cancelled` between every entry/drain/hash step) and via `fetch_cancel.changed()` inside the `block_on(select!)` closure. `send(true)` wakes both paths atomically because the receiver observes the new value before or on the next `changed()` poll. The test `worker_shutdown_cancels_network_prefetch_and_removes_partial_staging` validates the exact scenario (blocked fetch → shutdown → cancellation → empty staging, no receipt). | `src/workflow_worker.rs:855-880`, `src/cargo_prefetch.rs:1433-1444` |
| **Integer arithmetic** | Every add/mul is `checked_*` ; `saturating_sub` is used for remaining-bytes/inodes; `usize::try_from` guards 32-bit targets. | `src/cargo_prefetch.rs:129-143` (budget), `src/cargo_prefetch.rs:538-544` (tar stream), `src/preparation.rs:855-857` (reserved inodes) |
| **Tar stream overhead** | 64 KiB fixed + 6144 per-inode (4096 max path + 2048 slack) — covers LongLink headers, 512-byte padding, gzip wraparound. Overhead can never dominate because `checked_mul` rejects overflow. | `src/cargo_prefetch.rs:36-37` |
| **EOF-at-exact-limit** | `BoundedReader` probes with a single byte when `remaining == 0`; `GzDecoder` returning 0 means exact fit; returning >0 means trailing data → `InvalidData` error. | `src/cargo_prefetch.rs:158-180` |
| **Archive-path safety** | Rejects NUL, backslash, absolute, `..`, non-UTF8, oversized paths, leading `/`, and entries ending with `/` for non-directories. First component must match exact `name-version` root. | `src/cargo_prefetch.rs:474-508` |
| **Checksum alias prevention** | Backslashes rejected before path → string conversion. Duplicate insertion into `BTreeMap` returns `InvalidCrateArchive`. | `src/cargo_prefetch.rs:414-417`, `src/cargo_prefetch.rs:490` |
| **Decompression bomb** | Gzip-decoded stream bounded by `maximum_tar_stream_bytes` (= payload + per-inode overhead). Declared bytes/inodes are checked during the *first* pass (`inspect_crate_archive`), not after full decompression. `BoundedReader` rejects excess on read, before `drain_archive` or extraction. | `src/cargo_prefetch.rs:270-329`, `src/cargo_prefetch.rs:158-180` |
| **DNS/route filtering** | Custom resolver accepts only `static.crates.io`; filters private, loopback, link-local, multicast, CGNAT, carrier-grade NAT, documentation, IANA reserved, and class D/E v4; ULA, link-local, documentation v6; rejects empty answer sets. | `src/dependency_fetch.rs:533-577` |
| **Peer authentication** | Fetcher server checks `peer_cred().uid()` against configured `allowed_uid` before reading any request bytes. Client checks server's `peer_cred().uid()` against `expected_server_uid` after connect, before sending request. | `src/dependency_fetch.rs:392-399`, `src/dependency_fetch.rs:261-269` |
| **Staging cleanup on failure** | `get_or_prepare_bounded_directory` removes staging via `remove_owned_tree` on producer error; `commit_stage` removes staging if commit fails; `reconcile_staging` cleans orphaned UUID directories on store open. | `src/preparation.rs:888-890`, `src/preparation.rs:1118-1119`, `src/preparation.rs:2573-2585` |
| **Cargo offline compatibility** | `cargo metadata --offline --locked` test passes against generated vendor dir with `source.rdashboard_vendor.directory` replacement, `CARGO_NET_OFFLINE=true`. Job binary writes `config.toml` to private per-job Cargo home. | `src/cargo_prefetch.rs:587-622` (test), `src/bin/rdashboard-workflow-job.rs:114-122` |
| **Systemd confinement** | Fetcher drops capabilities, has no `LoadCredential=`, `ProtectSystem=strict`, `InaccessiblePaths=` blocking credentials/CAS/launcher/container sockets, `UnsetEnvironment=` for proxies. | `deploy/systemd/rdashboard-dependency-fetcher.service` |

**OPEN QUESTIONS:** None.

**INSPECTED:**
- Full `git diff --cached` (17 files, 3653+73, SHA-256 `e1b9d99cc5fc1c6e1583b270c36cf530faae34b89fde67292d56f3ca51e8bb13`)
- `src/cargo_prefetch.rs` (full)
- `src/workflow_worker.rs` (full diff + existing `preparation.rs` interaction points)
- `src/dependency_fetch.rs` (full)
- `src/bin/rdashboard-dependency-fetcher.rs` (full)
- `src/bin/rdashboard-workflow-job.rs` (full diff)
- `src/bin/rdashboard-worker.rs` (full diff)
- `deploy/systemd/rdashboard-dependency-fetcher.service` (full)
- `deploy/systemd/rdashboard-worker.service` (full diff)
- `src/preparation.rs` (relevant sections: `get_or_prepare_bounded_directory`, `open_pinned`, `unpin_if_present`, `commit_stage`, `create_stage`, `remove_owned_tree`)
- `tests/workflow_worker_contracts.rs` (full diff)
- `src/domain/workflow.rs`, `src/lib.rs`, `Cargo.toml`, `config/schema/project-manifest-v2.json` (relevant diffs)
