GOAL
Decide whether the final exact staged Slice 4e product diff is safe and correct to commit as the
inactive Cargo.lock/crates.io dependency-preparation boundary for the repository-agnostic worker.

QUESTION
Does the exact staged product diff contain any concrete P0, P1 or P2 correctness, security,
compatibility, concurrency, TOCTOU, SSRF, decompression, archive-path, cache-identity, cancellation,
resource-bounding or offline-execution defect? Return SAFE if none exists. Otherwise cite the exact
path/symbol, executable failure scenario, severity and smallest coherent fix. Keep style-only notes P3.

EXACT REVIEW BOUNDARY
- Review only `git diff --cached -- . ':(exclude).agent/workflows/**'`.
- It must contain exactly 17 paths, 3653 insertions and 73 deletions with binary-diff SHA-256
  `e1b9d99cc5fc1c6e1583b270c36cf530faae34b89fde67292d56f3ca51e8bb13`.
- The paths are Cargo.lock, Cargo.toml, config/project-manifests/README.md,
  config/schema/project-manifest-v2.json, deploy/systemd/README.md,
  deploy/systemd/rdashboard-dependency-fetcher.service, deploy/systemd/rdashboard-worker.service,
  src/bin/rdashboard-dependency-fetcher.rs, src/bin/rdashboard-worker.rs,
  src/bin/rdashboard-workflow-job.rs, src/cargo_prefetch.rs, src/dependency_fetch.rs,
  src/domain/workflow.rs, src/lib.rs, src/preparation.rs, src/workflow_worker.rs and
  tests/workflow_worker_contracts.rs.
- Ignore workflow artifacts and unrelated unstaged notification work. Do not review a broad worktree
  diff. Do not edit files, access secrets or `.env`, run services/jobs, contact providers or mutate
  external state.

INTENDED CONTRACT
- The main worker is networkless, shared across repositories and uses one bounded sealed preparation
  store. Only a separate unprivileged fetcher can use the network. Its peer-UID-authenticated Unix
  protocol accepts validated `(crate name, version, SHA-256)` identities and constructs only
  `https://static.crates.io/crates/{name}/{name}-{version}.crate`.
- Redirects and proxies are disabled. A custom resolver accepts only the fixed hostname and filters
  private, loopback, link-local, documentation, reserved and multicast routes. TLS, request time,
  content length, streaming length and archive digest are checked. The fetcher has no source, CAS,
  controller, launcher, credential or container-socket access and is systemd resource-bounded.
- Cargo.lock is bounded to 8 MiB/version 4 and may contain only local workspace packages plus
  checksum-pinned packages from the two canonical crates.io index identities. Git, alternate registry,
  missing checksum, duplicate name/version, malformed identity and more than 4096 packages fail before
  fetch. Lock digest, canonical package-plan digest, platform, workflow policy and vendor layout bind
  the DependencySnapshot key and canonical manifest.
- The worker rechecks every archive digest, then inventories and extracts only the exact name-version
  root. Absolute/traversal paths, literal backslashes, NUL/non-UTF8/oversized paths, duplicate paths,
  root substitution, links, special entries, reserved checksum injection, unsafe modes and byte/inode
  overrun fail closed. Cargo checksum JSON is generated from the exact extracted file bytes.
- The gzip-expanded tar stream itself is now bounded by remaining payload bytes plus checked per-inode
  tar/path overhead and a small fixed envelope. Declared file bytes/inodes are rejected during the first
  pass, not after full decompression. Inventory explicitly drains each entry through a bounded buffer;
  extraction and trailing-stream validation use the same bound. Cancellation is checked before/after
  fetch, between entries/directories and every 128 KiB while inventorying, extracting and hashing.
- Matching typed keys single-flight into one immutable vendor snapshot; warm replay makes no network
  call. Temporary source/dependency pins prevent pressure eviction across DependencySnapshot and
  PreparedRun commits. Shutdown or lease loss cancels work, removes CAS staging and never emits success.
- The transient job is networkless, credentialless and receives sealed source/dependencies read-only.
  It validates the dependency manifest, uses a private Cargo home, fixed highest-precedence source
  replacement and offline mode, and executes only a fixed installed adapter path in bounded job state.
- `source_tree_v1` still works without a fetcher. Missing fetcher, unsupported preparation and all
  preparation failures produce deterministic failed receipts and complete cleanup rather than expiry.

SELF-REVIEW CORRECTIONS THAT INVALIDATED THE FIRST REVIEW
- An initial review of product hash
  `ef9fee21059f9611e724f3818613e502899632c2eb28267e245402051170f789` returned SAFE. Do not reuse it.
- Subsequent self-review found that `src\\lib.rs` and `src/lib.rs` could collapse to one generated
  checksum key because backslashes were rewritten after filesystem-path validation. The final diff
  rejects literal backslashes and also rejects duplicate checksum-map insertion.
- It also found that a checksum-valid, highly compressed archive could force decompression of excessive
  trailing tar data before the final payload budget rejected it. The final diff adds `BoundedReader`,
  early declared-byte/inode accounting, bounded explicit entry/trailing drains and synchronous
  cancellation through archive processing.
- Inspect these corrections adversarially. In particular check integer arithmetic, tar header/path
  overhead assumptions, EOF-at-the-exact-limit behavior, legitimate Cargo archive compatibility,
  cancellation propagation from the Tokio watch receiver into `spawn_blocking`, and cleanup semantics.

VERIFICATION
- Base HEAD: `3a3e42633b2611ab90caa1759b4b0bde572063d4`.
- `git diff --cached --check` passed.
- A `git checkout-index` export of this exact final staged tree passed bare `bin/ci`: formatting,
  Clippy with warnings denied, 223 active library tests with two credentialed live-provider tests
  ignored, every binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser
  contracts and the optimized release build. Release completed in 3 minutes 20 seconds.
- New regressions prove backslash/slash checksum aliases are rejected, a 2 MiB gzip-expanded trailing
  stream cannot pass a 64 KiB payload/16-inode envelope, and cancellation interrupts archive processing
  before manifest publication. Real `cargo metadata --offline --locked` still accepts the generated
  vendor source; the current repository lockfile still parses; existing one-fetch replay, pressure-pin,
  peer-authentication, fixed-route, public-address, Cargo-job and systemd contracts still pass.
- No live dependency fetch occurred. No unit/job was started, no VPS/provider/GitHub state changed, and
  no push or deployment occurred.

INSPECT FIRST
- `git diff --cached -- src/cargo_prefetch.rs`
- `git diff --cached -- src/workflow_worker.rs`
- `git diff --cached -- src/dependency_fetch.rs`
- `git diff --cached -- src/bin/rdashboard-dependency-fetcher.rs src/bin/rdashboard-workflow-job.rs`
- `git diff --cached -- deploy/systemd/rdashboard-dependency-fetcher.service deploy/systemd/rdashboard-worker.service`
- Existing preparation-store, launcher, lease and systemd code may be read only as needed to trace the
  exact staged interactions.
