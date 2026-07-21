GOAL
Decide whether the exact staged Slice 4e product diff is safe and correct to commit as the inactive,
fixed Cargo.lock/crates.io dependency-preparation boundary for the repository-agnostic workflow worker.

QUESTION
Does the exact 17-path staged product/config/test diff contain any concrete P0, P1, or P2 correctness,
security, compatibility, concurrency, TOCTOU, SSRF, archive-extraction, cache-identity, cancellation,
resource-bounding, or offline-execution defect? Return SAFE if no such defect exists. Otherwise cite the
path and symbol, give an executable failure scenario and severity, and propose the smallest coherent
fix. List low-value style suggestions only as P3.

REVIEW BOUNDARY
- Review only this command's output:
  `git diff --cached -- . ':(exclude).agent/workflows/**'`
- The exact reviewed path manifest is:
  - `Cargo.lock`
  - `Cargo.toml`
  - `config/project-manifests/README.md`
  - `config/schema/project-manifest-v2.json`
  - `deploy/systemd/README.md`
  - `deploy/systemd/rdashboard-dependency-fetcher.service`
  - `deploy/systemd/rdashboard-worker.service`
  - `src/bin/rdashboard-dependency-fetcher.rs`
  - `src/bin/rdashboard-worker.rs`
  - `src/bin/rdashboard-workflow-job.rs`
  - `src/cargo_prefetch.rs`
  - `src/dependency_fetch.rs`
  - `src/domain/workflow.rs`
  - `src/lib.rs`
  - `src/preparation.rs`
  - `src/workflow_worker.rs`
  - `tests/workflow_worker_contracts.rs`
- Ignore all workflow-documentation files and unrelated unstaged notification work. Do not review a
  broad worktree diff or treat those unrelated changes as part of this slice.

CONSTRAINTS AND INTENDED CONTRACT
- Do not edit files, run services, access secrets, read `.env`, contact crates.io or another provider,
  or mutate external state. Existing source may be read only as needed to trace the staged behavior.
- This slice remains inactive. It does not install/start units, execute a repository job, fetch a live
  crate, deploy, mutate the VPS, push, or contact GitHub/providers.
- The main worker remains networkless and repository-agnostic. Only the separate unprivileged
  dependency-fetcher has network access. It accepts validated `(name, version, SHA-256)` package
  identities from the worker over a peer-UID-authenticated Unix socket and constructs the sole fixed
  `https://static.crates.io/crates/{name}/{name}-{version}.crate` route itself.
- The fetcher disables redirects and proxy environment use, uses a custom resolver that accepts only
  `static.crates.io`, filters private/loopback/link-local/documentation/reserved/multicast addresses,
  validates TLS for the fixed hostname, bounds one response at 64 MiB, and verifies its checksum.
  It cannot read source exports, CAS/controller/launcher state, credentials, container sockets, or the
  worker gateway. Its service permits at most four connections and has fixed time/memory/CPU bounds.
- The parser accepts only Cargo.lock version 4, local workspace packages, and checksum-pinned packages
  from the two canonical crates.io index source identities. Git dependencies, alternate registries,
  missing checksums, duplicate name/version pairs, malformed identities, more than 4096 packages, and
  a lockfile above 8 MiB fail before any fetch.
- The exact raw Cargo.lock digest, canonical sorted package-plan digest, platform, installed workflow
  policy, and versioned vendor-layout digest bind the shared DependencySnapshot key and manifest.
- Every downloaded archive is verified again by the worker. Inventory and extraction reject root
  substitution, traversal, absolute paths, duplicate paths, links, devices/special entries, reserved
  checksum-file injection, byte/inode overflow and unsafe modes. The worker generates Cargo directory-
  source `.cargo-checksum.json` files from extracted bytes and seals one immutable vendor snapshot.
- Preparation is single-flight by typed CAS key. Matching workers join one producer; warm replay makes
  no fetch call. Source and dependency snapshots are temporarily pinned across dependency and
  PreparedRun publication so pressure eviction cannot break the composition between atomic commits.
- Lease loss or worker shutdown cancels the active client fetch, removes partial CAS staging and emits
  no success receipt. A server may finish at most the one already accepted, bounded 45-second archive
  request after a client disconnect; it cannot continue with the rest of a package plan.
- The fixed transient job remains networkless and has no credentials or runtime/controller sockets. It
  validates the canonical dependency manifest and sealed vendor root, sets a private Cargo home, fixed
  source replacement and offline mode, and executes only the installed adapter command. The dependency
  snapshot is mounted read-only; per-job source/target state stays in the bounded transient workspace.
- `source_tree_v1` remains supported without a fetcher. `cargo_crates_io_v1` fails with a terminal
  failed receipt when the narrow fetcher is unavailable. A synchronously rejected preparation adapter
  must also produce a failed receipt with complete cleanup instead of silently expiring.

KNOWN EVIDENCE
- Base HEAD: `3a3e42633b2611ab90caa1759b4b0bde572063d4`.
- Exact staged product/config/test binary diff SHA-256:
  `ef9fee21059f9611e724f3818613e502899632c2eb28267e245402051170f789`
  (17 paths, 3293 insertions, 73 deletions).
- `git diff --cached --check` passed.
- A `git checkout-index` export of the exact staged tree passed bare `bin/ci`: formatting, Clippy with
  warnings denied, 220 active library tests with two credentialed live-provider tests ignored, every
  binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser contracts, and the
  optimized release build. The release phase completed in 3 minutes 24 seconds.
- The first full attempt exposed a real regression: synchronous adapter-selection failure bypassed the
  required failed receipt and left the controller waiting. The dispatch now routes that error through
  `fail_without_runtime`; its exact regression test completes in 0.01 seconds, and the complete exact
  gate above passed after the correction.
- Focused contracts include actual `cargo metadata --offline --locked` against the generated vendor
  source, parsing this repository's current lockfile, malformed source/checksum/archive/budget
  rejection, single-flight replay, pressure-safe pins, cancellation cleanup, peer-UID authentication,
  fixed URL construction, public-route filtering, Cargo job configuration and systemd privilege
  separation.
- No live dependency fetch occurred. Initial isolated exact-gate copies demonstrated 17.5 GiB of
  duplicated temporary Cargo target output; those disposable generated targets were removed and the
  successful exact gate reused one shared local Cargo target. This is execution evidence for the
  shared-cache objective, not a product-state mutation.

FOCUS AREAS
- Can lockfile/package fields influence a host, URL, filesystem path, Cargo configuration or checksum
  boundary despite validation?
- Can DNS rebinding, proxy variables, redirects, address classes, framing, peer credentials or shared
  group permissions turn the fetcher into an SSRF or confused-deputy route?
- Can malformed tar/gzip input escape, alias, overwrite controller files, exhaust unbounded resources,
  or produce a vendor tree Cargo interprets differently from the verified inventory?
- Can concurrent preparation, CAS pressure, pin expiry, cancellation, renewal or process shutdown
  publish an incomplete object, evict a live input, fetch the same plan per slot, leak staging, or emit
  a false success/failure receipt?
- Can repository-controlled Cargo inputs escape the sealed vendor/offline configuration or cause the
  networkless job to consume a host/global cache?
- Are systemd identities, groups, namespaces, writable paths, socket modes and resource limits aligned
  with the code's peer and filesystem assumptions?

INSPECT IF NEEDED
- `git diff --cached -- src/cargo_prefetch.rs`
- `git diff --cached -- src/dependency_fetch.rs`
- `git diff --cached -- src/workflow_worker.rs`
- `git diff --cached -- src/bin/rdashboard-dependency-fetcher.rs`
- `git diff --cached -- src/bin/rdashboard-workflow-job.rs`
- `git diff --cached -- deploy/systemd/rdashboard-dependency-fetcher.service deploy/systemd/rdashboard-worker.service`
- Existing preparation-store, launcher, lease, source-archive and systemd contracts may be read only as
  needed to verify interactions with the staged diff.
