GOAL
Decide whether the exact staged Slice 4d is safe and correct to commit as the inactive sealed-input composition and per-job writable-workspace boundary for the repository-agnostic workflow worker.

QUESTION
Does the exact staged diff contain any concrete P0, P1, or P2 correctness, security, compatibility, concurrency, TOCTOU, eviction, resource-bounding, or cache-identity defect? Focus especially on whether a stale or incomplete PreparedRun can be accepted, a referenced source/dependency can be evicted while live, a repository can collide with controller metadata, a build UID can mutate sealed shared inputs, or the bounded workspace copy can escape, alias, overrun, or execute a substituted script. Return SAFE if no such defect exists; otherwise cite path/symbol, an executable failure scenario, severity, and the smallest coherent fix. List low-value style suggestions only as P3.

CONSTRAINTS
- Review only `git diff --cached`; the worktree intentionally contains unrelated unstaged notification work that is not part of this review.
- Do not edit files, run services, access secrets, read `.env`, contact providers, or mutate external state.
- This slice remains inactive. It does not install/start units, execute a repository job, prefetch network dependencies, deploy, mutate the VPS, or contact GitHub/providers.
- `source_tree_v1` still supports only dependency-free or fully vendored repositories. A populated Cargo/Ruby/npm/system dependency snapshot is a later fixed adapter; do not report its explicit absence as a defect unless this diff falsely claims it exists.
- The generic worker owns the sealed preparation store. A separate root launcher revalidates exact entries and derives systemd properties. Repository code runs as a distinct unprivileged build UID with no network, credentials, runtime socket, controller socket, or writable shared CAS path.
- Verification obtains a durable pin before asking the launcher to authorize. Pin acquisition now fully validates the PreparedRun and both referenced sealed snapshots, then records the two transitive protected keys in the canonical pin so eviction admission does not repeatedly hash large dependencies.
- Existing non-composite V1 pins must remain canonically decodable. A same-ID legacy PreparedRun pin may be upgraded only after the new composition validates.
- The PreparedRun layout is controller metadata plus a distinct sealed `source/` directory. A versioned generated-input digest gives this layout a different key from the source-only Slice 4c cache object. Repository source may legitimately contain the same hidden basename inside `source/` without colliding with controller metadata.
- Each transient job receives read-only `/prepared` and `/dependencies` mounts plus a byte/inode-bounded private `/job` tmpfs. The fixed job copies only `/prepared/source` into `/job/workspace`, rejects links, special files, unsafe modes, identity changes, more than 100,000 entries or 2 GiB, then executes only the fixed adapter script path from that private workspace.

KNOWN EVIDENCE
- Base HEAD: `d30652112b8fa8c4a6307b0ab3590da3c1989a72`.
- Exact staged binary diff SHA-256: `db0c76a6916a8febcd8dfffcd6fd043bacff4887984bab59127d43a00a428e7f` (5 paths, 884 insertions, 43 deletions).
- `git diff --cached --check` passed.
- Bare `bin/ci` passed in a `git checkout-index` export of the exact staged tree: formatting, Clippy with warnings denied, 207 active library tests (2 credentialed live-provider tests ignored), every binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser contracts, and the optimized release build. The final release phase completed in 2m43s.
- The first sandboxed exact run reached the suite but four existing Unix-socket tests received sandbox `EPERM`; the same unchanged export passed when local Unix-socket creation was allowed. This was an execution sandbox limitation, not a code failure.
- Focused contracts cover canonical composition/key validation, missing referenced dependency rejection before pin creation, transitive pin closure, legacy non-composite pin wire shape, source/metadata basename isolation, policy mismatch rejection, read-only mounts, private workspace copy, executable-bit preservation, and link/non-empty-destination rejection.
- No unit was installed or started, no repository command was launched through systemd, no provider was contacted, and no VPS/deployment state changed.

INSPECT IF NEEDED
- `git diff --cached -- src/preparation.rs`
- `git diff --cached -- src/workflow_worker.rs`
- `git diff --cached -- src/workflow_launcher.rs`
- `git diff --cached -- src/bin/rdashboard-workflow-job.rs`
- `git diff --cached -- deploy/systemd/README.md`
- Existing lease, grant, launcher-journal, CAS sealing, source archive, systemd unit and worker lifecycle code may be read only as needed to trace the staged behavior.
