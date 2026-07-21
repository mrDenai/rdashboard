# Slice 4h final exact OCI build/result acceptance review

Perform a fresh read-only acceptance review of the exact staged diff in
`/home/denai/RustroverProjects/rdashboard` at baseline HEAD
`924ddadc563d7a2b342316174f077cde5e40c09d`.

The complete staged binary diff SHA-256, including the plan/review ledger, is
`d0eb21160581e6e1ca02b8ae40bc2b9dc211ac0784893256da911db9303d8dd2`. The stable
17-path product/config/test binary diff SHA-256, excluding only those two workflow ledger files, is
`220f049f3ef5b5fefdf4567d6c2231f2e4ff065c16757234c7a9a115fcd1c554`.

Inspect `git diff --cached` plus directly relevant committed context. Ignore all unrelated unstaged
notification/dashboard work and untracked consult stderr logs. Do not modify files, inspect credentials,
install/start a service, contact a provider, run an OCI build, push or deploy.

## Delta since the initial independent review

The initial fresh review inspected the same implementation before one final correction and returned
`VERDICT: SAFE`, no P0-P2 finding and `OPEN QUESTIONS: NONE`. It raised three P3 observations:

1. The concurrent wait/terminate cleanup race already fails closed: lifecycle and store locks serialize
   promotion/discard, the losing path cannot publish unverified output, cleanup is idempotent and startup
   reconciliation removes bounded debris. No code change was required.
2. The installed build client intentionally uses the transient unit's lease-bound `RuntimeMaxSec`,
   `TimeoutStopSec` and process-group cleanup as the outer liveness boundary. No second client timer was
   added because it would duplicate that authority and would not improve recovery from filesystem/kernel
   stalls.
3. `rootless_oci_build` used Unix APIs but its module export lacked `#[cfg(unix)]`. This was fixed. This
   one guard is the only product/config/test change after the initial `SAFE` review.

Bare `bin/ci` passed again after the correction. Do not simply inherit the old verdict: independently
verify the exact current staged product and whether the P3 dispositions are sound.

## Intended contract

- GitHub is only a source/signal boundary, never an execution dependency. A generic cross-project worker
  receives a signed offline release-build lease.
- `ReleaseBuild` produces typed `ReleaseBuildResult`, not final `ReleaseBundle`; final sealing remains
  downstream of CI, deterministic reduction, resource reservation and deployment-policy evidence.
- Launcher policy admits OCI only with the already-reviewed rootless runtime contract and one exact
  per-project policy binding Dockerfile, target, `linux/amd64`, sorted build args, sealed local OCI-layout
  bases and archive ceiling. The native release enum remains wire-compatible but is not admitted or
  mapped to a repository script without an equivalent typed output.
- The transient unit executes only installed `rdashboard-workflow-oci-build` with sealed inputs, one
  peer-restricted BuildKit Unix socket, one build-owned staging directory, private network and rebuilt
  environment. It receives no operation-state mount, credential, host/container-runtime socket,
  entitlement, secret/SSH mount, registry output, external cache or network fetch.
- The fixed client uses builtin `dockerfile.v0`, rejects external `# syntax=` before invoking BuildKit,
  maps every non-scratch base to an authorized local OCI layout, exports one OCI tar plus metadata, and
  validates tar bounds/path/type/trailing bytes plus index -> manifest -> config/layer digest graph.
- Root repeats ownership, lease, archive and complete reachable-graph validation before atomic promotion.
  Process exit alone can never be success; the worker commits the typed result digest.
- The result store is a separate root-owned exact 4-6 GiB, 10k-100k-inode filesystem. It preserves a
  12 GiB root reserve, caps a project archive at 3 GiB, admits capacity before spawn, retains one result
  per project and reconciles bounded staging/request/deleting debris.
- The root runtime registers `unit -> request` before slow preparation, rechecks after preparation, and
  clears only on verified promotion or successful discard. Ambiguous wait retains the registration so
  cleanup stops the unit before retrying discard; restart reconciliation clears orphaned store debris.
- OCI uses independently bounded BuildKit/result state and does not allocate or mount the 6-8 GiB
  compiled operation state. The VPS may build OCI beside verification. Optional i9 remains
  verification-only, non-blocking and cannot own release output.
- Terminal compatibility is preserved: OCI success requires output digest; non-OCI canonical bytes omit
  it; failed terminals cannot carry it. Root-side failures emit stable reason codes and concise evidence.

This slice remains inactive. No BuildKit binary/service/socket/filesystem/project policy was installed
or enabled, no base layout was prepared, and no OCI build/import/deployment was executed.

## Verification evidence

- Focused: 8 rootless OCI build tests, 9 launcher tests and 16 scheduler contracts passed.
- Formatting and strict Clippy across all targets/features passed.
- Post-correction bare `bin/ci` passed: 269 active library tests in the shared worktree, two credentialed
  live-provider tests ignored by design, every binary/integration/socket/scheduler/worker suite, both
  schema checks, nine browser contracts and the optimized release build (4m17s).
- `git diff --cached --check` passed.

## Review questions

1. Find every concrete P0-P3 correctness, security, crash/replay, TOCTOU, operability, resource-bound or
   observability defect in the current exact staged diff. Cite file/line evidence and realistic impact.
2. Is the added Unix guard sufficient and are both accepted P3 dispositions correct under the actual
   systemd/lifecycle/store implementation?
3. Can malformed/malicious output, a build UID, a concurrent cleanup, process/host crash or replay publish
   unverified bytes, escape storage, lose required evidence, strand unbounded data or turn failure into
   success?
4. Are BuildKit argv/metadata assumptions, local OCI named contexts, archive validation, workflow output
   typing, scheduler operation-state exclusion and rolling cleanup mutually coherent?
5. Does any transient-unit path/network/authority exposure exceed the intended contract or omit a required
   fixed input?

Return `VERDICT: SAFE` only if no P0-P2 issue remains. P3 findings must be concrete defects, not style
preferences. Otherwise provide severity, evidence, impact and the smallest coherent fix. End with
`OPEN QUESTIONS: NONE` or a bounded list.
