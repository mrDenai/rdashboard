# Slice 4h exact staged OCI build/result review

Perform a fresh read-only review of the exact staged diff in
`/home/denai/RustroverProjects/rdashboard` at baseline HEAD
`924ddadc563d7a2b342316174f077cde5e40c09d`. The canonical staged binary diff SHA-256 is
`adf65a56f2db72cb4ff4d42852bb75e41d6a4b0ba3750b20ba1ea53a0490a4ae` and the staged manifest is:

```text
.agent/workflows/2026-07-20-github-independent-delivery/plan.md
.agent/workflows/2026-07-20-github-independent-delivery/review.md
config/project-manifests/ralert.json
config/schema/project-manifest-v2.json
deploy/systemd/README.md
deploy/systemd/ROOTLESS_OCI.md
deploy/systemd/rdashboard-tmpfiles.conf
src/bin/rdashboard-workflow-job.rs
src/bin/rdashboard-workflow-launcher.rs
src/bin/rdashboard-workflow-oci-build.rs
src/domain/workflow.rs
src/lib.rs
src/operation_state.rs
src/rootless_oci_build.rs
src/scheduler.rs
src/workflow_launcher.rs
src/workflow_worker.rs
tests/workflow_scheduler_contracts.rs
tests/workflow_worker_contracts.rs
```

Inspect `git diff --cached` plus directly relevant committed context. Ignore every unrelated unstaged
notification/dashboard change and untracked consult stderr log. Do not inspect credentials, `.env`,
provider state or private files. Do not modify files, install/start a service, contact a provider, run
an OCI build, push or deploy.

## Intended contract

- GitHub is not in the execution path. The generic worker receives a signed offline release-build
  lease over the same cross-project scheduler used by all installed repositories.
- `ReleaseBuild` produces a new `ReleaseBuildResult`, not the final `ReleaseBundle`. Final sealing must
  still wait for CI, deterministic reduction, resource reservation and deployment-policy evidence.
- Launcher policy admits OCI only when both the already-reviewed rootless runtime contract and one
  exact per-project build policy exist. The policy binds Dockerfile, target, `linux/amd64`, sorted build
  args, sealed local OCI-layout bases and an archive ceiling. Native release remains a domain-reserved
  future adapter but is no longer admitted or mapped to a repository script without typed output.
- The transient unit directly executes fixed
  `/usr/libexec/rdashboard/rdashboard-workflow-oci-build`; it receives sealed prepared/dependency roots,
  one BuildKit Unix socket, one build-owned staging directory, private network, reconstructed
  environment and no operation-state mount. It receives no credential, host/container-runtime socket,
  insecure entitlement, SSH/secret mount, registry output or external cache argument.
- The installed client uses builtin `dockerfile.v0`, rejects external `# syntax=` before `buildctl`,
  maps every nonscratch base to an authorized local OCI layout, exports a local OCI tar and reads
  BuildKit metadata. It validates tar shape/path/type/count/size/trailing bytes, hashes every blob,
  validates index -> selected manifest -> config/layers, and binds manifest/config/archive digests and
  bytes into canonical request/result documents.
- Root revalidates the build-owned output after process exit, changes exact files to root ownership and
  atomically promotes one result per project. The result store requires a separate 4-6 GiB,
  10k-100k-inode filesystem, keeps a 12 GiB root reserve, caps individual archives at 3 GiB, checks
  capacity before spawn and reconciles bounded staging/request/deleting debris at startup.
- A root-owned in-memory `unit -> request` registry survives every in-process race: prepare registers
  before slow storage work and rechecks afterward; promote/discard clear exact entries; ambiguous wait
  leaves registration so later cleanup first stops the unit and then discards output; process restart
  is covered by store reconciliation. Root-side failures log stable reason codes and evidence digests.
- OCI has its own independently bounded output/cache state and does not allocate the 6-8 GiB compiled
  operation state. Scheduler tests require OCI and verification to be simultaneously leaseable on the
  VPS while only actual compiled-cache consumers share/serialize operation state. i9 remains optional,
  verification-only and cannot own release output.
- A successful OCI terminal must contain the verified result digest. The worker rejects missing typed
  output and commits the result digest; non-OCI terminal canonical bytes remain compatible because the
  optional field is omitted when absent.

This slice is inactive: no rootless runtime/result filesystem is installed, no policy enables OCI, no
base layout is prepared, and no OCI build/import or deployment was executed.

## Verification evidence

- Focused: all 8 rootless OCI build tests, 9 launcher tests and 16 scheduler contracts passed.
- `cargo fmt --all -- --check` and strict Clippy for all targets/features passed.
- Final bare `bin/ci` passed on the final product code: 267 active library tests, two credentialed live
  provider tests ignored by design, every binary/integration/socket/scheduler/worker suite, both schema
  checks, nine browser contracts and the optimized release build. Release compilation took 4m01s.
- `git diff --cached --check` passed.

## Review questions

1. Find every concrete P0-P3 correctness, security, crash/replay, TOCTOU, operability, resource-bound or
   observability defect in the exact staged diff. Cite exact file/line evidence and realistic impact.
2. Are the fixed `buildctl` arguments and BuildKit metadata/OCI digest assumptions correct for one
   `linux/amd64` OCI archive with authorized local OCI-layout named contexts?
3. Can a malformed/malicious archive, concurrent build UID, filesystem crash or systemd wait/cleanup
   race publish unverified bytes, escape storage, lose required evidence, strand unbounded data or turn
   failure into success?
4. Are policy compatibility, native-adapter removal, scheduler operation-state exclusion, terminal
   canonical compatibility and worker output reduction coherent across restart and rolling cleanup?
5. Does the systemd transient argv expose more paths/network/authority than intended, or fail to expose
   a required fixed path?

Return `VERDICT: SAFE` only if no P0-P2 issue remains. P3 findings should still be concrete, not style
preferences. Otherwise give severity, evidence, impact and the smallest coherent fix. End with
`OPEN QUESTIONS: NONE` or a bounded list.
