# Slice 4h corrected request-permission final acceptance review

Perform a fresh read-only acceptance review of the exact staged implementation in
`/home/denai/RustroverProjects/rdashboard` at baseline HEAD
`924ddadc563d7a2b342316174f077cde5e40c09d`.

The stable 17-path product/config/test binary diff SHA-256, excluding only workflow/consultation
ledger evidence, is `9203b951038298566b92ce6063cf72f8207836ac7ccae6f56461a19fdbe2f79e`.
The complete current staged binary diff SHA-256, including plan/review ledger, is
`4e54be9ef6b808551cc541537e23f554c86df3ce546e321d307cd64a8cd349ac`.

Inspect `git diff --cached` and directly relevant committed context. Ignore unrelated unstaged
notification/dashboard work and untracked consultation logs. Do not modify files, inspect credentials,
install/start services, run an OCI build, contact providers, push or deploy.

## Required correction to verify

The preceding fresh acceptance review found one blocking defect and no other P0-P2: the root launcher
created the canonical OCI request as root-owned mode `0400`, then systemd ran the fixed client as an
unrelated non-root build UID with no capabilities. Its individual read-only bind therefore failed at
`open()` with `EACCES` before BuildKit.

The current exact product changes that boundary as follows:

- the non-secret canonical sandbox request has exact `SANDBOX_REQUEST_FILE_MODE = 0o444` at creation,
  root-side stale/reconcile/promote/discard validation and client-side stable-open validation;
- the request remains root-owned in an exact root-owned mode-`0700` dedicated result-store directory,
  which the build UID cannot traverse on the host;
- systemd exposes only the exact request file as `BindReadOnlyPaths=...:/request/oci-build-request.jcs`
  inside a private transient mount namespace, with the target request tmpfs read-only/noexec;
- the build UID receives no capability and no write path to the request or host store;
- OCI archive/result/request output in build staging and promoted result remains exact mode `0400`;
- the result-store regression now checks the actual produced request mode has other-read and no write,
  and reopens the exact canonical bytes through the same stable-file validation;
- documentation explains why this one non-secret file is `0444` without broadening host visibility.

The missing `#[cfg(unix)]` correction from the earlier review remains present. The earlier wait/terminate
and client-timeout P3 dispositions remain accepted: store/lifecycle locks fail closed and systemd
`RuntimeMaxSec` + `TimeoutStopSec` + `KillMode=control-group` are the outer liveness authority.

## Whole-slice contract to recheck

- GitHub is source/signal only; a generic cross-project worker receives signed offline leases.
- `ReleaseBuild` produces typed `ReleaseBuildResult`, never a premature final `ReleaseBundle`.
- OCI policy binds Dockerfile, target, `linux/amd64`, sorted build args, sealed local OCI-layout bases and
  archive ceiling. Native release remains wire-decodable but is not admitted without typed output.
- The transient job executes only installed `rdashboard-workflow-oci-build` with sealed prepared and
  dependency roots, one BuildKit Unix socket and one staging directory. It has private network and no
  credential, container-runtime socket, entitlement, secret/SSH mount, registry output or external cache.
- The client uses builtin `dockerfile.v0`, rejects external `# syntax=`, maps every non-scratch base to an
  authorized local OCI layout and validates metadata plus the complete bounded OCI archive digest graph.
- Root independently revalidates ownership, lease binding, archive and reachable OCI graph before atomic
  promotion. Process exit cannot become success without the typed result digest.
- BuildKit state, 6-8 GiB compiled verification state and 4-6 GiB OCI results are distinct hard-bounded
  resources. OCI allocates no compiled operation state and may run beside verification; optional i9 is
  verification-only and cannot block or own release output.
- The result store keeps one result/project, a 3 GiB archive ceiling, 10k-100k inode boundary and 12 GiB
  root reserve. Startup and explicit cleanup reconcile bounded request/staging/deleting debris.

This slice remains inactive: no BuildKit install/start, result filesystem, project policy, sealed base,
OCI build/import, VPS/i9 mutation, push or deployment occurred.

## Verification

- Focused rootless OCI tests passed after the correction; formatting passed.
- Bare `bin/ci` then passed: strict Clippy, 269 active library tests in the shared worktree with two
  credentialed live-provider tests ignored by design, every binary/integration/socket/scheduler/worker
  suite, both schema checks, nine browser contracts and optimized release build (3m50s).
- `git diff --cached --check` passed.

## Questions

1. Does exact mode `0444` plus the root-only host parent and individual systemd read-only bind make the
   request readable by the sandbox UID without exposing mutation or unintended host readers?
2. Are all request-mode creation and validation sites coherent while all output files remain private?
3. Find every remaining concrete P0-P3 correctness, security, crash/replay, TOCTOU, operability,
   resource-bound or observability defect across the full exact slice, with file/line evidence.
4. Can a build UID, malformed archive, concurrent cleanup, crash or replay publish unverified bytes,
   escape storage, strand unbounded data or turn failure into success?
5. Are the BuildKit argv/metadata assumptions, workflow output typing, operation-state exclusion,
   terminal compatibility and rolling cleanup mutually coherent?

Return `VERDICT: SAFE` only if no P0-P2 remains. P3 findings must be concrete defects. Otherwise state
severity, evidence, impact and smallest coherent fix. End with `OPEN QUESTIONS: NONE` or a bounded list.
