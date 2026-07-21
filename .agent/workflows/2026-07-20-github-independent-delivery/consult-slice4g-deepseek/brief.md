# Slice 4g independent review: rootless OCI activation boundary

Review the exact staged diff in `/home/denai/RustroverProjects/rdashboard` at baseline HEAD
`6962f583e19c163ffbaeaa88888baf414e5317dd`. The canonical staged binary diff SHA-256 is
`0998ac4e17c891dda484833561b39f1045790d8ff64a73e327562e25b6ac5127`.

Inspect only `git diff --cached` and the directly relevant committed context. The worktree contains
unrelated notification/dashboard edits belonging to another task; do not review them and do not read
`.env`, credentials, provider state, or any untracked stderr logs. This is a read-only architecture,
security, correctness, and operability review. Do not modify files, install software, start services,
contact providers, or run a deployment.

## Intended outcome

This inactive slice makes `worker_oci_release_build_v1` impossible to activate unless the root-owned
workflow-launcher policy carries one exact `rootless_oci` contract and a startup preflight proves the
installed host boundary. It deliberately does not yet execute an OCI build, prefetch/import base
images, publish an OCI archive, install/start systemd, or activate a project. Native CI/release
adapters must remain usable without OCI.

The intended boundary is:

- a dedicated non-root BuildKit UID distinct from the generic worker and transient job UID;
- reviewed root-owned fixed-path `buildkitd`, `buildctl`, `rootlesskit`, and `runc`, each SHA-256 pinned;
- root-owned fixed configuration, exact strict TOML semantics, no insecure entitlements, OCI worker
  only, process sandbox enabled, one concurrent vertex, bounded history and GC;
- rootless execution inside a private systemd network namespace with only AF_UNIX/AF_NETLINK, no
  production credentials/state/source, no Docker/containerd/Podman sockets, and no network fetch;
- exact trusted `newuidmap`/`newgidmap`, non-overlapping subordinate UID/GID ranges, and required kernel
  user-namespace/AppArmor switches;
- BuildKit state on its own 1.5-2.5 GiB and 50k-500k-inode filesystem, at least 12 GiB free on `/`,
  exact ownership/modes, and a live owner/group/mode-bound Unix socket;
- stable structured failure codes, summaries, and remediations for operators/LLMs;
- no fallback to Docker or Podman and no weakening of non-OCI adapter availability.

The staged scope is exactly nine paths: the new rootless readiness module, BuildKit service/config and
activation note, launcher policy/startup coupling, one tmpfiles line, one isolated `src/lib.rs` export
hunk, and focused contract tests. `git diff --cached --check` passes.

## Verification evidence

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- focused rootless, launcher, and systemd contract tests: passed.
- bare `bin/ci`: passed on 2026-07-21, including 258 library tests (two credentialed live-provider
  tests ignored by design), all binary/integration suites, nine browser contracts, schema checks, and
  the optimized release build; release compilation took 3m44s.
- `systemd-analyze verify` parsed the new unit and reported only the expected absent executable at
  `/usr/libexec/rdashboard/rootlesskit`; the reviewed vendor bundle is intentionally not installed on
  this development host.

## Questions

1. Report concrete P0/P1/P2 findings with exact file/line evidence. Pay special attention to false
   readiness, bypass of OCI-policy coupling, canonical-policy compatibility, filesystem/socket TOCTOU,
   subordinate-ID parsing, rootless identity isolation, and storage/reserve arithmetic.
2. Review the systemd/RootlessKit/BuildKit combination for privilege escalation, accidental host
   networking, secret/source/runtime-socket exposure, configuration drift, unusable hardening, or an
   unbounded resource path. Distinguish a real defect from the intentionally deferred OCI adapter and
   live activation proof.
3. Verify failure paths are fail-closed but do not block native CI/release when OCI is absent.
4. Identify missing high-signal tests that would expose a realistic regression in this staged slice.

Return `VERDICT: SAFE` only if no P0-P2 issue remains. Otherwise list severity, evidence, impact, and
the smallest coherent fix. End with `OPEN QUESTIONS: NONE` or a bounded list.
