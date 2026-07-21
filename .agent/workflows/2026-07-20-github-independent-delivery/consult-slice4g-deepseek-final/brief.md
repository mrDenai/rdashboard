# Slice 4g final exact-hash review

Perform a fresh final review of the exact staged diff in
`/home/denai/RustroverProjects/rdashboard` at baseline HEAD
`6962f583e19c163ffbaeaa88888baf414e5317dd`. The current canonical staged binary diff SHA-256 is
`32ba824c16f4ff383aa47c1cec9e49265b1812b05afe7384f609752725ace6ca`.

Inspect only `git diff --cached` and directly relevant committed context. Ignore all unrelated dirty
notification/dashboard work and untracked stderr logs. Do not read `.env`, credentials, provider
state, or private files. This is read-only: do not modify files, install/start services, contact
providers, or deploy.

## Intended inactive boundary

`worker_oci_release_build_v1` cannot be present in launcher policy unless an exact rootless OCI
contract is present. Launcher startup then validates pinned root-owned tools/configuration, a separate
non-root daemon identity, safe subordinate-ID and kernel policy, a dedicated hard-bounded filesystem,
the root recovery reserve, and a peer-restricted live Unix socket. The shipped service keeps BuildKit
in a private systemd network namespace, offline, without credentials/source/controller/executor or
Docker/containerd/Podman sockets. It has one concurrent vertex and bounded memory/CPU/tasks/GC/state.
Non-OCI CI/native adapters remain usable with no rootless contract.

This slice intentionally does not install/start BuildKit, activate a manifest, execute an OCI build,
prefetch/import base images, publish an archive, push, deploy, or mutate the VPS. Those are later
adapter/live-proof gates.

## Prior review and disposition

The prior exact hash `0998ac4e...` received `NEEDS_FIX` for one P2: every `/etc/subuid` and
`/etc/subgid` entry below 65536 was rejected but reported as if the BuildKit user merely lacked enough
IDs. The suggested fix was to ignore low ranges belonging to other users.

The updated code retains the global rejection deliberately. `newuidmap`/`newgidmap` are setuid helpers;
allowing any account a subordinate range inside the reserved host UID/GID space can expose a system
identity and undermine this boundary even when the BuildKit user's own entry is correct. Instead, the
real operability defect was fixed:

- unsafe global layout and missing BuildKit capacity are now distinct typed outcomes;
- low/overlapping/malformed host ranges return stable
  `rootless_oci_subid_layout_unsafe` with specific remediation;
- an otherwise safe layout with less than 65536 IDs for BuildKit retains
  `rootless_oci_subid_range_missing`;
- the activation note explicitly declares the host-wide >=65536/non-overlap invariant and its threat;
- regression tests cover unrelated low ranges, global overlap, short BuildKit range, missing optional
  kernel switches, invalid daemon identity, all mountinfo escapes, truncated/unknown escapes, and the
  new failure document.

The prior P3 suggestions were assessed as follows:

- exact root-owned mode `0644` remains an installation-drift contract rather than a minimum-permission
  check; the installed file is digest-pinned and the documented unit expects this exact shape;
- the rootless helper's stricter same-file comparison remains local because the compared artifacts and
  threat boundaries differ; extracting it would expand this slice without fixing a defect;
- `available_space` is deliberately conservative: the 12 GiB recovery reserve must be available to
  normal recovery processes, not merely consumable via root-reserved ext4 blocks;
- continuous BuildKit health belongs to the future OCI adapter/operation lifecycle. In this slice a
  later socket loss cannot become success: the future client operation will fail, while systemd has
  `Restart=on-failure`; no OCI execution is activated here.

## Current verification

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- six rootless unit tests plus launcher/systemd focused contracts: passed.
- bare `bin/ci`: passed after the correction on 2026-07-21: 259 library tests (two credentialed
  live-provider tests ignored by design), every binary/integration suite, schema checks, nine browser
  contracts, and optimized release build; release compilation took 4m58s.
- `git diff --cached --check`: passed.
- `systemd-analyze verify` previously parsed the unit and reported only the intentionally absent
  reviewed `/usr/libexec/rdashboard/rootlesskit` bundle on this development host.

## Final questions

1. Does the current exact hash have any concrete P0/P1/P2 correctness, security, operability, or
   fail-closed availability defect?
2. Is retaining the explicit global subordinate-range floor justified by the setuid mapping threat,
   and is its now-distinct diagnostic/remediation sufficient?
3. Does policy compatibility preserve native adapters when OCI is absent while preventing partial OCI
   activation?
4. Are the systemd, BuildKit config, filesystem, socket, digest, and TOCTOU checks coherent for this
   inactive activation boundary?

Return `VERDICT: SAFE` only if no P0-P2 issue remains. Otherwise provide severity, exact evidence,
impact, and smallest coherent fix. End with `OPEN QUESTIONS: NONE` or a bounded list.
