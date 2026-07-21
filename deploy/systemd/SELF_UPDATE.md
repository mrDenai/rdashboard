# Inactive rdashboard self-update boundary

This repository ships the local trust and recovery boundary for `rdashboard` A/B self-update. It is
intentionally inactive until the installed policy, first release slot, stable recovery kit and
staging-host failure drills have been reviewed and installed explicitly.

The build handoff is `/var/lib/rdashboard-build/self-releases/<git-sha>/` with exactly
`release.jcs` and `release.tar`. The root launcher publishes the complete directory with one atomic
rename after validating the worker output and signing the exact release. Published directories are
root-owned, grouped to the bootstrap reader GID and mode `0550`; files are mode `0440`. The handoff
root is root-owned mode `0711`, so the build UID cannot publish a partial or caller-selected release.
The bootstrap ignores only structurally valid hidden launcher staging directories and rejects
mutable, linked, extra, missing, expired, conflicting or policy-incompatible input.

Root stages verified releases at `/var/lib/rdashboard-bootstrap/releases/<manifest-digest>`. Release
directories and files become immutable before publication. `current` and `last-known-good` are
relative atomic links inside `/var/lib/rdashboard-bootstrap`; a target outside the verified release
store is never followed.

`rdashboard-bootstrap.service` stays outside the versioned release slots. Configure only this numeric
host identity in root-owned `/etc/rdashboard/self-update.env`:

```ini
RDASHBOARD_SELF_RELEASE_GID=<rdashboard-build-readers gid>
```

Install the canonical root-owned mode-`0400` policy at
`/etc/rdashboard/self-update-policy.jcs`. The public policy pins the signing key ID/epoch, runtime
contract digest, supported state-schema interval, archive ceiling and exact path/mode allowlist. It
contains no signing seed.

Every application service executes through `/var/lib/rdashboard-bootstrap/current/bin`. The signed
release policy requires the complete fixed application payload: controller, source path, observer,
executor, generic worker path, health proxy and their four fixed transient-job clients. A policy that
omits one of those binaries is rejected before work starts. `rdashboard-bootstrap`,
`rdashboard-recovery`, source configuration/schema tools and separately hash-pinned privileged
adapters stay in `/usr/libexec/rdashboard`; a broken application release therefore cannot replace its
own recovery kit.

Before a pointer switch, the supervisor uses SQLite online backup for the controller, metrics,
integration, executor-security and source journals. Each backup is integrity-checked, hashed and
bound to the update operation. A failed candidate health check stops the candidate, restores the
verified databases, switches to the previous release and proves previous health. Crash/restart replays
the root-owned journal; an unknown pointer or failed rollback becomes `needs_reconcile` instead of an
invented success. That unresolved record is never pruned and blocks every newer candidate until the
root recovery path closes it. The socket-activated rimg health helper is quiesced for a pointer switch
but remains on-demand rather than being treated as a permanently active health dependency.

Install `rdashboard-recovery` as a root-owned, non-symlinked, non-writable executable at
`/usr/libexec/rdashboard/rdashboard-recovery`. It has no provider/network command and accepts only:

```text
rdashboard-recovery inspect
rdashboard-recovery resume
rdashboard-recovery restart-current
rdashboard-recovery restore-lkg <operation-uuid>
rdashboard-recovery admit <40-character-git-sha>
```

Stop `rdashboard-bootstrap.service` before invoking it; the CLI proves the supervisor is inactive so
the two processes cannot hold different views of the root journal or release store. `inspect` returns
the verified current/LKG identities and complete bounded operation records. `resume` replays only the
existing nonterminal coordinator operation. `restart-current` cannot select another digest and is
blocked by any unresolved record. `restore-lkg` requires the exact `needs_reconcile` operation, its
verified database-backup receipt and the exact installed LKG pointer; it marks the original journal
record rolled back only after restored health succeeds. `admit` accepts no path or tag: it validates
the fixed SHA-named handoff, installed signing policy, current source sequence and prior-attempt
history, then enters the normal backup/switch/health/rollback coordinator. Success and failure are
single-line JSON suitable for operator or LLM diagnosis. Restart the bootstrap only after inspecting
the terminal result.

Do not enable this unit in production yet. Activation additionally requires:

1. a reviewed initial versioned release with both `current` and `last-known-good` initialized before
   the migrated units are reloaded;
2. disposable-host kill, OOM and reboot drills at every recorded phase;
3. install the reviewed `rdashboard` manifest/source controls and matching launcher/self-update
   policies with `auto_deploy` still false;
4. a fresh explicit production authorization.

The generic worker producer, explicit terminal self-update workflow, inactive `rdashboard` repository
catalog/control candidates, root-signed atomic handoff, versioned executable paths and stable root
recovery CLI are implemented locally. They remain inactive until the launcher policy, signing
credential, drop-in, initial slots and bootstrap activation gates above are installed together.
