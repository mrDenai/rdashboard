# Inactive rdashboard self-update boundary

This repository ships the local trust and recovery boundary for a future `rdashboard` A/B
self-update. It is intentionally inactive until the installed policy, first release slot, stable
bootstrap binary and staging-host failure drills have been reviewed and installed explicitly.

The build handoff is `/var/lib/rdashboard-build/self-releases/<git-sha>/` with exactly
`release.jcs` and `release.tar`. The root launcher publishes the complete directory with one atomic
rename after validating the worker output and signing the exact release. Published directories are
root-owned, grouped to the bootstrap reader GID and mode `0550`; files are mode `0440`. The handoff
root is root-owned mode `0711`, so the build UID cannot publish a partial or caller-selected release.
The bootstrap ignores only structurally valid hidden launcher staging directories and rejects
mutable, linked, extra, missing, expired, conflicting or policy-incompatible input.

Root stages verified releases at `/var/lib/rdashboard-bootstrap/releases/<manifest-digest>`. Release
directories and files become immutable before publication. `current` and `last-known-good` are relative
atomic links inside `/var/lib/rdashboard-bootstrap`; a target outside the verified release store is
never followed.

`rdashboard-bootstrap.service` stays outside the versioned release slots. Configure only these numeric
host identities in root-owned `/etc/rdashboard/self-update.env`:

```ini
RDASHBOARD_SELF_RELEASE_GID=<rdashboard-build-readers gid>
```

Install the canonical root-owned mode-`0400` policy at
`/etc/rdashboard/self-update-policy.jcs`. The public policy pins the signing key ID/epoch, runtime
contract digest, supported state-schema interval, archive ceiling and exact path/mode allowlist. It
contains no signing seed.

Before a pointer switch, the supervisor uses SQLite online backup for the controller, metrics,
integration, executor-security and source journals. Each backup is integrity-checked, hashed and
bound to the update operation. A failed candidate health check stops the candidate, restores the
verified databases, switches to the previous release and proves previous health. Crash/restart replays
the root-owned journal; an unknown pointer or failed rollback becomes `needs_reconcile` instead of an
invented success.

Do not enable this unit in production yet. Activation additionally requires:

1. a reviewed initial versioned release and executable-path migration;
2. the root-only recovery CLI;
3. disposable-host kill, OOM and reboot drills at every recorded phase;
4. a fresh explicit production authorization.

The generic worker producer and root-signed atomic handoff are implemented locally. They remain
inactive until the launcher policy, signing credential, drop-in and bootstrap activation gates above
are installed together.
