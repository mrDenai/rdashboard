# rdashboard self-update boundary

This repository ships the local trust and recovery boundary for atomic `rdashboard` self-update.
First activation remains fail-closed until the installed policy, first release slot, stable recovery
kit and staging-host failure drills have been reviewed and installed explicitly.

The build handoff is
`/var/lib/rdashboard-build/self-releases/release-<manifest-sha256>/` with exactly `release.jcs` and
`release.tar`. Naming by the signed manifest identity permits a newly attested source sequence to
publish the same Git commit without replacing its earlier immutable handoff. Readers accept only this
manifest-bound form. The root launcher publishes the complete directory with one atomic rename after
validating the worker output and signing the exact release. Published directories are
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

Do not hand-edit that policy independently from `/etc/rdashboard/workflow-launcher.jcs`. Install the
stable `rdashboard-self-update-config` binary below `/usr/libexec/rdashboard`, keep the raw 32-byte
`/etc/rdashboard/credentials/self-release-seed` root-owned mode `0600`, and generate one reviewed
canonical bundle from the canonical launcher policy before its native self-release adapter is enabled:

```text
rdashboard-self-update-config build-workflow-bootstrap KEY_EPOCH WORKER_UID BUILD_UID BUILD_GID SOURCE_UID BUILD_READER_GID DEPENDENCY_FETCHER_UID DEPENDENCY_FETCH_GID
rdashboard-self-update-config extract-base-launcher
rdashboard-self-update-config render-workflow-gateway
rdashboard-self-update-config render-workflow-worker
rdashboard-self-update-config build-policies KEY_EPOCH SELF_RELEASE_READER_GID
rdashboard-self-update-config extract-launcher
rdashboard-self-update-config extract-self-update
rdashboard-self-update-config render-environment
```

`build-workflow-bootstrap` reads the separate fixed raw 32-byte
`/etc/rdashboard/credentials/workflow-grant-seed` and emits one canonical digest-bound bundle. Its
three extraction commands produce the base launcher JCS, gateway environment and worker environment
from exactly the same UID/GID set and derived public key. Install neither an environment nor a policy
from a different bundle. Treat the seed as immutable for a key epoch: replacing it requires a strictly
higher `KEY_EPOCH`, installation of the new verification key before the gateway signs with it, and a
bounded retirement window for the old key. Never reuse an epoch with different seed material. Feed the
extracted base launcher into `build-policies`; that second command
adds only the self-release adapter and its independently derived signing authority.

`build-policies` reads the base launcher policy from bounded stdin and the seed only from the fixed
credential path. The bundle binds the derived public key, compiled runtime contract, exact complete
versioned binary payload, schema version, 128 MiB archive ceiling, 15-minute publication validity, reader GID and the
complete augmented launcher policy. It refuses an already configured release authority instead of
silently rotating it. The extract commands accept only that canonical digest-bound bundle and emit
the exact launcher JCS, bootstrap JCS or `self-update.env` line for atomic root-owned installation.
The bundle is a review artifact, not runtime authority.

Every versioned application service executes through `/var/lib/rdashboard-bootstrap/current/bin`. The signed
release policy requires the complete fixed application payload: controller, source path, observer,
executor, generic worker path, health proxy and their four fixed transient-job clients. A policy that
omits one of those binaries is rejected before work starts. `rdashboard-bootstrap`,
`rdashboard-recovery`, source configuration/schema tools and separately hash-pinned privileged
adapters stay in `/usr/libexec/rdashboard`; a broken application release therefore cannot replace its
own recovery kit. Stable host infrastructure is not part of a release pointer switch: in particular,
the optional rootless BuildKit daemon and the socket-proxy source ingress bridge retain their own
systemd lifecycle and are neither stopped nor required by self-update.

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
record rolled back only after restored health succeeds. `admit` accepts no path or tag: it selects the
newest unexpired manifest-named handoff for the exact Git SHA, validates the installed signing policy,
current source sequence and prior-attempt history, then enters the normal
backup/switch/health/rollback coordinator. Success and failure are
single-line JSON suitable for operator or LLM diagnosis. Restart the bootstrap only after inspecting
the terminal result.

Before the first production enable, complete all activation requirements:

1. a reviewed initial versioned release with both `current` and `last-known-good` initialized before
   the migrated units are reloaded;
2. disposable-host kill, OOM and reboot drills at every recorded phase;
3. install the reviewed `rdashboard` manifest/source controls and matching launcher/self-update
   policies with `auto_deploy` still false;
4. a fresh explicit production authorization.

### Initial slot provisioning

The initial slot is created before any migrated unit is reloaded, so no service ever observes a
missing `/var/lib/rdashboard-bootstrap/current/bin`. Install the exact release binaries from the
verified build under the fixed root-owned mode-`0700`
`/usr/libexec/rdashboard/initial-release/bin` directory. Every name in the versioned payload must be
present exactly once as a root-owned, single-link, non-symlinked mode-`0555` file; extra files fail the
operation.

Create a reviewed input containing the exact source SHA and sequence plus the real source-attestation,
installed-workflow-policy and successful verification-receipt digests. Pipe that bounded JSON through
`rdashboard-self-update-config build-initial-plan`, then atomically install the emitted canonical JCS
as root-owned mode `0400` `/etc/rdashboard/initial-self-release.jcs`. This root-only command re-hashes
the fixed payload and binds every exact path, byte count and SHA-256 into the plan; `initialize`
re-hashes it again and rejects any copy or post-plan change. No placeholder source evidence is
generated by the tool: the activation review must still prove the three supplied evidence digests
came from the same source/build being installed.

With the bootstrap stopped and no self-update journal history, run the root-only fixed command:

```text
rdashboard-self-update-config initialize
```

It accepts no caller-selected path. It revalidates the installed policy pair and signing seed, signs
only the fixed payload, stages the immutable release, publishes `last-known-good` first and publishes
`current` only afterward. A crash after LKG publication resumes from the already signed/staged release
instead of generating a timestamp-distinct descriptor. Conflicting pointers, prior journal activity,
policy drift, payload inventory drift or an unsafe payload fail closed. Exact repeats return a
single-line canonical JSON
`already_initialized` result. Only after both pointers inspect as the same valid digest may the
current-based units be installed/reloaded; the disposable-host failure drills and explicit activation
still remain mandatory.

The generic worker producer, explicit terminal self-update workflow, inactive `rdashboard` repository
catalog/control candidates, root-signed atomic handoff, versioned executable paths and stable root
recovery/config CLIs are implemented locally. They remain inactive until the generated policy pair,
signing credential, drop-in, initial slot and bootstrap activation gates above are installed together.
