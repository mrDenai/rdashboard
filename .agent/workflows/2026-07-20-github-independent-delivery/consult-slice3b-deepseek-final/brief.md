# Final review: durable multi-project GitHub source ingress

Review only the current staged diff in `/home/denai/RustroverProjects/rdashboard` against the
repository source and this contract. Do not modify files, do not read `.env` or credentials, and do
not review unrelated unstaged notification work.

The staged product/config/test diff (excluding `.agent` workflow artifacts) has SHA-256
`5b2808f5e304074cced07397d5600c2b554d7c7af87e652fddcf4310ee5a62d3` and contains 21 paths,
4,768 insertions and 406 deletions. An exact staged export passed bare `bin/ci`, including formatting,
Clippy, every Rust/JavaScript/schema contract and the optimized release build.

## Required behavior

- A loopback-only ingress accepts bounded GitHub push requests for every installed project, forwards
  the unchanged body over a peer-authenticated Unix socket, and owns no source credentials, database,
  Git, Docker or deployment authority.
- The broker verifies exact route/project, repository binding and GitHub HMAC before it durably admits
  a secret-free wake-up. Admission is content-bound and idempotent, globally capped at 2,048 rows and
  capped at 128 rows per project.
- A committed wake-up preempts or outranks periodic fetch work across projects. Periodic network work
  has a two-second ceiling and must never queue in front of durable webhook work. A project's bounded
  batch shares one foreground fetch. Restart, delayed remote visibility, removed/remapped projects and
  concurrent arrival during drain must not lose accepted work.
- Root-generated schema-V5 configuration is derived from the exact installed workflow catalog, binds
  identities/repositories/policy/credential digests, serializes no secret bytes, and emits exact
  systemd credential wiring. The installed example remains inactive.
- No repository-selected commands or project-specific worker/service topology is introduced.

## Prior review context

The preceding review returned `SAFE`, with no P0-P2 finding, but the dispatcher classified its otherwise
complete response as `PARTIAL`. It listed five P3 observations. Its P3 #1 is factually invalid:
`src/source.rs` already queries `source_deliveries` with
`WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3` and binds
`SourceChannel::GithubWebhook`. The remaining P3 observations describe bounded retry/wasted-work/timer
effects or a documented race whose ingress-side signal prevents loss; none requires a correctness fix.

## Output

Return a concise final verdict. Report only concrete P0-P2 defects with file/line evidence, consequence
and smallest safe correction. If none exist, say `SAFE — no P0-P2 defect found`. Explicitly confirm or
reject the correction to prior P3 #1. Keep the response under 1,000 words and include no broad redesign.
