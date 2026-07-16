# Root executor boundary review

Review the current uncommitted implementation of the read-only root executor boundary in
`/home/denai/RustroverProjects/rdashboard`.

Scope:

- `src/executor_socket.rs`
- `src/protocol/frame.rs`
- `src/protocol/message.rs`
- `src/bin/rdashboard-executor.rs`
- the root-executor integration in `src/bin/rdashboardd.rs`
- `tests/executor_socket.rs`
- `deploy/systemd/rdashboard-executor.service`
- `deploy/systemd/rdashboard.service`

The repository is intentionally a largely untracked working tree, so do not compare the target
against committed `HEAD` or treat untracked files as absent. Inspect the live files above.

Review for concrete P0/P1/P2 correctness, security, and concurrency defects. In particular verify:

- peer-credential authorization and socket lifecycle cannot be bypassed by path or inode races;
- one-request framing, deadline handling, version negotiation, response binding, and size limits are
  internally consistent;
- overload and graceful shutdown do not permit unbounded work or indefinite hangs;
- all mutation requests and unconfigured privileged observations fail closed;
- the controller cannot silently fall back from configured executor observations to invented or
  stale healthy metrics;
- root-owned config checks and systemd hardening match the executable's filesystem/network needs;
- tests cover the meaningful observable boundaries without depending on a false contract.

Report only findings that survive source verification, with severity, path/line, exploit or failure
sequence, and a specific fix. Return `PASS` if no P0/P1/P2 finding survives.
