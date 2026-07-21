GOAL
Decide whether the exact staged slice is a production-worthy inactive foundation for exact workflow
source binding and one shared bounded host-local preparation CAS before the actual worker/launcher is
implemented.

QUESTION
Does `git diff --cached` contain any concrete P0, P1, or P2 correctness, security, concurrency,
crash-safety, compatibility, or resource-accounting defect? Trace the relevant code and tests. Return
actionable findings with severity and evidence, or `SAFE` if no P0-P2 defect exists. Keep optional P3
observations clearly separate.

CONSTRAINTS
- Review only the staged diff and its direct current-code dependencies. Unstaged notification work and
  unrelated workflow artifacts are outside scope.
- GitHub remains only source hosting/signal; no GitHub runner or deployment is activated here.
- New leases must bind the accepted source sequence and attestation. Persisted V1 leases without the
  optional identity must remain canonically decodable, but cannot start new work.
- The CAS is owned by the trusted non-root orchestrator. Future repository commands run as a different
  build UID and receive read-only entries; repository code is not allowed to write the CAS.
- Production open must fail unless the CAS root is an exact dedicated mount. Persistent objects are
  capped at 6 GiB and 100,000 inodes; the root filesystem keeps at least 12 GiB available.
- Publication must be all-or-nothing across crashes, verify content on every open, reject symlink,
  hard-link, special-file and path substitution, coordinate same-key producers, protect live pins,
  and evict only cold unpinned sealed entries.
- This slice intentionally does not claim to implement command execution, dependency prefetch,
  writable COW slots, the root launcher, or service activation. Those are the immediately following
  slice and should not be reported as a defect in this foundation unless the current API makes them
  unsafe or impossible.

KNOWN EVIDENCE
- `git diff --cached --check` passed.
- An exact `git checkout-index` export of the staged state passed bare `bin/ci`: formatting, Clippy
  with warnings denied, 181 active library tests (2 live-provider tests ignored), every binary and
  integration suite, 14 scheduler contracts, 8 browser contracts, both schema checks, and the release
  build.
- `src/preparation.rs` tests cover deterministic typed keys, four-way same-key single-flight, producer
  failure, staging recovery, interrupted post-rename recovery, checksum tamper, symlink/hard-link
  rejection, pins/LRU, emergency reserve, read-only sealing, and exact sequence-9 source selection
  while sequence 10 is latest.
- `src/domain/workflow.rs` tests canonical decoding of a legacy lease without `source_identity` and
  refusal by `required_source_identity`; scheduler integration proves new and renewed leases retain
  the exact sequence/attestation across database reopen.

INSPECT IF NEEDED
- `git diff --cached`
- `src/preparation.rs`: `PreparationStore`, `reserve`, `commit_stage`, `scan_usage`,
  `validate_entry_with_root_mode`, `inspect_input_directory`, sidecar/pin/access handling, filesystem
  boundary validation, removal/reconciliation, and module tests
- `src/build_source.rs`: `SourceArchiveReaderV1::exact` and `open_publication`
- `src/domain/workflow.rs`: `WorkflowSourceIdentityV1`, `WorkflowLeaseV1`
- `src/scheduler.rs`: `claim_next_transaction`, `load_ready_candidates`, candidate SQL mapping
- `tests/workflow_scheduler_contracts.rs`
