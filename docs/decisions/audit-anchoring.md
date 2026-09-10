# ADR: External anchoring for the audit log's hash chain

## Decision
Periodically publish a "checkpoint" — (sequence_up_to, chain_hash,
published_at) — to a store outside the application's SQLite database.
`chain_hash` is simply the `record_hash` of the latest audit record at
publish time: because each record's hash already covers every record
before it (that's what makes it a hash *chain*), anchoring the single most
recent hash is sufficient to commit to the entire history up to that point.

Implementation:
- `src/ivp/adapters/anchoring/interface.py` — `AnchorAdapter` port.
- `src/ivp/adapters/anchoring/local_file.py` — `LocalFileAnchorAdapter`, an
  append-only JSON-lines file kept outside the SQLite database. Demo-grade
  only, consistent with every other adapter in this project: no real
  external service (a signing service, a WORM object store, a public
  transparency log) is implemented.
- `src/ivp/services/anchor_service.py` — `AuditAnchorService`:
  `checkpoint_if_new_records()` (idempotent — publishes only if the chain
  has grown since the last checkpoint) and `verify_against_anchors()`
  (raises `AnchorVerificationFailed` on the first checkpoint that no longer
  matches the live log).
- Admin UI: `/admin/audit` gained a "Create checkpoint now" and "Verify
  against anchors" action, plus a table of published checkpoints. A
  checkpoint is also attempted once at every app startup.

## Why
This closes the residual risk this project's own threat model named:
`verify_integrity()` (the in-database hash chain) only checks the chain
against itself, so an attacker with full database access can rewrite every
record and recompute every hash forward, and internal verification alone
would still pass. Publishing the head hash somewhere that attacker doesn't
also control means a later, fully self-consistent rewrite can no longer
match a checkpoint that was published *before* the rewrite happened.

## What this does and does not protect
- **Protects**: everything up to the most recently published checkpoint.
  `test_verify_against_anchors_catches_a_fully_consistent_rewrite`
  (tests/test_anchor_service.py) demonstrates this directly: it tampers
  with a record and recomputes the entire chain forward so
  `verify_integrity()` alone passes, and confirms `verify_against_anchors()`
  still catches it.
- **Does not protect**: records appended *after* the last checkpoint. Until
  the next checkpoint is published, new records are only as protected as
  the in-database chain alone. This is inherent to any checkpoint-based
  scheme (the same property Certificate Transparency logs have) — the fix
  is checkpointing frequently, not something a single checkpoint can
  guarantee retroactively.
- **Does not protect** against compromise of the anchor store itself. The
  local-file mock is explicitly not a security boundary on its own — see
  the module docstring in `local_file.py`.

## Consequence
`IVP_ANCHOR_LOG_PATH` (default `./demo_data/anchor_log.jsonl`) must be
excluded from `.gitignore` cleanup rules the same way the SQLite database
is — it's runtime state, not source, and it accumulates data a real
deployment would need to retain.
