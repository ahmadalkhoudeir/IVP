"""Orchestrates checkpointing the audit log's hash chain to an external
anchor (see adapters/anchoring/interface.py for the security property this
provides and its limits).

Deliberately does not live in ivp.audit — that package is pure hash-chain
logic with no I/O of its own; this module composes it with an adapter, the
same separation used by VerificationOrchestrator for the verification flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ivp.adapters.anchoring.interface import AnchorAdapter, AnchorReceipt
from ivp.audit.log import AuditLog
from ivp.db.sqlite_audit_log import SqliteAuditLog


class AnchorVerificationFailed(Exception):
    """Raised when a published checkpoint's chain_hash does not match what
    the live audit log now has at that sequence — i.e. history was
    rewritten after that checkpoint was published. Unlike TamperDetected
    (ivp.audit.log), this can catch a fully internally-consistent rewrite:
    an attacker who edited every record and recomputed every hash forward
    would still fail this check, because the checkpoint's hash was
    published before the rewrite and lives outside the database."""

    def __init__(self, sequence_up_to: int, expected_hash: str, actual_hash: str | None):
        self.sequence_up_to = sequence_up_to
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(
            f"anchor mismatch at sequence {sequence_up_to}: "
            f"expected {expected_hash!r}, found {actual_hash!r}"
        )


@dataclass
class AuditAnchorService:
    audit_log: AuditLog | SqliteAuditLog
    anchor_adapter: AnchorAdapter

    def checkpoint_if_new_records(self, *, now: datetime) -> AnchorReceipt | None:
        """Idempotent-safe to call anytime (e.g. on a schedule, or from an
        admin action): publishes a new checkpoint only if the chain has
        grown since the last one. Returns None if there's nothing new to
        anchor (empty log, or no records since the last checkpoint)."""
        records = self.audit_log.all_records()
        if not records:
            return None
        latest = records[-1]

        last_checkpoint = self.anchor_adapter.latest_checkpoint()
        if last_checkpoint is not None and last_checkpoint.sequence_up_to >= latest.sequence:
            return None

        return self.anchor_adapter.publish_checkpoint(
            sequence_up_to=latest.sequence, chain_hash=latest.record_hash, now=now
        )

    def verify_against_anchors(self) -> None:
        """Raises AnchorVerificationFailed on the first checkpoint whose
        chain_hash no longer matches the live audit log's record at that
        sequence. Returns None (no exception) if every published
        checkpoint still matches."""
        records_by_sequence = {r.sequence: r for r in self.audit_log.all_records()}
        for checkpoint in self.anchor_adapter.list_checkpoints():
            record = records_by_sequence.get(checkpoint.sequence_up_to)
            actual_hash = record.record_hash if record else None
            if actual_hash != checkpoint.chain_hash:
                raise AnchorVerificationFailed(
                    checkpoint.sequence_up_to, checkpoint.chain_hash, actual_hash
                )
