"""Append-only, hash-chained audit log (hard requirement 4).

This module intentionally exposes no update or delete operation of any
kind — that is the enforcement mechanism for "append-only," not a
convention callers are trusted to follow. A persistence-backed
implementation (e.g. SQLite) must preserve that property: no UPDATE/DELETE
statement against the audit table anywhere in the codebase.

Each record's hash covers its own fields plus the previous record's hash,
so altering or removing any record breaks the chain from that point
forward. `verify_integrity()` recomputes the chain from a genesis hash and
reports the first point of divergence, if any.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from ivp.audit.record import AuditOutcome, AuditRecord
from ivp.core.models import ChannelType, SensitiveAction

GENESIS_HASH = "0" * 64


def _canonical_payload(
    *,
    sequence: int,
    ticket_id: str,
    actor_id: str,
    actor_role: str,
    requested_action: SensitiveAction,
    channel_type: ChannelType | None,
    outcome: AuditOutcome,
    timestamp: datetime,
    reason: str | None,
    prev_hash: str,
) -> str:
    payload = {
        "sequence": sequence,
        "ticket_id": ticket_id,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "requested_action": requested_action.value,
        "channel_type": channel_type.value if channel_type else None,
        "outcome": outcome.value,
        "timestamp": timestamp.isoformat(),
        "reason": reason,
        "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_record_hash(**kwargs) -> str:
    canonical = _canonical_payload(**kwargs)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TamperDetected(Exception):
    """Raised by verify_integrity() when the chain does not recompute
    cleanly. Carries the sequence number of the first bad record."""

    def __init__(self, sequence: int, reason: str):
        self.sequence = sequence
        self.reason = reason
        super().__init__(f"audit log tampered at sequence {sequence}: {reason}")


@dataclass
class AuditLog:
    """In-memory, hash-chained audit log. A persistence-backed repository
    (src/ivp/db/) wraps the same append-only contract; this class is the
    reference implementation used directly in tests and by anything that
    doesn't need durability (e.g. a dry-run)."""

    _records: list[AuditRecord]

    def __init__(self) -> None:
        self._records = []

    def append(
        self,
        *,
        ticket_id: str,
        actor_id: str,
        actor_role: str,
        requested_action: SensitiveAction,
        channel_type: ChannelType | None,
        outcome: AuditOutcome,
        timestamp: datetime,
        reason: str | None = None,
    ) -> AuditRecord:
        if outcome == AuditOutcome.ADMIN_OVERRIDE and not reason:
            raise ValueError("ADMIN_OVERRIDE records require a reason")

        sequence = len(self._records)
        prev_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
        record_hash = compute_record_hash(
            sequence=sequence,
            ticket_id=ticket_id,
            actor_id=actor_id,
            actor_role=actor_role,
            requested_action=requested_action,
            channel_type=channel_type,
            outcome=outcome,
            timestamp=timestamp,
            reason=reason,
            prev_hash=prev_hash,
        )
        record = AuditRecord(
            sequence=sequence,
            ticket_id=ticket_id,
            actor_id=actor_id,
            actor_role=actor_role,
            requested_action=requested_action,
            channel_type=channel_type,
            outcome=outcome,
            timestamp=timestamp,
            prev_hash=prev_hash,
            record_hash=record_hash,
            reason=reason,
        )
        self._records.append(record)
        return record

    def records_for_ticket(self, ticket_id: str) -> list[AuditRecord]:
        return [r for r in self._records if r.ticket_id == ticket_id]

    def all_records(self) -> list[AuditRecord]:
        return list(self._records)

    def verify_integrity(self) -> None:
        """Raises TamperDetected on the first record whose stored hash does
        not match a fresh recomputation from its own fields and the
        preceding record's hash. Returns None (no exception) if the whole
        chain is intact."""
        expected_prev = GENESIS_HASH
        for record in self._records:
            if record.prev_hash != expected_prev:
                raise TamperDetected(
                    record.sequence,
                    f"prev_hash {record.prev_hash!r} does not match preceding "
                    f"record's hash {expected_prev!r}",
                )
            recomputed = compute_record_hash(
                sequence=record.sequence,
                ticket_id=record.ticket_id,
                actor_id=record.actor_id,
                actor_role=record.actor_role,
                requested_action=record.requested_action,
                channel_type=record.channel_type,
                outcome=record.outcome,
                timestamp=record.timestamp,
                reason=record.reason,
                prev_hash=record.prev_hash,
            )
            if recomputed != record.record_hash:
                raise TamperDetected(
                    record.sequence,
                    "stored record_hash does not match recomputed hash "
                    "(record contents were altered after being written)",
                )
            expected_prev = record.record_hash
