"""SQLite-backed audit log. Same public surface as ivp.audit.log.AuditLog
(append / records_for_ticket / all_records / verify_integrity) — no
update/delete method exists here either, and the underlying table also
rejects UPDATE/DELETE via triggers (db/connection.py). Tamper detection
logic is shared with the in-memory implementation via audit.log.verify_chain
rather than reimplemented.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime

from ivp.audit.log import GENESIS_HASH, compute_record_hash, verify_chain
from ivp.audit.record import AuditOutcome, AuditRecord
from ivp.core.models import ChannelType, SensitiveAction


class SqliteAuditLog:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

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

        row = self._conn.execute(
            "SELECT sequence, record_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = (row["sequence"] + 1) if row else 0
        prev_hash = row["record_hash"] if row else GENESIS_HASH

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
        self._conn.execute(
            """
            INSERT INTO audit_log
                (sequence, ticket_id, actor_id, actor_role, requested_action,
                 channel_type, outcome, timestamp, prev_hash, record_hash, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                ticket_id,
                actor_id,
                actor_role,
                requested_action.value,
                channel_type.value if channel_type else None,
                outcome.value,
                timestamp.isoformat(),
                prev_hash,
                record_hash,
                reason,
            ),
        )
        self._conn.commit()
        return AuditRecord(
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

    def records_for_ticket(self, ticket_id: str) -> list[AuditRecord]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE ticket_id = ? ORDER BY sequence", (ticket_id,)
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def all_records(self) -> list[AuditRecord]:
        rows = self._conn.execute("SELECT * FROM audit_log ORDER BY sequence").fetchall()
        return [self._row_to_record(row) for row in rows]

    def verify_integrity(self) -> None:
        verify_chain(self.all_records())

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            sequence=row["sequence"],
            ticket_id=row["ticket_id"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            requested_action=SensitiveAction(row["requested_action"]),
            channel_type=ChannelType(row["channel_type"]) if row["channel_type"] else None,
            outcome=AuditOutcome(row["outcome"]),
            timestamp=datetime.fromisoformat(row["timestamp"]),
            prev_hash=row["prev_hash"],
            record_hash=row["record_hash"],
            reason=row["reason"],
        )
