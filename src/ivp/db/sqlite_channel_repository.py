"""Channel enrollment storage. Per docs/threat-model.md (Information
Disclosure), only a label and a fingerprint hash are stored — never a raw
phone number/push token — since demo data must be synthetic (requirement 7)
and this project never actually sends anything to a real destination.

Multiple channels per subscriber are allowed (project owner decision:
redundancy is permitted, not limited to one channel).
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime

from ivp.core.models import ChannelType


@dataclass(frozen=True)
class ChannelEnrollment:
    id: str
    subscriber_id: str
    channel_type: ChannelType
    label: str
    destination_fingerprint: str
    enrolled_at: datetime
    usable_from: datetime | None = None

    def is_usable(self, now: datetime) -> bool:
        """False while the channel is still inside its enrollment cooling-off
        period (docs/decisions/enrollment-cooling-off.md)."""
        return (self.usable_from or self.enrolled_at) <= now


def fingerprint(destination: str) -> str:
    return hashlib.sha256(destination.encode("utf-8")).hexdigest()


class SqliteChannelRepository:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def enroll(
        self,
        *,
        subscriber_id: str,
        channel_type: ChannelType,
        label: str,
        destination: str,
        now: datetime,
        usable_from: datetime | None = None,
    ) -> ChannelEnrollment:
        enrollment_id = str(uuid.uuid4())
        fp = fingerprint(destination)
        usable_from = usable_from or now
        self._conn.execute(
            """
            INSERT INTO channel_enrollments
                (id, subscriber_id, channel_type, label, destination_fingerprint,
                 enrolled_at, usable_from)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enrollment_id,
                subscriber_id,
                channel_type.value,
                label,
                fp,
                now.isoformat(),
                usable_from.isoformat(),
            ),
        )
        self._conn.commit()
        return ChannelEnrollment(
            id=enrollment_id,
            subscriber_id=subscriber_id,
            channel_type=channel_type,
            label=label,
            destination_fingerprint=fp,
            enrolled_at=now,
            usable_from=usable_from,
        )

    def list_for_subscriber(self, subscriber_id: str) -> list[ChannelEnrollment]:
        rows = self._conn.execute(
            "SELECT * FROM channel_enrollments WHERE subscriber_id = ? ORDER BY enrolled_at",
            (subscriber_id,),
        ).fetchall()
        return [self._row_to_enrollment(row) for row in rows]

    def has_any_enrollment(self, subscriber_id: str) -> bool:
        return bool(self.list_for_subscriber(subscriber_id))

    def get_by_id(self, enrollment_id: str) -> ChannelEnrollment | None:
        row = self._conn.execute(
            "SELECT * FROM channel_enrollments WHERE id = ?", (enrollment_id,)
        ).fetchone()
        return self._row_to_enrollment(row) if row else None

    def fingerprint_exists(self, subscriber_id: str, destination: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM channel_enrollments WHERE subscriber_id = ? "
            "AND destination_fingerprint = ?",
            (subscriber_id, fingerprint(destination)),
        ).fetchone()
        return row is not None

    def list_distinct_subscribers(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT subscriber_id FROM channel_enrollments ORDER BY subscriber_id"
        ).fetchall()
        return [row["subscriber_id"] for row in rows]

    @staticmethod
    def _row_to_enrollment(row: sqlite3.Row) -> ChannelEnrollment:
        return ChannelEnrollment(
            id=row["id"],
            subscriber_id=row["subscriber_id"],
            channel_type=ChannelType(row["channel_type"]),
            label=row["label"],
            destination_fingerprint=row["destination_fingerprint"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            usable_from=(
                datetime.fromisoformat(row["usable_from"]) if row["usable_from"] else None
            ),
        )
