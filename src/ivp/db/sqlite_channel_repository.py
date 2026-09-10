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
    ) -> ChannelEnrollment:
        enrollment_id = str(uuid.uuid4())
        fp = fingerprint(destination)
        self._conn.execute(
            """
            INSERT INTO channel_enrollments
                (id, subscriber_id, channel_type, label, destination_fingerprint, enrolled_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (enrollment_id, subscriber_id, channel_type.value, label, fp, now.isoformat()),
        )
        self._conn.commit()
        return ChannelEnrollment(
            id=enrollment_id,
            subscriber_id=subscriber_id,
            channel_type=channel_type,
            label=label,
            destination_fingerprint=fp,
            enrolled_at=now,
        )

    def list_for_subscriber(self, subscriber_id: str) -> list[ChannelEnrollment]:
        rows = self._conn.execute(
            "SELECT * FROM channel_enrollments WHERE subscriber_id = ? ORDER BY enrolled_at",
            (subscriber_id,),
        ).fetchall()
        return [self._row_to_enrollment(row) for row in rows]

    def has_any_enrollment(self, subscriber_id: str) -> bool:
        return bool(self.list_for_subscriber(subscriber_id))

    @staticmethod
    def _row_to_enrollment(row: sqlite3.Row) -> ChannelEnrollment:
        return ChannelEnrollment(
            id=row["id"],
            subscriber_id=row["subscriber_id"],
            channel_type=ChannelType(row["channel_type"]),
            label=row["label"],
            destination_fingerprint=row["destination_fingerprint"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
        )
