"""Persists VerificationAttempt (ivp.core.state_machine) across requests —
that module is pure in-memory domain logic with no I/O of its own, so this
repository is what lets a stateless HTTP request pick up where the last one
left off. Also stores the number-matching `code` (CISA guidance) alongside
each attempt, since it isn't part of the state machine's own fields.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta

from ivp.core.models import SensitiveAction
from ivp.core.state_machine import VerificationAttempt, VerificationState


class VerificationAttemptNotFound(Exception):
    pass


class SqliteVerificationRepository:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(
        self,
        *,
        ticket_id: str,
        requested_action: SensitiveAction,
        channel_id: str | None,
        code: str,
        max_attempts: int,
        timeout: timedelta,
    ) -> tuple[str, VerificationAttempt]:
        attempt = VerificationAttempt(
            ticket_id=ticket_id,
            requested_action=requested_action,
            channel_id=channel_id,
            max_attempts=max_attempts,
            timeout=timeout,
        )
        attempt_id = str(uuid.uuid4())
        self._insert(attempt_id, attempt, code)
        return attempt_id, attempt

    def get(self, attempt_id: str) -> tuple[VerificationAttempt, str]:
        row = self._conn.execute(
            "SELECT * FROM verification_attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise VerificationAttemptNotFound(attempt_id)
        return self._row_to_attempt(row), row["code"]

    def latest_for_ticket(self, ticket_id: str) -> tuple[str, VerificationAttempt, str] | None:
        row = self._conn.execute(
            "SELECT * FROM verification_attempts WHERE ticket_id = ? "
            "ORDER BY rowid DESC LIMIT 1",
            (ticket_id,),
        ).fetchone()
        if row is None:
            return None
        return row["id"], self._row_to_attempt(row), row["code"]

    def save(self, attempt_id: str, attempt: VerificationAttempt, code: str) -> None:
        self._conn.execute(
            """
            UPDATE verification_attempts
            SET channel_id = ?, code = ?, state = ?, attempt_number = ?,
                max_attempts = ?, timeout_seconds = ?, pending_since = ?
            WHERE id = ?
            """,
            (
                attempt.channel_id,
                code,
                attempt.state.value,
                attempt.attempt_number,
                attempt.max_attempts,
                int(attempt.timeout.total_seconds()),
                attempt.pending_since.isoformat() if attempt.pending_since else None,
                attempt_id,
            ),
        )
        self._conn.commit()

    def _insert(self, attempt_id: str, attempt: VerificationAttempt, code: str) -> None:
        self._conn.execute(
            """
            INSERT INTO verification_attempts
                (id, ticket_id, requested_action, channel_id, code, state,
                 attempt_number, max_attempts, timeout_seconds, pending_since)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                attempt.ticket_id,
                attempt.requested_action,
                attempt.channel_id,
                code,
                attempt.state.value,
                attempt.attempt_number,
                attempt.max_attempts,
                int(attempt.timeout.total_seconds()),
                attempt.pending_since.isoformat() if attempt.pending_since else None,
            ),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_attempt(row: sqlite3.Row) -> VerificationAttempt:
        attempt = VerificationAttempt(
            ticket_id=row["ticket_id"],
            requested_action=SensitiveAction(row["requested_action"]),
            channel_id=row["channel_id"],
            max_attempts=row["max_attempts"],
            timeout=timedelta(seconds=row["timeout_seconds"]),
        )
        attempt.state = VerificationState(row["state"])
        attempt.attempt_number = row["attempt_number"]
        attempt.pending_since = (
            datetime.fromisoformat(row["pending_since"]) if row["pending_since"] else None
        )
        return attempt
