from __future__ import annotations

import sqlite3
from datetime import datetime

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.core.models import SensitiveAction, TicketStatus
from ivp.core.ticket import Ticket


class SqliteTicketRepository:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(self, ticket: Ticket, *, agent_id: str, now: datetime) -> None:
        self._conn.execute(
            """
            INSERT INTO tickets
                (id, requested_action, status, action_performed, agent_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ticket.id,
                ticket.requested_action.value,
                ticket.status.value,
                int(ticket.action_performed),
                agent_id,
                now.isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, ticket_id: str) -> Ticket:
        row = self._conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if row is None:
            raise TicketNotFound(ticket_id)
        return self._row_to_ticket(row)

    def save(self, ticket: Ticket) -> None:
        self._conn.execute(
            "UPDATE tickets SET status = ?, action_performed = ? WHERE id = ?",
            (ticket.status.value, int(ticket.action_performed), ticket.id),
        )
        self._conn.commit()

    def list_for_agent(self, agent_id: str) -> list[Ticket]:
        rows = self._conn.execute(
            "SELECT * FROM tickets WHERE agent_id = ? ORDER BY created_at DESC", (agent_id,)
        ).fetchall()
        return [self._row_to_ticket(row) for row in rows]

    def list_all(self) -> list[Ticket]:
        rows = self._conn.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
        return [self._row_to_ticket(row) for row in rows]

    @staticmethod
    def _row_to_ticket(row: sqlite3.Row) -> Ticket:
        return Ticket(
            id=row["id"],
            requested_action=SensitiveAction(row["requested_action"]),
            status=TicketStatus(row["status"]),
            action_performed=bool(row["action_performed"]),
        )
