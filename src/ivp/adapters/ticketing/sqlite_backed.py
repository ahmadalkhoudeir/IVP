"""SQLite-persisted ticketing adapter. Still a "mock" in the sense of
requirement 6 — there is no real vendor (ServiceNow/Jira/etc.) behind it —
but persisting locally lets the docker-compose demo survive a restart.

Mirrors adapters.ticketing.mock.MockTicketingAdapter's re-validation
behavior: every close/authorize call goes through TicketClosureGate, never
trusting the caller.
"""

from __future__ import annotations

from ivp.core.ticket import Ticket, TicketClosureGate
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository


class SqlitePersistedTicketingAdapter:
    def __init__(self, repository: SqliteTicketRepository, closure_gate: TicketClosureGate):
        self._repository = repository
        self._closure_gate = closure_gate

    def get_ticket(self, ticket_id: str) -> Ticket:
        return self._repository.get(ticket_id)

    def close_ticket(self, ticket_id: str) -> None:
        ticket = self._repository.get(ticket_id)
        self._closure_gate.close(ticket)  # raises ClosureBlocked if not eligible
        self._repository.save(ticket)

    def mark_action_performed(self, ticket_id: str) -> None:
        ticket = self._repository.get(ticket_id)
        self._closure_gate.authorize_action(ticket)
        self._repository.save(ticket)
