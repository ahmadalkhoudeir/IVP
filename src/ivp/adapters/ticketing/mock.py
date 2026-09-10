"""In-memory ticketing adapter for tests and the docker-compose demo."""

from __future__ import annotations

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.core.ticket import Ticket, TicketClosureGate


class MockTicketingAdapter:
    def __init__(self, closure_gate: TicketClosureGate):
        self._closure_gate = closure_gate
        self._tickets: dict[str, Ticket] = {}

    def seed(self, ticket: Ticket) -> None:
        self._tickets[ticket.id] = ticket

    def get_ticket(self, ticket_id: str) -> Ticket:
        try:
            return self._tickets[ticket_id]
        except KeyError:
            raise TicketNotFound(ticket_id) from None

    def close_ticket(self, ticket_id: str) -> None:
        ticket = self.get_ticket(ticket_id)
        self._closure_gate.close(ticket)

    def mark_action_performed(self, ticket_id: str) -> None:
        ticket = self.get_ticket(ticket_id)
        self._closure_gate.authorize_action(ticket)
