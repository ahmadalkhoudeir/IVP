"""Ticketing system port (hard requirement 6). Real implementations
(ServiceNow, Jira, Zendesk, etc.) live outside this codebase; only mocks
exist here. Nothing in this module or its callers may assume a specific
vendor's API shape.

Security note: an implementation MUST re-validate closure/action-performed
eligibility against the audit log itself (via TicketClosureGate) rather
than trusting that a caller already checked — see docs/threat-model.md,
"Elevation of Privilege: An agent or integrator calls the ticketing adapter
directly...". MockTicketingAdapter demonstrates this by holding its own
TicketClosureGate reference and delegating to it, never accepting a
caller-supplied "already verified" flag.
"""

from __future__ import annotations

from typing import Protocol

from ivp.core.ticket import Ticket


class TicketNotFound(Exception):
    pass


class TicketingAdapter(Protocol):
    def get_ticket(self, ticket_id: str) -> Ticket: ...

    def close_ticket(self, ticket_id: str) -> None:
        """Must raise ClosureBlocked (ivp.core.ticket) if no valid
        verification record exists for the ticket. Never accepts a
        caller-supplied override of that check."""
        ...

    def mark_action_performed(self, ticket_id: str) -> None:
        """Must raise ClosureBlocked if no APPROVED/ADMIN_OVERRIDE record
        exists for the ticket."""
        ...
