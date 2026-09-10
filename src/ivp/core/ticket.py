"""Ticket domain model and the closure gate that enforces hard requirement 3.

Kept deliberately separate from VerificationAttempt: a ticket's closure
eligibility depends on the audit log (which may contain an ADMIN_OVERRIDE
record that never existed as a VerificationAttempt at all), not on any
single attempt's state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ivp.audit.log import AuditLog
from ivp.audit.record import CLOSURE_SATISFYING_OUTCOMES, AuditOutcome
from ivp.core.models import SensitiveAction, TicketStatus

# Outcomes that authorize the sensitive action itself to be marked
# performed. Deliberately narrower than CLOSURE_SATISFYING_OUTCOMES: a
# DENIED or plain EXPIRED record lets the ticket close, but must never
# authorize the action. ADMIN_OVERRIDE is included — see
# docs/decisions/admin-override.md "Follow-up decision" for the reasoning
# and the trade-off this accepts.
ACTION_AUTHORIZING_OUTCOMES = frozenset({AuditOutcome.APPROVED, AuditOutcome.ADMIN_OVERRIDE})


class ClosureBlocked(Exception):
    """Raised when a ticket operation is attempted without satisfying hard
    requirement 3 (a valid verification record must exist)."""


@dataclass
class Ticket:
    id: str
    requested_action: SensitiveAction
    status: TicketStatus = TicketStatus.OPEN
    action_performed: bool = field(default=False)


class TicketClosureGate:
    """The single place in the codebase that may set Ticket.status =
    CLOSED or Ticket.action_performed = True. No other code path should
    mutate those fields directly — this is what "enforced at the adapter
    boundary" (see docs/threat-model.md, Elevation of Privilege) means in
    practice for the ticketing adapter's mock/real implementations."""

    def __init__(self, audit_log: AuditLog):
        self._audit_log = audit_log

    def authorize_action(self, ticket: Ticket) -> None:
        if ticket.action_performed:
            return
        if not self._has_outcome(ticket.id, ACTION_AUTHORIZING_OUTCOMES):
            raise ClosureBlocked(
                f"ticket {ticket.id}: no APPROVED or ADMIN_OVERRIDE record exists; "
                "the sensitive action may not be performed"
            )
        ticket.action_performed = True

    def close(self, ticket: Ticket) -> None:
        if ticket.status == TicketStatus.CLOSED:
            raise ClosureBlocked(f"ticket {ticket.id} is already closed")
        if not self._has_outcome(ticket.id, CLOSURE_SATISFYING_OUTCOMES):
            raise ClosureBlocked(
                f"ticket {ticket.id}: no verification record exists; closure is blocked"
            )
        ticket.status = TicketStatus.CLOSED

    def _has_outcome(self, ticket_id: str, outcomes: frozenset[AuditOutcome]) -> bool:
        return any(r.outcome in outcomes for r in self._audit_log.records_for_ticket(ticket_id))
