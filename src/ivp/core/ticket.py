"""Ticket domain model and the closure gate that enforces hard requirement 3.

Kept deliberately separate from VerificationAttempt: a ticket's closure
eligibility depends on the audit log (which may contain an ADMIN_OVERRIDE
record that never existed as a VerificationAttempt at all), not on any
single attempt's state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ivp.audit.log import AuditLog
from ivp.audit.record import CLOSURE_SATISFYING_OUTCOMES, AuditOutcome
from ivp.auth.roles import Permission, Role, require_permission
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
    subscriber_id: str
    agent_id: str
    status: TicketStatus = TicketStatus.OPEN
    action_performed: bool = field(default=False)
    # Populated by the repository; used for the speed metrics (the 30-second
    # target, hard requirement 5) and the verification receipt.
    created_at: datetime | None = field(default=None)
    closed_at: datetime | None = field(default=None)


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

    def admin_override(
        self,
        ticket: Ticket,
        *,
        actor_id: str,
        actor_role: Role,
        reason: str,
        now: datetime,
    ) -> None:
        """Write an ADMIN_OVERRIDE record for this ticket, e.g. to unblock a
        NO_CHANNEL_BLOCKED ticket via out-of-system identity proofing. This
        does NOT call close()/authorize_action() itself — callers still go
        through those methods, which will now see the ADMIN_OVERRIDE record.

        Checks the ADMIN_OVERRIDE_TICKET permission itself, as a
        defense-in-depth backstop: the web route calling this must already
        enforce Role.ADMIN via the RBAC dependency (docs/decisions/
        admin-override.md), but this method must never trust that alone
        (see docs/threat-model.md, Elevation of Privilege).
        """
        require_permission(actor_role, Permission.ADMIN_OVERRIDE_TICKET)
        if not reason:
            raise ValueError("ADMIN_OVERRIDE requires a reason")
        self._audit_log.append(
            ticket_id=ticket.id,
            actor_id=actor_id,
            actor_role=actor_role.value,
            requested_action=ticket.requested_action,
            channel_type=None,
            outcome=AuditOutcome.ADMIN_OVERRIDE,
            timestamp=now,
            reason=reason,
        )

    def _has_outcome(self, ticket_id: str, outcomes: frozenset[AuditOutcome]) -> bool:
        return any(r.outcome in outcomes for r in self._audit_log.records_for_ticket(ticket_id))
