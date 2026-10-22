"""Audit record schema (hard requirement 4).

Every record captures: ticket ID, actor ID, requested action, channel used,
timestamps, and outcome. `actor_id`/`actor_role` cover both the agent who
requested the action and, for ADMIN_OVERRIDE, the admin who closed the
ticket without a completed verification — the schema is deliberately the
same shape for both so overrides are not a special, less-audited case.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from ivp.core.models import ChannelType, SensitiveAction


class AuditOutcome(StrEnum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"  # invalid/replayed confirmation token presented
    NO_CHANNEL_BLOCKED = "NO_CHANNEL_BLOCKED"
    ADMIN_OVERRIDE = "ADMIN_OVERRIDE"
    # The holder pressed "I did not request this". Treated like DENIED for
    # closure purposes, but flagged to supervisors/admins as a likely
    # social-engineering attempt (docs/decisions/fraud-reporting.md).
    FRAUD_REPORTED = "FRAUD_REPORTED"
    # The destination-keyed send rate limit (push-bombing defense) refused
    # to send. Not a verification record: the ticket stays OPEN.
    RATE_LIMITED = "RATE_LIMITED"
    # Every enrolled channel was unusable because of a carrier risk signal
    # (SIM swap / number port, NIST SP 800-63B-4 restricted authenticator
    # guidance). Not a verification record: needs an ADMIN_OVERRIDE.
    RISK_BLOCKED = "RISK_BLOCKED"
    # A new confirmation channel was enrolled for a subscriber. Not tied to
    # a ticket; ticket_id is an "ENR-..." enrollment reference.
    CHANNEL_ENROLLED = "CHANNEL_ENROLLED"


# Outcomes that satisfy hard requirement 3 (ticket may leave OPEN). Kept here
# rather than in core.state_machine because ADMIN_OVERRIDE is an
# audit-log-level concept, not a VerificationAttempt state.
CLOSURE_SATISFYING_OUTCOMES = frozenset(
    {
        AuditOutcome.APPROVED,
        AuditOutcome.DENIED,
        AuditOutcome.EXPIRED,
        AuditOutcome.ADMIN_OVERRIDE,
        AuditOutcome.FRAUD_REPORTED,
    }
)

# Outcomes meaning verification could not even be attempted. The agent sees
# these as the reason the ticket is blocked.
BLOCKING_OUTCOMES = frozenset(
    {
        AuditOutcome.NO_CHANNEL_BLOCKED,
        AuditOutcome.RATE_LIMITED,
        AuditOutcome.RISK_BLOCKED,
    }
)


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    ticket_id: str
    actor_id: str
    actor_role: str
    requested_action: SensitiveAction
    channel_type: ChannelType | None
    outcome: AuditOutcome
    timestamp: datetime
    prev_hash: str
    record_hash: str
    reason: str | None = None
