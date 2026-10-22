"""Domain enums shared across the verification state machine, audit log, and
ticketing adapter. No framework or persistence dependencies belong here.
"""

from __future__ import annotations

from enum import StrEnum


class SensitiveAction(StrEnum):
    """Actions that MUST NOT be marked performed on a ticket without an
    APPROVED verification record (project hard requirement 3)."""

    PASSWORD_RESET = "PASSWORD_RESET"
    MFA_RESET = "MFA_RESET"
    ACCOUNT_UNLOCK = "ACCOUNT_UNLOCK"
    # Not a ticket action an agent can request: used only as the
    # requested_action of the CHANNEL_ENROLLED audit record, so channel
    # enrollment is audited in the same hash chain as everything else
    # (docs/decisions/enrollment-cooling-off.md). Excluded from
    # TICKET_ACTIONS below.
    CHANNEL_ENROLLMENT = "CHANNEL_ENROLLMENT"


# The actions an agent may open a ticket for. Anything else submitted to the
# ticket-creation route is rejected.
TICKET_ACTIONS: tuple[SensitiveAction, ...] = (
    SensitiveAction.PASSWORD_RESET,
    SensitiveAction.MFA_RESET,
    SensitiveAction.ACCOUNT_UNLOCK,
)


class ChannelType(StrEnum):
    """Out-of-band confirmation channel types. Email is deliberately absent:
    NIST SP 800-63B-4 prohibits email for out-of-band authentication
    ("Email SHALL NOT be used for out-of-band authentication..."). See
    docs/decisions/ and docs/threat-model.md for the citation and reasoning.
    """

    PUSH = "PUSH"
    PSTN = "PSTN"  # SMS/voice — NIST SP 800-63B-4 restricted authenticator


class TicketStatus(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
