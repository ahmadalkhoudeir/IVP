from datetime import UTC, datetime

import pytest

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.adapters.ticketing.mock import MockTicketingAdapter
from ivp.audit.log import AuditLog
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.core.ticket import ClosureBlocked, Ticket, TicketClosureGate

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_adapter() -> tuple[MockTicketingAdapter, AuditLog]:
    log = AuditLog()
    gate = TicketClosureGate(log)
    return MockTicketingAdapter(gate), log


def test_get_ticket_not_found_raises():
    adapter, _ = make_adapter()
    with pytest.raises(TicketNotFound):
        adapter.get_ticket("nope")


def test_close_ticket_blocked_without_verification_record():
    """The adapter re-validates itself; it never trusts a caller's claim
    that verification already happened."""
    adapter, _log = make_adapter()
    adapter.seed(Ticket(id="T-1", requested_action=SensitiveAction.PASSWORD_RESET))
    with pytest.raises(ClosureBlocked):
        adapter.close_ticket("T-1")


def test_close_ticket_succeeds_after_audit_record_exists():
    adapter, log = make_adapter()
    adapter.seed(Ticket(id="T-1", requested_action=SensitiveAction.PASSWORD_RESET))
    log.append(
        ticket_id="T-1",
        actor_id="agent-1",
        actor_role="agent",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=ChannelType.PUSH,
        outcome=AuditOutcome.APPROVED,
        timestamp=T0,
    )
    adapter.close_ticket("T-1")
    assert adapter.get_ticket("T-1").status.value == "CLOSED"


def test_mark_action_performed_blocked_without_approval():
    adapter, log = make_adapter()
    adapter.seed(Ticket(id="T-1", requested_action=SensitiveAction.PASSWORD_RESET))
    log.append(
        ticket_id="T-1",
        actor_id="agent-1",
        actor_role="agent",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=ChannelType.PUSH,
        outcome=AuditOutcome.DENIED,
        timestamp=T0,
    )
    with pytest.raises(ClosureBlocked):
        adapter.mark_action_performed("T-1")
