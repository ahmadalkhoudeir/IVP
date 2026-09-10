from datetime import UTC, datetime

import pytest

from ivp.audit.log import AuditLog
from ivp.audit.record import AuditOutcome
from ivp.auth.roles import PermissionDenied, Role
from ivp.core.models import ChannelType, SensitiveAction, TicketStatus
from ivp.core.ticket import ClosureBlocked, Ticket, TicketClosureGate

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_ticket(ticket_id: str = "T-1") -> Ticket:
    return Ticket(id=ticket_id, requested_action=SensitiveAction.PASSWORD_RESET)


def record(log: AuditLog, ticket_id: str, outcome: AuditOutcome, **overrides) -> None:
    defaults = {
        "ticket_id": ticket_id,
        "actor_id": "agent-1",
        "actor_role": "agent",
        "requested_action": SensitiveAction.PASSWORD_RESET,
        "channel_type": ChannelType.PUSH,
        "outcome": outcome,
        "timestamp": T0,
    }
    defaults.update(overrides)
    log.append(**defaults)


def test_close_blocked_with_no_record_at_all():
    log = AuditLog()
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)
    assert ticket.status == TicketStatus.OPEN


@pytest.mark.parametrize(
    "outcome", [AuditOutcome.APPROVED, AuditOutcome.DENIED, AuditOutcome.EXPIRED]
)
def test_close_allowed_once_any_terminal_record_exists(outcome):
    """Per docs/decisions/closure-semantics.md: a refusal or a final expiry
    is still a record; the ticket is not stuck open forever."""
    log = AuditLog()
    record(log, "T-1", outcome)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    gate.close(ticket)
    assert ticket.status == TicketStatus.CLOSED


def test_close_blocked_for_no_channel_blocked_alone():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.NO_CHANNEL_BLOCKED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)


def test_close_blocked_for_rejected_alone():
    """A REJECTED (replayed/invalid token) event is a security signal, not
    a verification outcome — it must not, by itself, unblock closure."""
    log = AuditLog()
    record(log, "T-1", AuditOutcome.REJECTED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)


def test_no_channel_blocked_ticket_closable_after_admin_override():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.NO_CHANNEL_BLOCKED)
    record(
        log,
        "T-1",
        AuditOutcome.ADMIN_OVERRIDE,
        actor_id="admin-1",
        actor_role="admin",
        reason="Identity proofed in person; caller had no enrolled channel.",
        timestamp=T0,
    )
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    gate.close(ticket)
    assert ticket.status == TicketStatus.CLOSED


def test_records_for_a_different_ticket_do_not_satisfy_the_gate():
    log = AuditLog()
    record(log, "T-OTHER", AuditOutcome.APPROVED)
    gate = TicketClosureGate(log)
    ticket = make_ticket("T-1")
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)


def test_double_close_is_blocked():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.APPROVED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    gate.close(ticket)
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)


def test_authorize_action_requires_approved_or_admin_override():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.DENIED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(ClosureBlocked):
        gate.authorize_action(ticket)
    assert not ticket.action_performed


def test_authorize_action_succeeds_with_approved():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.APPROVED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    gate.authorize_action(ticket)
    assert ticket.action_performed


def test_authorize_action_succeeds_with_admin_override():
    log = AuditLog()
    record(
        log,
        "T-1",
        AuditOutcome.ADMIN_OVERRIDE,
        actor_id="admin-1",
        actor_role="admin",
        reason="Identity proofed out of band.",
    )
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    gate.authorize_action(ticket)
    assert ticket.action_performed


def test_denied_ticket_can_close_but_action_is_never_authorized():
    log = AuditLog()
    record(log, "T-1", AuditOutcome.DENIED)
    gate = TicketClosureGate(log)
    ticket = make_ticket()

    with pytest.raises(ClosureBlocked):
        gate.authorize_action(ticket)

    gate.close(ticket)
    assert ticket.status == TicketStatus.CLOSED
    assert not ticket.action_performed


def test_admin_override_by_supervisor_is_denied():
    """Defense-in-depth: even if a route-level RBAC check were bypassed,
    the domain method itself must refuse a non-admin actor."""
    log = AuditLog()
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(PermissionDenied):
        gate.admin_override(
            ticket,
            actor_id="supervisor-1",
            actor_role=Role.SUPERVISOR,
            reason="trying to skip verification",
            now=T0,
        )
    assert not log.records_for_ticket(ticket.id)


def test_admin_override_by_agent_is_denied():
    log = AuditLog()
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(PermissionDenied):
        gate.admin_override(
            ticket, actor_id="agent-1", actor_role=Role.AGENT, reason="trying to skip", now=T0
        )


def test_admin_override_without_reason_is_rejected():
    log = AuditLog()
    gate = TicketClosureGate(log)
    ticket = make_ticket()
    with pytest.raises(ValueError):
        gate.admin_override(
            ticket, actor_id="admin-1", actor_role=Role.ADMIN, reason="", now=T0
        )


def test_admin_override_by_admin_writes_record_and_unblocks_closure_and_action():
    log = AuditLog()
    gate = TicketClosureGate(log)
    ticket = make_ticket()

    gate.admin_override(
        ticket,
        actor_id="admin-1",
        actor_role=Role.ADMIN,
        reason="Identity proofed in person; no enrolled channel.",
        now=T0,
    )

    [record] = log.records_for_ticket(ticket.id)
    assert record.outcome == AuditOutcome.ADMIN_OVERRIDE
    assert record.actor_id == "admin-1"
    assert record.reason

    gate.authorize_action(ticket)
    gate.close(ticket)
    assert ticket.action_performed
    assert ticket.status == TicketStatus.CLOSED
