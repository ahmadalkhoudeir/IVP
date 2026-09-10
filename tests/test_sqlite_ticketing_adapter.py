from datetime import UTC, datetime

import pytest

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.adapters.ticketing.sqlite_backed import SqlitePersistedTicketingAdapter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction, TicketStatus
from ivp.core.ticket import ClosureBlocked, Ticket, TicketClosureGate
from ivp.db.connection import connect
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def build(conn):
    audit_log = SqliteAuditLog(conn)
    gate = TicketClosureGate(audit_log)
    repo = SqliteTicketRepository(conn)
    return SqlitePersistedTicketingAdapter(repo, gate), repo, audit_log


def test_get_ticket_not_found():
    conn = connect(":memory:")
    ticketing, _repo, _log = build(conn)
    with pytest.raises(TicketNotFound):
        ticketing.get_ticket("nope")
    conn.close()


def test_close_ticket_blocked_without_record():
    conn = connect(":memory:")
    ticketing, repo, _log = build(conn)
    repo.create(
        Ticket(
            id="T-1",
            requested_action=SensitiveAction.PASSWORD_RESET,
            subscriber_id="sub-1",
            agent_id="agent-1",
        ),
        now=T0,
    )
    with pytest.raises(ClosureBlocked):
        ticketing.close_ticket("T-1")
    conn.close()


def test_close_ticket_persists_status():
    conn = connect(":memory:")
    ticketing, repo, log = build(conn)
    repo.create(
        Ticket(
            id="T-1",
            requested_action=SensitiveAction.PASSWORD_RESET,
            subscriber_id="sub-1",
            agent_id="agent-1",
        ),
        now=T0,
    )
    log.append(
        ticket_id="T-1",
        actor_id="agent-1",
        actor_role="agent",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=ChannelType.PUSH,
        outcome=AuditOutcome.APPROVED,
        timestamp=T0,
    )
    ticketing.close_ticket("T-1")
    assert repo.get("T-1").status == TicketStatus.CLOSED
    conn.close()


def test_full_round_trip_survives_a_fresh_connection_object(tmp_path):
    """The point of SQLite persistence: state written by one adapter
    instance is visible to a new one opened against the same file,
    simulating an app restart."""
    db_path = str(tmp_path / "ivp.db")

    conn1 = connect(db_path)
    ticketing1, repo1, log1 = build(conn1)
    repo1.create(
        Ticket(
            id="T-1",
            requested_action=SensitiveAction.PASSWORD_RESET,
            subscriber_id="sub-1",
            agent_id="agent-1",
        ),
        now=T0,
    )
    log1.append(
        ticket_id="T-1",
        actor_id="agent-1",
        actor_role="agent",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=ChannelType.PUSH,
        outcome=AuditOutcome.APPROVED,
        timestamp=T0,
    )
    ticketing1.close_ticket("T-1")
    conn1.close()

    conn2 = connect(db_path)
    repo2 = SqliteTicketRepository(conn2)
    assert repo2.get("T-1").status == TicketStatus.CLOSED
    conn2.close()
