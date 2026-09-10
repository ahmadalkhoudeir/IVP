import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from ivp.audit.log import TamperDetected
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.db.connection import connect
from ivp.db.sqlite_audit_log import SqliteAuditLog

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def conn():
    connection = connect(":memory:")
    yield connection
    connection.close()


def append_sample(log: SqliteAuditLog, ticket_id: str = "T-1", **overrides):
    defaults = {
        "ticket_id": ticket_id,
        "actor_id": "agent-1",
        "actor_role": "agent",
        "requested_action": SensitiveAction.PASSWORD_RESET,
        "channel_type": ChannelType.PUSH,
        "outcome": AuditOutcome.APPROVED,
        "timestamp": T0,
    }
    defaults.update(overrides)
    return log.append(**defaults)


def test_append_and_read_back_round_trips(conn):
    log = SqliteAuditLog(conn)
    append_sample(log)
    [record] = log.all_records()
    assert record.ticket_id == "T-1"
    assert record.requested_action == SensitiveAction.PASSWORD_RESET
    assert record.channel_type == ChannelType.PUSH
    assert record.outcome == AuditOutcome.APPROVED


def test_chain_persists_across_appends(conn):
    log = SqliteAuditLog(conn)
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    records = log.all_records()
    assert records[1].prev_hash == records[0].record_hash


def test_verify_integrity_passes_on_untouched_log(conn):
    log = SqliteAuditLog(conn)
    for i in range(4):
        append_sample(log, ticket_id=f"T-{i}", timestamp=T0 + timedelta(seconds=i))
    log.verify_integrity()


def test_records_for_ticket_filters(conn):
    log = SqliteAuditLog(conn)
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    assert [r.ticket_id for r in log.records_for_ticket("T-1")] == ["T-1"]


def test_admin_override_requires_reason(conn):
    log = SqliteAuditLog(conn)
    with pytest.raises(ValueError):
        append_sample(log, outcome=AuditOutcome.ADMIN_OVERRIDE, actor_role="admin")


def test_database_rejects_update_against_audit_log(conn):
    """Defense in depth at the SQL layer: even a raw UPDATE statement,
    bypassing the Python class entirely, is rejected by the trigger in
    db/connection.py."""
    log = SqliteAuditLog(conn)
    append_sample(log)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE audit_log SET outcome = 'DENIED' WHERE sequence = 0")


def test_database_rejects_delete_against_audit_log(conn):
    log = SqliteAuditLog(conn)
    append_sample(log)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM audit_log WHERE sequence = 0")


def test_tamper_detected_if_row_edited_via_a_separate_raw_connection(conn):
    """Simulates an attacker with raw file-level DB access rewriting a row
    outside of any application code path (e.g. editing the .db file
    directly) — the trigger only stops normal SQL connections' UPDATE
    statements from this same handle; a lower-level rewrite must still be
    caught by verify_integrity()'s hash recomputation."""
    log = SqliteAuditLog(conn)
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))

    # Drop the trigger to simulate a rewrite that bypassed it (e.g. direct
    # file manipulation), then corrupt a row.
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET outcome = 'DENIED' WHERE sequence = 0")
    conn.commit()

    with pytest.raises(TamperDetected):
        log.verify_integrity()
