import csv
import io
from datetime import UTC, datetime, timedelta

from ivp.audit.log import AuditLog
from ivp.audit.record import AuditOutcome
from ivp.core.models import SensitiveAction, TicketStatus
from ivp.core.ticket import Ticket
from ivp.services.audit_export import neutralize, records_to_csv
from ivp.services.metrics import compute_metrics, percentile

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _ticket(tid, agent="agent-1", status=TicketStatus.OPEN):
    return Ticket(
        id=tid,
        requested_action=SensitiveAction.PASSWORD_RESET,
        subscriber_id="sub-1",
        agent_id=agent,
        status=status,
        created_at=T0,
    )


def _append(log, tid, outcome, seconds, reason=None, actor="sub-1"):
    log.append(
        ticket_id=tid,
        actor_id=actor,
        actor_role="account_holder",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=None,
        outcome=outcome,
        timestamp=T0 + timedelta(seconds=seconds),
        reason=reason,
    )


def test_percentile_nearest_rank():
    assert percentile([5, 1, 3], 50) == 3
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90) == 9
    assert percentile([7], 90) == 7


def test_compute_metrics_speed_resolutions_and_fraud():
    log = AuditLog()
    tickets = [
        _ticket("T-1", status=TicketStatus.CLOSED),
        _ticket("T-2"),
        _ticket("T-3", agent="agent-2"),
        _ticket("T-4"),
        _ticket("T-5"),
    ]
    _append(log, "T-1", AuditOutcome.APPROVED, 12)
    _append(log, "T-2", AuditOutcome.DENIED, 45)
    _append(log, "T-3", AuditOutcome.FRAUD_REPORTED, 20, reason="not me")
    _append(log, "T-4", AuditOutcome.RATE_LIMITED, 0, actor="agent-1")

    m = compute_metrics(tickets, log)

    assert (m.total_tickets, m.open_tickets, m.closed_tickets) == (5, 4, 1)
    assert m.resolutions == {
        "APPROVED": 1,
        "DENIED": 1,
        "FRAUD_REPORTED": 1,
        "BLOCKED": 1,
        "PENDING": 1,
    }
    assert m.verify_samples == 3
    assert m.median_seconds == 20
    assert round(m.within_target_pct) == 67
    assert m.fraud_ticket_ids == ["T-3"]
    by_agent = {a.agent_id: a for a in m.agents}
    assert by_agent["agent-2"].fraud_reports == 1
    assert by_agent["agent-1"].approved == 1


def test_metrics_with_no_data_has_no_speed_numbers():
    m = compute_metrics([], AuditLog())
    assert m.median_seconds is None and m.within_target_pct is None


def test_csv_export_neutralizes_formulas_and_keeps_hashes():
    log = AuditLog()
    _append(log, "T-1", AuditOutcome.APPROVED, 1)
    log.append(
        ticket_id="T-1",
        actor_id="admin-1",
        actor_role="ADMIN",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=None,
        outcome=AuditOutcome.ADMIN_OVERRIDE,
        timestamp=T0,
        reason='=HYPERLINK("http://evil.example","x")',
    )
    rows = list(csv.DictReader(io.StringIO(records_to_csv(log.all_records()))))
    assert len(rows) == 2
    assert rows[1]["reason"].startswith("'=")
    assert rows[1]["prev_hash"] == rows[0]["record_hash"]
    assert neutralize("+1") == "'+1" and neutralize("ok") == "ok"
