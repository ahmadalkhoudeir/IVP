from datetime import UTC, datetime, timedelta

import pytest

from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction, TicketStatus
from ivp.core.state_machine import VerificationState
from ivp.core.ticket import ClosureBlocked, TicketClosureGate
from ivp.db.connection import connect
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import SqliteChannelRepository
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository
from ivp.db.sqlite_verification_repository import SqliteVerificationRepository
from ivp.services.verification_service import ConfirmationResult, VerificationOrchestrator

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def build_orchestrator(*, max_attempts: int = 3, timeout: timedelta = timedelta(minutes=4)):
    conn = connect(":memory:")
    audit_log = SqliteAuditLog(conn)
    orchestrator = VerificationOrchestrator(
        ticket_repo=SqliteTicketRepository(conn),
        channel_repo=SqliteChannelRepository(conn),
        verification_repo=SqliteVerificationRepository(conn),
        audit_log=audit_log,
        push_adapter=MockPushAdapter(),
        pstn_adapter=MockPstnAdapter(),
        max_attempts=max_attempts,
        timeout=timeout,
    )
    gate = TicketClosureGate(audit_log)
    return orchestrator, gate, conn


def test_no_enrolled_channel_blocks_and_records_it():
    orchestrator, gate, conn = build_orchestrator()
    ticket, attempt_id = orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-no-channel",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    assert attempt_id is None
    [record] = orchestrator.audit_log.records_for_ticket("T-1")
    assert record.outcome == AuditOutcome.NO_CHANNEL_BLOCKED
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)
    conn.close()


def test_happy_path_approve_and_close():
    orchestrator, gate, conn = build_orchestrator()
    orchestrator.channel_repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    ticket, attempt_id = orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    assert attempt_id is not None
    assert len(orchestrator.push_adapter.sent) == 1
    sent_code = orchestrator.push_adapter.sent[0].code

    result = orchestrator.submit_confirmation(attempt_id, selected_code=sent_code, now=T0)
    assert result == ConfirmationResult.APPROVED

    gate.authorize_action(ticket)
    gate.close(ticket)
    assert ticket.action_performed
    assert ticket.status == TicketStatus.CLOSED
    conn.close()


def test_wrong_code_denies():
    orchestrator, gate, conn = build_orchestrator()
    orchestrator.channel_repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    ticket, attempt_id = orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    result = orchestrator.submit_confirmation(attempt_id, selected_code="000000", now=T0)
    assert result == ConfirmationResult.DENIED
    gate.close(ticket)  # allowed: DENIED is still a record
    assert ticket.status == TicketStatus.CLOSED
    assert not ticket.action_performed
    conn.close()


def test_replayed_confirmation_after_resolution_is_rejected_and_does_not_flip_outcome():
    orchestrator, _gate, conn = build_orchestrator()
    orchestrator.channel_repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    _ticket, attempt_id = orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    sent_code = orchestrator.push_adapter.sent[0].code
    orchestrator.submit_confirmation(attempt_id, selected_code=sent_code, now=T0)

    # Someone replays the same confirmation link, this time trying to deny.
    result = orchestrator.submit_confirmation(attempt_id, selected_code="999999", now=T0)
    assert result == ConfirmationResult.ALREADY_RESOLVED

    records = orchestrator.audit_log.records_for_ticket("T-1")
    outcomes = [r.outcome for r in records]
    assert outcomes.count(AuditOutcome.APPROVED) == 1
    assert AuditOutcome.REJECTED in outcomes
    conn.close()


def test_timeout_without_retry_writes_final_expired_record():
    orchestrator, gate, conn = build_orchestrator(max_attempts=1, timeout=timedelta(minutes=4))
    orchestrator.channel_repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    ticket, _attempt_id = orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    orchestrator.check_and_apply_timeout("T-1", now=T0 + timedelta(minutes=5))
    [record] = orchestrator.audit_log.records_for_ticket("T-1")
    assert record.outcome == AuditOutcome.EXPIRED
    gate.close(ticket)
    conn.close()


def test_timeout_with_retries_remaining_does_not_write_a_record_yet():
    orchestrator, _gate, conn = build_orchestrator(max_attempts=3, timeout=timedelta(minutes=4))
    orchestrator.channel_repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    orchestrator.open_ticket_and_start_verification(
        ticket_id="T-1",
        agent_id="agent-1",
        subscriber_id="sub-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=T0,
    )
    orchestrator.check_and_apply_timeout("T-1", now=T0 + timedelta(minutes=5))
    assert orchestrator.audit_log.records_for_ticket("T-1") == []

    retry_attempt_id = orchestrator.retry_verification("T-1", now=T0 + timedelta(minutes=5))
    assert retry_attempt_id is not None
    attempt, _code = orchestrator.verification_repo.get(retry_attempt_id)
    assert attempt.state == VerificationState.PENDING_CONFIRMATION
    assert attempt.attempt_number == 2
    assert len(orchestrator.push_adapter.sent) == 2  # original send + retry send
    conn.close()
