from datetime import UTC, datetime, timedelta

import pytest

from ivp.core.models import SensitiveAction
from ivp.core.state_machine import VerificationState
from ivp.db.connection import connect
from ivp.db.sqlite_verification_repository import (
    SqliteVerificationRepository,
    VerificationAttemptNotFound,
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_create_and_get_round_trips():
    conn = connect(":memory:")
    repo = SqliteVerificationRepository(conn)
    attempt_id, attempt = repo.create(
        ticket_id="T-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_id="chan-1",
        code="482913",
        max_attempts=3,
        timeout=timedelta(minutes=4),
    )
    attempt.start(has_enrolled_channel=True, now=T0)
    repo.save(attempt_id, attempt, "482913")

    reloaded, code = repo.get(attempt_id)
    assert code == "482913"
    assert reloaded.state == VerificationState.PENDING_CONFIRMATION
    assert reloaded.attempt_number == 1
    assert reloaded.pending_since == T0
    assert reloaded.channel_id == "chan-1"
    assert reloaded.max_attempts == 3
    assert reloaded.timeout == timedelta(minutes=4)


def test_get_missing_raises():
    conn = connect(":memory:")
    repo = SqliteVerificationRepository(conn)
    with pytest.raises(VerificationAttemptNotFound):
        repo.get("nope")


def test_latest_for_ticket_returns_most_recent():
    conn = connect(":memory:")
    repo = SqliteVerificationRepository(conn)
    repo.create(
        ticket_id="T-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_id="chan-1",
        code="111111",
        max_attempts=3,
        timeout=timedelta(minutes=4),
    )
    second_id, _second = repo.create(
        ticket_id="T-1",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_id="chan-1",
        code="222222",
        max_attempts=3,
        timeout=timedelta(minutes=4),
    )
    result = repo.latest_for_ticket("T-1")
    assert result is not None
    attempt_id, _attempt, code = result
    assert attempt_id == second_id
    assert code == "222222"


def test_latest_for_ticket_none_when_no_attempts_exist():
    conn = connect(":memory:")
    repo = SqliteVerificationRepository(conn)
    assert repo.latest_for_ticket("T-none") is None


def test_full_state_transitions_persist_correctly():
    conn = connect(":memory:")
    repo = SqliteVerificationRepository(conn)
    attempt_id, attempt = repo.create(
        ticket_id="T-1",
        requested_action=SensitiveAction.MFA_RESET,
        channel_id="chan-1",
        code="482913",
        max_attempts=3,
        timeout=timedelta(minutes=4),
    )
    attempt.start(has_enrolled_channel=True, now=T0)
    attempt.approve()
    repo.save(attempt_id, attempt, "482913")

    reloaded, _code = repo.get(attempt_id)
    assert reloaded.state == VerificationState.APPROVED
    assert reloaded.is_closure_eligible
