from datetime import datetime, timedelta

import pytest

from ivp.core.state_machine import (
    InvalidTransition,
    VerificationAttempt,
    VerificationState,
)

NOW = datetime(2026, 1, 1, 12, 0, 0)


def make_attempt(**overrides) -> VerificationAttempt:
    defaults = dict(
        ticket_id="T-1",
        requested_action="PASSWORD_RESET",
        channel_id="chan-1",
        max_attempts=3,
        timeout=timedelta(minutes=4),
    )
    defaults.update(overrides)
    return VerificationAttempt(**defaults)


def test_starts_in_requested():
    attempt = make_attempt()
    assert attempt.state == VerificationState.REQUESTED
    assert attempt.attempt_number == 0
    assert not attempt.is_closure_eligible


def test_start_with_no_enrolled_channel_blocks_and_never_reaches_closure_eligible():
    attempt = make_attempt(channel_id=None)
    attempt.start(has_enrolled_channel=False, now=NOW)
    assert attempt.state == VerificationState.NO_CHANNEL_BLOCKED
    assert not attempt.is_closure_eligible


def test_start_with_enrolled_channel_enters_pending_and_counts_first_attempt():
    attempt = make_attempt()
    attempt.start(has_enrolled_channel=True, now=NOW)
    assert attempt.state == VerificationState.PENDING_CONFIRMATION
    assert attempt.attempt_number == 1
    assert attempt.pending_since == NOW
    assert not attempt.is_closure_eligible


def test_approve_from_pending_is_closure_eligible():
    attempt = make_attempt()
    attempt.start(has_enrolled_channel=True, now=NOW)
    attempt.approve()
    assert attempt.state == VerificationState.APPROVED
    assert attempt.is_closure_eligible


def test_deny_from_pending_is_also_closure_eligible():
    """A refusal is still a verification record: requirement 3 blocks
    closure without a record, not without an approval."""
    attempt = make_attempt()
    attempt.start(has_enrolled_channel=True, now=NOW)
    attempt.deny()
    assert attempt.state == VerificationState.DENIED
    assert attempt.is_closure_eligible


@pytest.mark.parametrize("method", ["approve", "deny"])
def test_approve_or_deny_outside_pending_raises(method):
    attempt = make_attempt()
    with pytest.raises(InvalidTransition):
        getattr(attempt, method)()


def test_check_timeout_false_before_timeout_elapses():
    attempt = make_attempt(timeout=timedelta(minutes=4))
    attempt.start(has_enrolled_channel=True, now=NOW)
    changed = attempt.check_timeout(NOW + timedelta(minutes=3, seconds=59))
    assert changed is False
    assert attempt.state == VerificationState.PENDING_CONFIRMATION


def test_check_timeout_true_after_timeout_elapses():
    attempt = make_attempt(timeout=timedelta(minutes=4))
    attempt.start(has_enrolled_channel=True, now=NOW)
    changed = attempt.check_timeout(NOW + timedelta(minutes=4))
    assert changed is True
    assert attempt.state == VerificationState.EXPIRED


def test_expired_with_attempts_remaining_can_retry_and_is_not_yet_closure_eligible():
    attempt = make_attempt(max_attempts=3)
    attempt.start(has_enrolled_channel=True, now=NOW)
    attempt.check_timeout(NOW + timedelta(minutes=4))
    assert attempt.state == VerificationState.EXPIRED
    assert attempt.can_retry()
    assert not attempt.is_closure_eligible

    attempt.retry(now=NOW + timedelta(minutes=4))
    assert attempt.state == VerificationState.PENDING_CONFIRMATION
    assert attempt.attempt_number == 2


def test_expired_after_exhausting_max_attempts_is_final_and_closure_eligible():
    attempt = make_attempt(max_attempts=2, timeout=timedelta(minutes=4))
    t = NOW
    attempt.start(has_enrolled_channel=True, now=t)  # attempt 1

    t += timedelta(minutes=4)
    attempt.check_timeout(t)
    assert attempt.attempt_number == 1
    assert attempt.can_retry()
    attempt.retry(now=t)  # attempt 2

    t += timedelta(minutes=4)
    attempt.check_timeout(t)
    assert attempt.state == VerificationState.EXPIRED
    assert attempt.attempt_number == 2
    assert not attempt.can_retry()
    assert attempt.is_closure_eligible


def test_retry_when_not_eligible_raises():
    attempt = make_attempt(max_attempts=1)
    attempt.start(has_enrolled_channel=True, now=NOW)
    attempt.check_timeout(NOW + timedelta(minutes=4))
    assert not attempt.can_retry()
    with pytest.raises(InvalidTransition):
        attempt.retry(now=NOW + timedelta(minutes=4))


def test_check_timeout_outside_pending_raises():
    attempt = make_attempt()
    with pytest.raises(InvalidTransition):
        attempt.check_timeout(NOW)


def test_start_twice_raises():
    attempt = make_attempt()
    attempt.start(has_enrolled_channel=True, now=NOW)
    with pytest.raises(InvalidTransition):
        attempt.start(has_enrolled_channel=True, now=NOW)
