"""Verification-start blocks (rate limit, carrier risk, cooling-off),
restart semantics, fraud reporting, and code generation at the orchestrator
layer, below the web UI."""

from datetime import timedelta

import pytest

from ivp.adapters.notification.mock_pstn import RiskSignals
from ivp.adapters.notification.rate_limit import SlidingWindowRateLimiter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.core.state_machine import VerificationState
from ivp.core.ticket import ClosureBlocked
from ivp.services.verification_service import ConfirmationResult, generate_code
from tests.test_verification_service import T0, build_orchestrator


def _enroll(orchestrator, sub, kind, dest, *, usable_from=None):
    return orchestrator.channel_repo.enroll(
        subscriber_id=sub,
        channel_type=kind,
        label=f"{sub} {kind.value}",
        destination=dest,
        now=T0,
        usable_from=usable_from,
    )


def _open(orchestrator, ticket_id, sub, now=T0):
    return orchestrator.open_ticket_and_start_verification(
        ticket_id=ticket_id,
        agent_id="agent-1",
        subscriber_id=sub,
        requested_action=SensitiveAction.PASSWORD_RESET,
        now=now,
    )


def _outcomes(orchestrator, ticket_id):
    return [r.outcome for r in orchestrator.audit_log.records_for_ticket(ticket_id)]


def test_generated_codes_are_six_digit_strings_from_a_csprng(monkeypatch):
    import ivp.services.verification_service as svc

    calls = []
    monkeypatch.setattr(svc.secrets, "randbelow", lambda n: calls.append(n) or 42)
    assert generate_code() == "000042"
    assert calls == [1_000_000]
    assert all(len(generate_code()) == 6 for _ in range(10))


def test_rate_limited_start_is_recorded_not_raised_and_ticket_stays_blocked():
    orchestrator, gate, conn = build_orchestrator()
    orchestrator.push_adapter._rate_limiter = SlidingWindowRateLimiter(
        max_sends=1, window=timedelta(minutes=10)
    )
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")

    _first, first_id = _open(orchestrator, "T-1", "sub-1")
    assert first_id is not None
    ticket, second_id = _open(orchestrator, "T-2", "sub-1", now=T0 + timedelta(seconds=5))

    assert second_id is None
    assert _outcomes(orchestrator, "T-2") == [AuditOutcome.RATE_LIMITED]
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)
    conn.close()


def test_restart_after_rate_limit_window_passes_starts_verification():
    orchestrator, _gate, conn = build_orchestrator()
    orchestrator.push_adapter._rate_limiter = SlidingWindowRateLimiter(
        max_sends=1, window=timedelta(minutes=10)
    )
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")
    _open(orchestrator, "T-1", "sub-1")
    _open(orchestrator, "T-2", "sub-1", now=T0 + timedelta(seconds=5))

    assert orchestrator.restart_verification("T-2", now=T0 + timedelta(minutes=1)) is None
    attempt_id = orchestrator.restart_verification("T-2", now=T0 + timedelta(minutes=11))
    assert attempt_id is not None
    attempt, _code = orchestrator.verification_repo.get(attempt_id)
    assert attempt.state == VerificationState.PENDING_CONFIRMATION
    conn.close()


def test_restart_is_refused_once_an_attempt_exists():
    """Restart must never re-roll a DENIED (or any started) verification."""
    orchestrator, _gate, conn = build_orchestrator()
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")
    _ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")
    orchestrator.submit_confirmation(attempt_id, selected_code="wrong", now=T0)

    assert orchestrator.restart_verification("T-1", now=T0 + timedelta(minutes=1)) is None
    assert _outcomes(orchestrator, "T-1") == [AuditOutcome.DENIED]
    conn.close()


def test_rate_limited_retry_keeps_attempt_expired_with_retry_unspent():
    orchestrator, _gate, conn = build_orchestrator(timeout=timedelta(seconds=30))
    orchestrator.push_adapter._rate_limiter = SlidingWindowRateLimiter(
        max_sends=1, window=timedelta(minutes=10)
    )
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")
    _open(orchestrator, "T-1", "sub-1")
    later = T0 + timedelta(minutes=1)
    orchestrator.check_and_apply_timeout("T-1", now=later)

    assert orchestrator.retry_verification("T-1", now=later) is None
    _id, attempt, _code = orchestrator.verification_repo.latest_for_ticket("T-1")
    assert attempt.state == VerificationState.EXPIRED
    assert attempt.attempt_number == 1
    assert attempt.can_retry()
    assert AuditOutcome.RATE_LIMITED in _outcomes(orchestrator, "T-1")
    conn.close()


def test_pstn_with_carrier_risk_and_no_alternative_is_risk_blocked():
    orchestrator, gate, conn = build_orchestrator()
    channel = _enroll(orchestrator, "sub-1", ChannelType.PSTN, "+15555550100")
    orchestrator.pstn_adapter.risk_overrides[channel.id] = RiskSignals(sim_swap_detected=True)

    ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")

    assert attempt_id is None
    assert _outcomes(orchestrator, "T-1") == [AuditOutcome.RISK_BLOCKED]
    assert orchestrator.pstn_adapter.sent == []
    with pytest.raises(ClosureBlocked):
        gate.close(ticket)
    conn.close()


def test_risky_pstn_falls_back_to_a_safe_push_channel():
    orchestrator, _gate, conn = build_orchestrator()
    risky = _enroll(orchestrator, "sub-1", ChannelType.PSTN, "+15555550100")
    orchestrator.pstn_adapter.risk_overrides[risky.id] = RiskSignals(number_recently_ported=True)
    push = _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")

    _ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")

    attempt, _code = orchestrator.verification_repo.get(attempt_id)
    assert attempt.channel_id == push.id
    assert orchestrator.pstn_adapter.sent == []
    conn.close()


def test_channel_in_cooling_off_is_not_used():
    orchestrator, _gate, conn = build_orchestrator()
    old = _enroll(orchestrator, "sub-1", ChannelType.PSTN, "+15555550100")
    _enroll(
        orchestrator, "sub-1", ChannelType.PUSH, "tok-new", usable_from=T0 + timedelta(hours=24)
    )

    _ticket, attempt_id = _open(orchestrator, "T-1", "sub-1", now=T0 + timedelta(hours=1))

    attempt, _code = orchestrator.verification_repo.get(attempt_id)
    assert attempt.channel_id == old.id, "the newer PUSH channel must wait out its cooling-off"
    conn.close()


def test_only_cooling_off_channels_blocks_with_reason():
    orchestrator, _gate, conn = build_orchestrator()
    _enroll(
        orchestrator, "sub-1", ChannelType.PUSH, "tok-new", usable_from=T0 + timedelta(hours=24)
    )
    _ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")

    assert attempt_id is None
    [record] = orchestrator.audit_log.records_for_ticket("T-1")
    assert record.outcome == AuditOutcome.NO_CHANNEL_BLOCKED
    assert "cooling-off" in record.reason
    conn.close()


def test_fraud_report_denies_blocks_action_but_allows_closure():
    orchestrator, gate, conn = build_orchestrator()
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")
    ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")

    assert orchestrator.report_fraud(attempt_id, now=T0) == ConfirmationResult.FRAUD_REPORTED

    attempt, _code = orchestrator.verification_repo.get(attempt_id)
    assert attempt.state == VerificationState.DENIED
    [record] = orchestrator.audit_log.records_for_ticket("T-1")
    assert record.outcome == AuditOutcome.FRAUD_REPORTED
    assert record.actor_id == "sub-1"
    assert record.reason
    with pytest.raises(ClosureBlocked):
        gate.authorize_action(ticket)
    gate.close(ticket)
    orchestrator.audit_log.verify_integrity()
    conn.close()


def test_fraud_report_after_resolution_is_logged_as_replay():
    orchestrator, _gate, conn = build_orchestrator()
    _enroll(orchestrator, "sub-1", ChannelType.PUSH, "tok-1")
    _ticket, attempt_id = _open(orchestrator, "T-1", "sub-1")
    _attempt, code = orchestrator.verification_repo.get(attempt_id)
    orchestrator.submit_confirmation(attempt_id, selected_code=code, now=T0)

    assert orchestrator.report_fraud(attempt_id, now=T0) == ConfirmationResult.ALREADY_RESOLVED
    assert _outcomes(orchestrator, "T-1") == [AuditOutcome.APPROVED, AuditOutcome.REJECTED]
    conn.close()
