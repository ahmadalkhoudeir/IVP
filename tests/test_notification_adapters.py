from datetime import UTC, datetime, timedelta

import pytest

from ivp.adapters.notification.mock_pstn import MockPstnAdapter, RiskSignals
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.adapters.notification.rate_limit import RateLimitExceeded, SlidingWindowRateLimiter

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_sliding_window_allows_up_to_max_sends():
    limiter = SlidingWindowRateLimiter(max_sends=3, window=timedelta(minutes=10))
    for i in range(3):
        limiter.check_and_record("chan-1", T0 + timedelta(seconds=i))  # must not raise


def test_sliding_window_blocks_beyond_max_sends():
    limiter = SlidingWindowRateLimiter(max_sends=3, window=timedelta(minutes=10))
    for i in range(3):
        limiter.check_and_record("chan-1", T0 + timedelta(seconds=i))
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_record("chan-1", T0 + timedelta(seconds=3))


def test_sliding_window_recovers_after_the_window_passes():
    limiter = SlidingWindowRateLimiter(max_sends=2, window=timedelta(minutes=10))
    limiter.check_and_record("chan-1", T0)
    limiter.check_and_record("chan-1", T0 + timedelta(minutes=1))
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_record("chan-1", T0 + timedelta(minutes=2))
    # first two sends have now aged out of the 10-minute window
    limiter.check_and_record("chan-1", T0 + timedelta(minutes=11, seconds=1))


def test_sliding_window_is_scoped_per_key():
    """Rate limiting is per-destination (channel_id), not global — one
    victim being bombed must not exhaust another subscriber's quota, and a
    single limiter instance must still isolate destinations correctly."""
    limiter = SlidingWindowRateLimiter(max_sends=1, window=timedelta(minutes=10))
    limiter.check_and_record("victim-channel", T0)
    limiter.check_and_record("other-channel", T0)  # must not raise
    with pytest.raises(RateLimitExceeded):
        limiter.check_and_record("victim-channel", T0 + timedelta(seconds=1))


def test_push_adapter_records_sends():
    adapter = MockPushAdapter()
    adapter.send_confirmation(channel_id="push-1", ticket_id="T-1", code="482913", now=T0)
    assert len(adapter.sent) == 1
    assert adapter.sent[0].code == "482913"


def test_push_adapter_enforces_rate_limit_across_tickets_for_same_destination():
    """A push-bombing attacker opening multiple tickets against the same
    victim channel must still be caught."""
    adapter = MockPushAdapter()
    for i in range(5):
        adapter.send_confirmation(
            channel_id="victim-push",
            ticket_id=f"T-{i}",
            code="000000",
            now=T0 + timedelta(seconds=i),
        )
    with pytest.raises(RateLimitExceeded):
        adapter.send_confirmation(
            channel_id="victim-push",
            ticket_id="T-attack",
            code="111111",
            now=T0 + timedelta(seconds=6),
        )


def test_pstn_adapter_default_risk_signals_are_clean():
    adapter = MockPstnAdapter()
    signals = adapter.check_risk_signals("phone-1")
    assert not signals.has_risk


def test_pstn_adapter_reports_seeded_risk_signals():
    adapter = MockPstnAdapter(risk_overrides={"phone-1": RiskSignals(sim_swap_detected=True)})
    signals = adapter.check_risk_signals("phone-1")
    assert signals.has_risk
    assert signals.sim_swap_detected


def test_pstn_adapter_has_a_lower_default_rate_limit_than_push():
    """Not load-bearing on a specific number, just documents that PSTN
    (restricted authenticator) is treated at least as conservatively as
    push."""
    from ivp.adapters.notification.mock_pstn import DEFAULT_MAX_SENDS as PSTN_MAX
    from ivp.adapters.notification.mock_push import DEFAULT_MAX_SENDS as PUSH_MAX

    assert PSTN_MAX <= PUSH_MAX
