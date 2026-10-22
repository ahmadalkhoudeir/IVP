from datetime import UTC, datetime, timedelta

from ivp.auth.throttle import LoginThrottle

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_locks_after_max_failures_and_unlocks_after_window():
    throttle = LoginThrottle(max_failures=3, window=timedelta(minutes=15))
    for i in range(3):
        assert not throttle.is_locked("agent1", T0)
        throttle.record_failure("agent1", T0 + timedelta(seconds=i))
    assert throttle.is_locked("agent1", T0 + timedelta(minutes=1))
    assert throttle.is_locked("AGENT1", T0 + timedelta(minutes=1)), "case-insensitive"
    assert not throttle.is_locked("agent1", T0 + timedelta(minutes=16))


def test_success_clears_failures_and_users_are_independent():
    throttle = LoginThrottle(max_failures=2)
    throttle.record_failure("a", T0)
    throttle.record_success("a")
    throttle.record_failure("a", T0)
    assert not throttle.is_locked("a", T0)
    throttle.record_failure("b", T0)
    throttle.record_failure("b", T0)
    assert throttle.is_locked("b", T0)
    assert not throttle.is_locked("a", T0)
