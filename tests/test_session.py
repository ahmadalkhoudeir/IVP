import time

import pytest

from ivp.auth.session import InvalidSession, create_session_cookie, read_session_cookie


def test_round_trips_user_id():
    cookie = create_session_cookie("secret", "user-123")
    assert read_session_cookie("secret", cookie) == "user-123"


def test_wrong_secret_rejected():
    cookie = create_session_cookie("secret-a", "user-123")
    with pytest.raises(InvalidSession):
        read_session_cookie("secret-b", cookie)


def test_tampered_cookie_rejected():
    cookie = create_session_cookie("secret", "user-123")
    with pytest.raises(InvalidSession):
        read_session_cookie("secret", cookie + "tampered")


def test_expired_cookie_rejected(monkeypatch):
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer("secret", salt="ivp-staff-session")
    old_cookie = serializer.dumps({"user_id": "user-123"})

    # Simulate the cookie having been issued far in the past by monkeypatching
    # time.time() forward past SESSION_MAX_AGE_SECONDS.
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 100_000)
    with pytest.raises(InvalidSession):
        read_session_cookie("secret", old_cookie)
