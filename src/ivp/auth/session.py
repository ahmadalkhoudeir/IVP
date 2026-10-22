"""Signed, HttpOnly session cookie for staff dashboard login. Not a JWT —
just a signed user_id, verified server-side against the staff_users table
on every request (auth/deps.py), so a revoked/deleted account stops working
immediately rather than waiting out a token's validity window.
"""

from __future__ import annotations

from itsdangerous import BadSignature, URLSafeTimedSerializer

SESSION_COOKIE_NAME = "ivp_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60  # 8 hours
# Admins can override the closure gate, enroll channels and create staff
# accounts, so their sessions are much shorter (docs/threat-model.md,
# "short session lifetime for the admin role"). NIST SP 800-63B-4 Sec. 2.3.3
# puts the AAL3 inactivity timeout at no more than 15 minutes and the
# overall timeout at 12 hours; one hour overall is a demo-friendly middle.
ADMIN_SESSION_MAX_AGE_SECONDS = 60 * 60  # 1 hour


class InvalidSession(Exception):
    pass


def create_session_cookie(secret: str, user_id: str) -> str:
    serializer = URLSafeTimedSerializer(secret, salt="ivp-staff-session")
    return serializer.dumps({"user_id": user_id})


def read_session_cookie(
    secret: str, cookie_value: str, *, max_age: int = SESSION_MAX_AGE_SECONDS
) -> str:
    serializer = URLSafeTimedSerializer(secret, salt="ivp-staff-session")
    try:
        data = serializer.loads(cookie_value, max_age=max_age)
    except BadSignature as exc:
        raise InvalidSession("invalid or expired session") from exc
    return data["user_id"]
