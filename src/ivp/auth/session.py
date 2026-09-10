"""Signed, HttpOnly session cookie for staff dashboard login. Not a JWT —
just a signed user_id, verified server-side against the staff_users table
on every request (auth/deps.py), so a revoked/deleted account stops working
immediately rather than waiting out a token's validity window.
"""

from __future__ import annotations

from itsdangerous import BadSignature, URLSafeTimedSerializer

SESSION_COOKIE_NAME = "ivp_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60  # 8 hours


class InvalidSession(Exception):
    pass


def create_session_cookie(secret: str, user_id: str) -> str:
    serializer = URLSafeTimedSerializer(secret, salt="ivp-staff-session")
    return serializer.dumps({"user_id": user_id})


def read_session_cookie(secret: str, cookie_value: str) -> str:
    serializer = URLSafeTimedSerializer(secret, salt="ivp-staff-session")
    try:
        data = serializer.loads(cookie_value, max_age=SESSION_MAX_AGE_SECONDS)
    except BadSignature as exc:
        raise InvalidSession("invalid or expired session") from exc
    return data["user_id"]
