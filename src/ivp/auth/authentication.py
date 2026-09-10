from __future__ import annotations

from typing import Protocol

from ivp.auth.passwords import verify_password
from ivp.db.sqlite_staff_repository import StaffUser, StaffUserNotFound


class InvalidCredentials(Exception):
    pass


class StaffUserLookup(Protocol):
    def get_by_username(self, username: str) -> StaffUser: ...


def authenticate(repository: StaffUserLookup, *, username: str, password: str) -> StaffUser:
    try:
        user = repository.get_by_username(username)
    except StaffUserNotFound as exc:
        # Same error as a wrong password: don't leak whether the username
        # exists.
        raise InvalidCredentials("invalid username or password") from exc
    if not verify_password(password, user.password_hash):
        raise InvalidCredentials("invalid username or password")
    return user
