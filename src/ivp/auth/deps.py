"""FastAPI dependencies enforcing RBAC server-side (hard requirement 9).
Every route that needs a logged-in user or a specific permission/role goes
through these — never re-implemented ad hoc per route.
"""

from __future__ import annotations

import sqlite3

from fastapi import Depends, Request

from ivp.auth.roles import Permission, Role, has_permission
from ivp.auth.session import SESSION_COOKIE_NAME, InvalidSession, read_session_cookie
from ivp.db.sqlite_staff_repository import StaffUser, StaffUserNotFound


class NotAuthenticated(Exception):
    pass


class Forbidden(Exception):
    def __init__(self, role: Role):
        self.role = role
        super().__init__(f"role {role} is not permitted to access this route")


def get_conn(request: Request) -> sqlite3.Connection:
    return request.app.state.conn


def get_current_user(request: Request) -> StaffUser | None:
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return None
    settings = request.app.state.settings
    try:
        user_id = read_session_cookie(settings.session_secret, cookie)
    except InvalidSession:
        return None
    try:
        return request.app.state.staff_repo.get(user_id)
    except StaffUserNotFound:
        return None


def require_login(request: Request) -> StaffUser:
    user = get_current_user(request)
    if user is None:
        raise NotAuthenticated
    return user


def require_permission(permission: Permission):
    def dependency(user: StaffUser = Depends(require_login)) -> StaffUser:
        if not has_permission(user.role, permission):
            raise Forbidden(user.role)
        return user

    return dependency


def require_role(role: Role):
    def dependency(user: StaffUser = Depends(require_login)) -> StaffUser:
        if user.role != role:
            raise Forbidden(user.role)
        return user

    return dependency
