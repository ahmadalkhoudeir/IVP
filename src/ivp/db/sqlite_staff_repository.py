from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass

from ivp.auth.roles import Role


class StaffUserNotFound(Exception):
    pass


class UsernameAlreadyExists(Exception):
    pass


@dataclass(frozen=True)
class StaffUser:
    id: str
    username: str
    password_hash: str
    role: Role


class SqliteStaffRepository:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(self, *, username: str, password_hash: str, role: Role) -> StaffUser:
        if self._conn.execute(
            "SELECT 1 FROM staff_users WHERE username = ?", (username,)
        ).fetchone():
            raise UsernameAlreadyExists(username)
        user_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO staff_users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (user_id, username, password_hash, role.value),
        )
        self._conn.commit()
        return StaffUser(id=user_id, username=username, password_hash=password_hash, role=role)

    def get_by_username(self, username: str) -> StaffUser:
        row = self._conn.execute(
            "SELECT * FROM staff_users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            raise StaffUserNotFound(username)
        return self._row_to_user(row)

    def get(self, user_id: str) -> StaffUser:
        row = self._conn.execute("SELECT * FROM staff_users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise StaffUserNotFound(user_id)
        return self._row_to_user(row)

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> StaffUser:
        return StaffUser(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=Role(row["role"]),
        )
