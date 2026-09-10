import pytest

from ivp.auth.authentication import InvalidCredentials, authenticate
from ivp.auth.passwords import hash_password, verify_password
from ivp.auth.roles import Role
from ivp.db.connection import connect
from ivp.db.sqlite_staff_repository import (
    SqliteStaffRepository,
    StaffUserNotFound,
    UsernameAlreadyExists,
)


def test_hash_password_round_trips():
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h)
    assert not verify_password("wrong-password", h)


def test_hash_password_does_not_store_plaintext():
    h = hash_password("hunter2")
    assert "hunter2" not in h


def test_create_and_get_by_username():
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    repo.create(username="agent.jane", password_hash=hash_password("pw"), role=Role.AGENT)
    user = repo.get_by_username("agent.jane")
    assert user.role == Role.AGENT
    conn.close()


def test_duplicate_username_rejected():
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    repo.create(username="dup", password_hash=hash_password("pw"), role=Role.AGENT)
    with pytest.raises(UsernameAlreadyExists):
        repo.create(username="dup", password_hash=hash_password("pw2"), role=Role.ADMIN)
    conn.close()


def test_get_by_username_not_found():
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    with pytest.raises(StaffUserNotFound):
        repo.get_by_username("ghost")
    conn.close()


def test_authenticate_succeeds_with_correct_password():
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    repo.create(username="admin.amy", password_hash=hash_password("s3cret"), role=Role.ADMIN)
    user = authenticate(repo, username="admin.amy", password="s3cret")
    assert user.role == Role.ADMIN
    conn.close()


def test_authenticate_fails_with_wrong_password():
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    repo.create(username="admin.amy", password_hash=hash_password("s3cret"), role=Role.ADMIN)
    with pytest.raises(InvalidCredentials):
        authenticate(repo, username="admin.amy", password="wrong")
    conn.close()


def test_authenticate_fails_for_unknown_username_with_same_error_type():
    """Same exception for unknown username vs. wrong password, so a login
    form can't be used to enumerate valid usernames."""
    conn = connect(":memory:")
    repo = SqliteStaffRepository(conn)
    with pytest.raises(InvalidCredentials):
        authenticate(repo, username="nobody", password="whatever")
    conn.close()
