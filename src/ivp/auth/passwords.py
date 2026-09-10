"""Argon2 password hashing for staff dashboard login. This authenticates
staff *to the dashboard* — a separate concern from the account holder's
out-of-band verification (see docs/decisions/persistence-and-tooling.md);
never conflate the two in code or in audit-log actor fields.
"""

from __future__ import annotations

from passlib.context import CryptContext

_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plaintext: str) -> str:
    return _context.hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    return _context.verify(plaintext, password_hash)
