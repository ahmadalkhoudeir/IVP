"""SQLite connection + schema. SQLite is the default persistence per
docs/decisions/persistence-and-tooling.md.

The audit_log table has BEFORE UPDATE / BEFORE DELETE triggers that abort
the statement. This is a deliberate second layer of enforcement for hard
requirement 4 on top of the Python layer (db/sqlite_audit_log.py exposes no
update/delete method) — even a bug that somehow issued an UPDATE or DELETE
against this table would be rejected by the database itself.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    sequence INTEGER PRIMARY KEY,
    ticket_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    channel_type TEXT,
    outcome TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ticket_id ON audit_log (ticket_id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    requested_action TEXT NOT NULL,
    status TEXT NOT NULL,
    action_performed INTEGER NOT NULL DEFAULT 0,
    agent_id TEXT NOT NULL,
    subscriber_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- team_id groups agents and supervisors for the supervisor's scoped view
-- (docs/threat-model.md, Information Disclosure: "supervisor view scoped
-- to their own team, not global"). NULL for admin, who is not team-scoped.
CREATE TABLE IF NOT EXISTS staff_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    team_id TEXT
);

CREATE TABLE IF NOT EXISTS channel_enrollments (
    id TEXT PRIMARY KEY,
    subscriber_id TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    label TEXT NOT NULL,
    destination_fingerprint TEXT NOT NULL,
    enrolled_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channel_enrollments_subscriber
    ON channel_enrollments (subscriber_id);

-- One row per verification effort for a ticket. `code` is the
-- number-matching code the agent reads aloud (CISA guidance, see
-- docs/threat-model.md). Reconstructed into a core.state_machine
-- VerificationAttempt by the repository layer.
CREATE TABLE IF NOT EXISTS verification_attempts (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    channel_id TEXT,
    code TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    pending_since TEXT
);

CREATE INDEX IF NOT EXISTS idx_verification_attempts_ticket
    ON verification_attempts (ticket_id);
"""


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
