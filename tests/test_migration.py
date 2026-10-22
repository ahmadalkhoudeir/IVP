"""A database created by v1.0 (before cooling-off and closed_at existed)
must open cleanly and gain the new columns without touching audit rows."""

import sqlite3

from ivp.db.connection import connect

V1_SCHEMA = """
CREATE TABLE channel_enrollments (
    id TEXT PRIMARY KEY, subscriber_id TEXT NOT NULL, channel_type TEXT NOT NULL,
    label TEXT NOT NULL, destination_fingerprint TEXT NOT NULL, enrolled_at TEXT NOT NULL
);
CREATE TABLE tickets (
    id TEXT PRIMARY KEY, requested_action TEXT NOT NULL, status TEXT NOT NULL,
    action_performed INTEGER NOT NULL DEFAULT 0, agent_id TEXT NOT NULL,
    subscriber_id TEXT NOT NULL, created_at TEXT NOT NULL
);
INSERT INTO channel_enrollments VALUES
    ('c1', 'sub-1', 'PUSH', 'Phone', 'fp', '2026-01-01T00:00:00+00:00');
"""


def test_v1_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(V1_SCHEMA)
    old.commit()
    old.close()

    conn = connect(str(path))
    from ivp.db.sqlite_channel_repository import SqliteChannelRepository

    [channel] = SqliteChannelRepository(conn).list_for_subscriber("sub-1")
    assert channel.usable_from is None
    assert channel.is_usable(channel.enrolled_at), "legacy rows are usable from enrollment"
    ticket_cols = {r["name"] for r in conn.execute("PRAGMA table_info(tickets)")}
    assert "closed_at" in ticket_cols
    conn.close()
    connect(str(path)).close()  # idempotent second open
