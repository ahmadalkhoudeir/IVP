"""Synthetic demo data for the docker-compose out-of-the-box demo
(requirement 7: no real credentials or personal data). Runs only when
IVP_SEED_DEMO_DATA=true and only if no staff accounts exist yet, so it
never clobbers data from a real deployment.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ivp.adapters.notification.mock_pstn import MockPstnAdapter, RiskSignals
from ivp.auth.passwords import hash_password
from ivp.auth.roles import Role
from ivp.core.models import ChannelType
from ivp.db.sqlite_channel_repository import SqliteChannelRepository, fingerprint
from ivp.db.sqlite_staff_repository import SqliteStaffRepository

DEMO_TEAM = "team-demo"

# Synthetic-only, documented here in the open on purpose: this is seed data
# for a local demo, never a real deployment (see .env.example and
# IVP_SEED_DEMO_DATA).
DEMO_STAFF = [
    ("agent1", "agent-demo-pass-1", Role.AGENT, DEMO_TEAM),
    ("agent2", "agent-demo-pass-2", Role.AGENT, DEMO_TEAM),
    ("supervisor1", "supervisor-demo-pass-1", Role.SUPERVISOR, DEMO_TEAM),
    ("admin1", "admin-demo-pass-1", Role.ADMIN, None),
]

DEMO_SUBSCRIBERS = [
    ("sub-alice", "Alice Demo", [(ChannelType.PUSH, "Alice's phone", "demo-push-token-alice")]),
    ("sub-bob", "Bob Demo", [(ChannelType.PSTN, "Bob's cell", "+15555550123")]),
    ("sub-carol", "Carol Demo (no enrolled channel)", []),
    (
        "sub-erin",
        "Erin Demo (SMS only, number recently ported)",
        [(ChannelType.PSTN, "Erin's cell", "+15555550188")],
    ),
]

# Destinations the mock carrier feed reports as recently ported, so the
# demo can show RISK_BLOCKED (NIST SP 800-63B-4 restricted-authenticator
# risk indicators). Synthetic 555 numbers only.
DEMO_PORTED_DESTINATIONS = frozenset({"+15555550188"})


def seed_if_empty(staff_repo: SqliteStaffRepository, channel_repo: SqliteChannelRepository) -> None:
    """Staff accounts are seeded only into an empty database. Demo
    subscriber channels are topped up idempotently (by destination
    fingerprint), so a demo database created by an earlier version also
    gets subscribers added later, such as sub-erin."""
    if not staff_repo.list_all():
        for username, password, role, team_id in DEMO_STAFF:
            staff_repo.create(
                username=username,
                password_hash=hash_password(password),
                role=role,
                team_id=team_id,
            )

    now = datetime.now(UTC)
    for subscriber_id, _display_name, channels in DEMO_SUBSCRIBERS:
        for channel_type, label, destination in channels:
            if channel_repo.fingerprint_exists(subscriber_id, destination):
                continue
            channel_repo.enroll(
                subscriber_id=subscriber_id,
                channel_type=channel_type,
                label=label,
                destination=destination,
                now=now,
            )


def apply_demo_risk_signals(
    channel_repo: SqliteChannelRepository, pstn_adapter: MockPstnAdapter
) -> None:
    """Simulate a carrier risk feed for the demo. Matches by destination
    fingerprint, since only fingerprints are stored. Runs on every startup
    because the mock adapter's state is in-memory."""
    flagged = {fingerprint(d) for d in DEMO_PORTED_DESTINATIONS}
    for subscriber_id in channel_repo.list_distinct_subscribers():
        for channel in channel_repo.list_for_subscriber(subscriber_id):
            if channel.destination_fingerprint in flagged:
                pstn_adapter.risk_overrides[channel.id] = RiskSignals(
                    number_recently_ported=True
                )
