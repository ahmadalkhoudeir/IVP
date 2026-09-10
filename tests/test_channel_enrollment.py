from datetime import UTC, datetime

from ivp.core.models import ChannelType
from ivp.db.connection import connect
from ivp.db.sqlite_channel_repository import SqliteChannelRepository, fingerprint

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_enroll_stores_fingerprint_not_raw_destination():
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    enrollment = repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Demo phone",
        destination="synthetic-push-token-123",
        now=T0,
    )
    assert enrollment.destination_fingerprint == fingerprint("synthetic-push-token-123")
    assert "synthetic-push-token-123" not in enrollment.destination_fingerprint
    conn.close()


def test_subscriber_can_enroll_multiple_channels():
    """Project owner decision: allow more than one enrolled channel per
    subscriber, for redundancy."""
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PSTN,
        label="Backup line",
        destination="+15550000000",
        now=T0,
    )
    enrollments = repo.list_for_subscriber("sub-1")
    assert len(enrollments) == 2
    assert {e.channel_type for e in enrollments} == {ChannelType.PUSH, ChannelType.PSTN}
    conn.close()


def test_has_any_enrollment_false_when_none_exist():
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    assert not repo.has_any_enrollment("sub-unknown")
    conn.close()


def test_has_any_enrollment_true_after_enrolling():
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    assert repo.has_any_enrollment("sub-1")
    conn.close()


def test_fingerprint_is_deterministic_and_collision_resistant_in_practice():
    assert fingerprint("same-input") == fingerprint("same-input")
    assert fingerprint("input-a") != fingerprint("input-b")


def test_list_distinct_subscribers_returns_each_once():
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-a",
        now=T0,
    )
    repo.enroll(
        subscriber_id="sub-1",
        channel_type=ChannelType.PSTN,
        label="Backup",
        destination="+15550000000",
        now=T0,
    )
    repo.enroll(
        subscriber_id="sub-2",
        channel_type=ChannelType.PUSH,
        label="Phone",
        destination="push-token-b",
        now=T0,
    )
    assert repo.list_distinct_subscribers() == ["sub-1", "sub-2"]
    conn.close()


def test_list_distinct_subscribers_empty_when_none_enrolled():
    conn = connect(":memory:")
    repo = SqliteChannelRepository(conn)
    assert repo.list_distinct_subscribers() == []
    conn.close()
