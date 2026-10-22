from datetime import timedelta

import pytest

from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.db.connection import connect
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import SqliteChannelRepository
from ivp.services.enrollment_service import ChannelEnrollmentService, EnrollmentRejected
from tests.test_verification_service import T0


@pytest.fixture
def service():
    conn = connect(":memory:")
    svc = ChannelEnrollmentService(
        channel_repo=SqliteChannelRepository(conn),
        audit_log=SqliteAuditLog(conn),
        push_adapter=MockPushAdapter(),
        pstn_adapter=MockPstnAdapter(),
        cooling_off=timedelta(hours=24),
    )
    yield svc
    conn.close()


def _enroll(svc, sub="sub-1", kind=ChannelType.PUSH, dest="tok-1", label="Phone"):
    return svc.enroll(
        subscriber_id=sub,
        channel_type=kind,
        label=label,
        destination=dest,
        actor_id="admin-1",
        actor_role="ADMIN",
        now=T0,
    )


def test_first_channel_is_usable_immediately_and_audited(service):
    result = _enroll(service)
    assert not result.cooling_off_applied
    assert result.enrollment.is_usable(T0)
    [record] = service.audit_log.all_records()
    assert record.outcome == AuditOutcome.CHANNEL_ENROLLED
    assert record.requested_action == SensitiveAction.CHANNEL_ENROLLMENT
    assert record.actor_id == "admin-1"
    assert record.ticket_id.startswith("ENR-")
    assert "tok-1" not in (record.reason or ""), "raw destination must never be logged"


def test_additional_channel_notifies_existing_and_cools_off(service):
    first = _enroll(service)
    second = _enroll(service, kind=ChannelType.PSTN, dest="+15555550100", label="Cell")

    assert second.cooling_off_applied
    assert second.notified_channels == 1
    assert not second.enrollment.is_usable(T0 + timedelta(hours=23))
    assert second.enrollment.is_usable(T0 + timedelta(hours=24))
    [notice] = service.push_adapter.enrollment_notices
    assert notice.channel_id == first.enrollment.id
    assert notice.new_channel_label == "Cell"
    service.audit_log.verify_integrity()


def test_cooling_off_survives_a_round_trip_through_the_database(service):
    _enroll(service)
    _enroll(service, dest="tok-2", label="Tablet")
    stored = service.channel_repo.list_for_subscriber("sub-1")
    assert [c.is_usable(T0) for c in stored] == [True, False]


def test_duplicate_destination_is_rejected(service):
    _enroll(service)
    with pytest.raises(EnrollmentRejected):
        _enroll(service)


@pytest.mark.parametrize(
    ("sub", "label", "dest"),
    [
        ("", "Phone", "tok"),
        ("sub 1; DROP", "Phone", "tok"),
        ("sub-1", "", "tok"),
        ("sub-1", "x" * 81, "tok"),
        ("sub-1", "Phone", "  "),
    ],
)
def test_invalid_input_is_rejected(service, sub, label, dest):
    with pytest.raises(EnrollmentRejected):
        _enroll(service, sub=sub, label=label, dest=dest)
    assert service.audit_log.all_records() == []
