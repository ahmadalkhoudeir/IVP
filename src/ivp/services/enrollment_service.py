"""Channel enrollment as an audited, notified process, not a bare INSERT.

Two protections against the "attacker talks an admin into adding a channel
they control" attack (docs/threat-model.md, Spoofing):

1. Notification. Every channel the subscriber already had is told about the
   new one, through that existing channel, i.e. "via a mechanism
   independent of the transaction binding the new authenticator"
   (NIST SP 800-63B-4 Sec. 4.1.2.1).
2. Cooling-off. The new channel is not used for verification until the
   cooling-off period passes, so the real holder has time to react to the
   notice. This delay is a project design choice, not a NIST requirement
   (docs/decisions/enrollment-cooling-off.md).

A subscriber's FIRST channel has nobody to notify and no older channel to
fall back on, so it is usable immediately. That trade-off is recorded in
the ADR.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import ChannelEnrollment, SqliteChannelRepository

SUBSCRIBER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_LABEL_LENGTH = 80


class EnrollmentRejected(ValueError):
    """Bad input or a duplicate destination. The message is safe to show."""


@dataclass(frozen=True)
class EnrollmentResult:
    enrollment: ChannelEnrollment
    notified_channels: int
    cooling_off_applied: bool


@dataclass
class ChannelEnrollmentService:
    channel_repo: SqliteChannelRepository
    audit_log: SqliteAuditLog
    push_adapter: MockPushAdapter
    pstn_adapter: MockPstnAdapter
    cooling_off: timedelta

    def enroll(
        self,
        *,
        subscriber_id: str,
        channel_type: ChannelType,
        label: str,
        destination: str,
        actor_id: str,
        actor_role: str,
        now: datetime,
    ) -> EnrollmentResult:
        subscriber_id = subscriber_id.strip()
        label = label.strip()
        destination = destination.strip()
        if not SUBSCRIBER_ID_PATTERN.match(subscriber_id):
            raise EnrollmentRejected(
                "Subscriber ID must be 1-64 letters, digits, hyphens or underscores"
            )
        if not label or len(label) > MAX_LABEL_LENGTH:
            raise EnrollmentRejected(f"Label must be 1-{MAX_LABEL_LENGTH} characters")
        if not destination:
            raise EnrollmentRejected("Destination is required")
        if self.channel_repo.fingerprint_exists(subscriber_id, destination):
            raise EnrollmentRejected("That destination is already enrolled for this subscriber")

        existing = self.channel_repo.list_for_subscriber(subscriber_id)
        cooling_off_applied = bool(existing) and self.cooling_off > timedelta(0)
        usable_from = now + self.cooling_off if cooling_off_applied else now

        enrollment = self.channel_repo.enroll(
            subscriber_id=subscriber_id,
            channel_type=channel_type,
            label=label,
            destination=destination,
            now=now,
            usable_from=usable_from,
        )

        for channel in existing:
            adapter = (
                self.push_adapter if channel.channel_type == ChannelType.PUSH else self.pstn_adapter
            )
            adapter.send_enrollment_notice(
                channel_id=channel.id,
                subscriber_id=subscriber_id,
                new_channel_label=label,
                now=now,
            )

        self.audit_log.append(
            ticket_id=f"ENR-{enrollment.id[:8]}",
            actor_id=actor_id,
            actor_role=actor_role,
            requested_action=SensitiveAction.CHANNEL_ENROLLMENT,
            channel_type=channel_type,
            outcome=AuditOutcome.CHANNEL_ENROLLED,
            timestamp=now,
            reason=(
                f"subscriber={subscriber_id}; label={label}; "
                f"usable_from={usable_from.isoformat()}; "
                f"notified {len(existing)} existing channel(s)"
            ),
        )
        return EnrollmentResult(
            enrollment=enrollment,
            notified_channels=len(existing),
            cooling_off_applied=cooling_off_applied,
        )
