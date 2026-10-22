"""Mock push-notification adapter. Preferred channel per
docs/threat-model.md's out-of-band channel evaluation — not a NIST
restricted authenticator, unlike PSTN."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ivp.adapters.notification.rate_limit import SlidingWindowRateLimiter
from ivp.core.models import ChannelType

DEFAULT_MAX_SENDS = 5
DEFAULT_WINDOW = timedelta(minutes=10)


@dataclass
class SentPush:
    channel_id: str
    ticket_id: str
    code: str
    sent_at: datetime


@dataclass
class EnrollmentNotice:
    channel_id: str
    subscriber_id: str
    new_channel_label: str
    sent_at: datetime


@dataclass
class MockPushAdapter:
    channel_type: ChannelType = field(default=ChannelType.PUSH, init=False)
    sent: list[SentPush] = field(default_factory=list)
    enrollment_notices: list[EnrollmentNotice] = field(default_factory=list)
    _rate_limiter: SlidingWindowRateLimiter = field(
        default_factory=lambda: SlidingWindowRateLimiter(
            max_sends=DEFAULT_MAX_SENDS, window=DEFAULT_WINDOW
        )
    )

    def send_confirmation(
        self, *, channel_id: str, ticket_id: str, code: str, now: datetime
    ) -> None:
        self._rate_limiter.check_and_record(channel_id, now)
        self.sent.append(
            SentPush(channel_id=channel_id, ticket_id=ticket_id, code=code, sent_at=now)
        )

    def send_enrollment_notice(
        self, *, channel_id: str, subscriber_id: str, new_channel_label: str, now: datetime
    ) -> None:
        self.enrollment_notices.append(
            EnrollmentNotice(
                channel_id=channel_id,
                subscriber_id=subscriber_id,
                new_channel_label=new_channel_label,
                sent_at=now,
            )
        )
