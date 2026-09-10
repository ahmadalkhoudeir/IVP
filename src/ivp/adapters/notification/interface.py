"""Notification (out-of-band confirmation delivery) port. Real
implementations (a push provider, a telephony provider) live outside this
codebase; only mocks exist here.

There is deliberately no EMAIL member/implementation — see
docs/decisions/email-channel.md (NIST SP 800-63B-4 prohibits email for
out-of-band authentication).

`send_confirmation` uses number matching (a short code the agent reads
aloud and the holder must select/enter) rather than a bare approve/deny
push, per CISA's interim guidance for push-based MFA. Implementations MUST
apply a destination-keyed rate limit (see rate_limit.py) before sending.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ivp.core.models import ChannelType


class NotificationAdapter(Protocol):
    channel_type: ChannelType

    def send_confirmation(
        self, *, channel_id: str, ticket_id: str, code: str, now: datetime
    ) -> None:
        """Deliver a number-matching confirmation request to channel_id.
        Must raise RateLimitExceeded (rate_limit.py) rather than silently
        sending, if the destination's send rate is exceeded. `now` is
        passed explicitly (never read from the system clock) so sends are
        deterministic in tests."""
        ...
