"""Mock SMS/voice (PSTN) adapter. NIST SP 800-63B-4 classifies PSTN-delivered
out-of-band confirmation as a *restricted authenticator* (see
docs/threat-model.md): verifiers SHOULD consider risk indicators (device
swap, SIM change, number porting) before sending. `check_risk_signals` is
the integration point for that — this mock always reports no risk, since a
real carrier signal feed is out of scope for this project, but the shape is
here so a real adapter can implement it without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ivp.adapters.notification.rate_limit import SlidingWindowRateLimiter
from ivp.core.models import ChannelType

DEFAULT_MAX_SENDS = 3
DEFAULT_WINDOW = timedelta(minutes=10)


@dataclass
class RiskSignals:
    sim_swap_detected: bool = False
    number_recently_ported: bool = False

    @property
    def has_risk(self) -> bool:
        return self.sim_swap_detected or self.number_recently_ported


@dataclass
class SentPstn:
    channel_id: str
    ticket_id: str
    code: str
    sent_at: datetime


@dataclass
class MockPstnAdapter:
    channel_type: ChannelType = field(default=ChannelType.PSTN, init=False)
    sent: list[SentPstn] = field(default_factory=list)
    # Test/demo hook: pre-seed a channel_id with risk signals to simulate a
    # carrier flagging a SIM swap or number port.
    risk_overrides: dict[str, RiskSignals] = field(default_factory=dict)
    _rate_limiter: SlidingWindowRateLimiter = field(
        default_factory=lambda: SlidingWindowRateLimiter(
            max_sends=DEFAULT_MAX_SENDS, window=DEFAULT_WINDOW
        )
    )

    def check_risk_signals(self, channel_id: str) -> RiskSignals:
        return self.risk_overrides.get(channel_id, RiskSignals())

    def send_confirmation(
        self, *, channel_id: str, ticket_id: str, code: str, now: datetime
    ) -> None:
        self._rate_limiter.check_and_record(channel_id, now)
        self.sent.append(
            SentPstn(channel_id=channel_id, ticket_id=ticket_id, code=code, sent_at=now)
        )
