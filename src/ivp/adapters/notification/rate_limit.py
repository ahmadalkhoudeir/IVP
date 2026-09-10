"""Sliding-window rate limiter, keyed by enrolled channel destination (not
by ticket), for push-bombing / MFA-fatigue defense per CISA guidance:
https://www.cisa.gov/news-events/alerts/2022/10/31/cisa-releases-guidance-phishing-resistant-and-numbers-matching-multifactor-authentication

Keying by channel_id rather than ticket_id matters: an attacker who wants
to bombard a real account holder can open many different tickets rather
than retrying one, so a per-ticket limit alone would not catch it. This is
a defense-in-depth layer independent of VerificationAttempt.max_attempts
(core.state_machine), which caps retries per verification effort but has
no visibility across tickets.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta


class RateLimitExceeded(Exception):
    def __init__(self, key: str, limit: int, window: timedelta):
        self.key = key
        self.limit = limit
        self.window = window
        super().__init__(f"rate limit exceeded for {key!r}: {limit} sends per {window}")


class SlidingWindowRateLimiter:
    def __init__(self, *, max_sends: int, window: timedelta):
        self._max_sends = max_sends
        self._window = window
        self._history: dict[str, deque[datetime]] = {}

    def check_and_record(self, key: str, now: datetime) -> None:
        history = self._history.setdefault(key, deque())
        cutoff = now - self._window
        while history and history[0] <= cutoff:
            history.popleft()
        if len(history) >= self._max_sends:
            raise RateLimitExceeded(key, self._max_sends, self._window)
        history.append(now)
