"""Failed-login throttling for the staff dashboard.

NIST SP 800-63B-4 Sec. 3.2.2 ("Rate Limiting (Throttling)") requires
verifiers to limit consecutive failed attempts to no more than 100 and says
"agencies MAY impose lower limits". This uses a much lower limit because
staff accounts here are password-only and guard every subscriber's account.

Keyed by username (case-insensitive), not IP: an attacker spraying from
many addresses is still caught per account. The lockout message does not
reveal whether the username exists, because unknown usernames are counted
exactly like real ones.

In-memory by design for this single-process demo: a restart clears it. A
multi-process deployment would need a shared store (docs/architecture.md).
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

DEFAULT_MAX_FAILURES = 5
DEFAULT_WINDOW = timedelta(minutes=15)


class LoginThrottle:
    def __init__(
        self, *, max_failures: int = DEFAULT_MAX_FAILURES, window: timedelta = DEFAULT_WINDOW
    ):
        self._max_failures = max_failures
        self._window = window
        self._failures: dict[str, deque[datetime]] = {}

    def _prune(self, key: str, now: datetime) -> deque[datetime]:
        history = self._failures.setdefault(key, deque())
        while history and history[0] <= now - self._window:
            history.popleft()
        return history

    def is_locked(self, username: str, now: datetime) -> bool:
        return len(self._prune(username.lower(), now)) >= self._max_failures

    def record_failure(self, username: str, now: datetime) -> None:
        self._prune(username.lower(), now).append(now)

    def record_success(self, username: str) -> None:
        self._failures.pop(username.lower(), None)
