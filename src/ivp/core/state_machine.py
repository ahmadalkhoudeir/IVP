"""Verification attempt state machine.

REQUESTED -> NO_CHANNEL_BLOCKED                          (no enrolled channel)
REQUESTED -> PENDING_CONFIRMATION -> APPROVED
                                   -> DENIED
                                   -> EXPIRED -> (retry) -> PENDING_CONFIRMATION
                                              -> (attempts exhausted, final)

This module is pure domain logic: no persistence, no I/O, no framework
dependency. `now` is always passed in explicitly rather than read from the
system clock, so tests are deterministic without patching time.

Project decision (see docs/decisions/closure-semantics.md): a ticket stays
OPEN until *some* verification record exists for it — APPROVED, DENIED, or a
final EXPIRED after retries are exhausted. There is no path that lets a
ticket close with zero record. `is_closure_eligible` reflects that per
attempt; NO_CHANNEL_BLOCKED is deliberately never closure-eligible on its own
(see its docstring below).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

DEFAULT_CONFIRMATION_TIMEOUT = timedelta(minutes=4)
DEFAULT_MAX_ATTEMPTS = 3


class VerificationState(StrEnum):
    REQUESTED = "REQUESTED"
    NO_CHANNEL_BLOCKED = "NO_CHANNEL_BLOCKED"
    PENDING_CONFIRMATION = "PENDING_CONFIRMATION"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


_CLOSURE_ELIGIBLE_STATES = frozenset({VerificationState.APPROVED, VerificationState.DENIED})


class InvalidTransition(Exception):
    """Raised when an event is not valid for the attempt's current state."""


@dataclass
class VerificationAttempt:
    ticket_id: str
    requested_action: str
    channel_id: str | None
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    timeout: timedelta = DEFAULT_CONFIRMATION_TIMEOUT

    state: VerificationState = field(default=VerificationState.REQUESTED)
    attempt_number: int = field(default=0)
    pending_since: datetime | None = field(default=None)

    def start(self, *, has_enrolled_channel: bool, now: datetime) -> None:
        """First transition out of REQUESTED. Enforces requirement 1/2: there
        is no fallback to knowledge-based verification here — either an
        enrolled channel exists and we proceed, or the attempt is blocked."""
        if self.state != VerificationState.REQUESTED:
            raise InvalidTransition(f"start() is only valid from REQUESTED, not {self.state}")
        if not has_enrolled_channel:
            self.state = VerificationState.NO_CHANNEL_BLOCKED
            return
        self._enter_pending(now)

    def approve(self) -> None:
        self._require_pending()
        self.state = VerificationState.APPROVED

    def deny(self) -> None:
        self._require_pending()
        self.state = VerificationState.DENIED

    def check_timeout(self, now: datetime) -> bool:
        """Move PENDING_CONFIRMATION -> EXPIRED if the timeout has elapsed.
        Returns True if a transition happened, False if still within the
        timeout window. Does not auto-retry; call retry() separately."""
        self._require_pending()
        assert self.pending_since is not None
        if now - self.pending_since < self.timeout:
            return False
        self.state = VerificationState.EXPIRED
        return True

    def can_retry(self) -> bool:
        return self.state == VerificationState.EXPIRED and self.attempt_number < self.max_attempts

    def retry(self, now: datetime) -> None:
        if not self.can_retry():
            raise InvalidTransition(
                f"retry() not valid: state={self.state}, "
                f"attempt {self.attempt_number}/{self.max_attempts}"
            )
        self._enter_pending(now)

    @property
    def is_closure_eligible(self) -> bool:
        """Whether this attempt alone provides a valid verification record
        that permits the ticket to leave OPEN (hard requirement 3).

        NO_CHANNEL_BLOCKED is deliberately excluded: this system has no
        in-band way to produce a valid record when no channel was ever
        enrolled, and falling back to knowledge-based verification to
        produce one would violate requirement 1. Such tickets can only
        become closure-eligible via an ADMIN_OVERRIDE record (see
        docs/decisions/admin-override.md), which is tracked at the audit-log
        layer, not here.
        """
        if self.state in _CLOSURE_ELIGIBLE_STATES:
            return True
        if self.state == VerificationState.EXPIRED:
            return not self.can_retry()
        return False

    def _enter_pending(self, now: datetime) -> None:
        self.attempt_number += 1
        self.state = VerificationState.PENDING_CONFIRMATION
        self.pending_since = now

    def _require_pending(self) -> None:
        if self.state != VerificationState.PENDING_CONFIRMATION:
            raise InvalidTransition(f"expected PENDING_CONFIRMATION, got {self.state}")
