"""Orchestrates ticket creation and the verification flow: checks channel
enrollment, generates the number-matching code (CISA guidance), dispatches
via the notification adapters, and applies timeouts.

This is the composition point FastAPI routes call. core.state_machine,
core.ticket, the adapters, and the db repositories don't know about each
other; this module is where they're wired together, deliberately kept out
of core/ since it has I/O and framework-adjacent concerns core/ must not
depend on.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto

from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.core.state_machine import VerificationAttempt, VerificationState
from ivp.core.ticket import Ticket
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import ChannelEnrollment, SqliteChannelRepository
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository
from ivp.db.sqlite_verification_repository import SqliteVerificationRepository

ACCOUNT_HOLDER_ROLE = "account_holder"


def generate_code() -> str:
    return f"{random.randint(0, 999_999):06d}"  # noqa: S311 — demo-only, not a security token itself


class ConfirmationResult(Enum):
    APPROVED = auto()
    DENIED = auto()
    ALREADY_RESOLVED = auto()


@dataclass
class VerificationOrchestrator:
    ticket_repo: SqliteTicketRepository
    channel_repo: SqliteChannelRepository
    verification_repo: SqliteVerificationRepository
    audit_log: SqliteAuditLog
    push_adapter: MockPushAdapter
    pstn_adapter: MockPstnAdapter
    max_attempts: int
    timeout: timedelta

    def open_ticket_and_start_verification(
        self,
        *,
        ticket_id: str,
        agent_id: str,
        subscriber_id: str,
        requested_action: SensitiveAction,
        now: datetime,
    ) -> tuple[Ticket, str | None]:
        ticket = Ticket(
            id=ticket_id,
            requested_action=requested_action,
            subscriber_id=subscriber_id,
            agent_id=agent_id,
        )
        self.ticket_repo.create(ticket, now=now)
        attempt_id = self.start_verification(ticket, now=now)
        return ticket, attempt_id

    def start_verification(self, ticket: Ticket, *, now: datetime) -> str | None:
        """Returns the new attempt's id, or None if the subscriber has no
        enrolled channel (NO_CHANNEL_BLOCKED — hard stop, see
        docs/state-machine.md)."""
        enrollments = self.channel_repo.list_for_subscriber(ticket.subscriber_id)
        if not enrollments:
            self.audit_log.append(
                ticket_id=ticket.id,
                actor_id=ticket.agent_id,
                actor_role="agent",
                requested_action=ticket.requested_action,
                channel_type=None,
                outcome=AuditOutcome.NO_CHANNEL_BLOCKED,
                timestamp=now,
            )
            return None

        # Prefer PUSH over PSTN when both are enrolled: PSTN is a NIST
        # restricted authenticator (docs/threat-model.md).
        enrollment = next(
            (e for e in enrollments if e.channel_type == ChannelType.PUSH), enrollments[0]
        )
        return self._dispatch_new_attempt(ticket.id, ticket.requested_action, enrollment, now)

    def submit_confirmation(
        self, attempt_id: str, *, selected_code: str, now: datetime
    ) -> ConfirmationResult:
        """Called from the holder console. Number matching: the holder
        selects the code the agent read aloud. A match approves; a
        mismatch denies (the code shown to the wrong person doesn't
        match — treated as a failed confirmation, not silently ignored)."""
        attempt, code = self.verification_repo.get(attempt_id)
        if attempt.state != VerificationState.PENDING_CONFIRMATION:
            self._write_audit(attempt, AuditOutcome.REJECTED, now)
            return ConfirmationResult.ALREADY_RESOLVED

        if selected_code == code:
            attempt.approve()
            outcome = AuditOutcome.APPROVED
            result = ConfirmationResult.APPROVED
        else:
            attempt.deny()
            outcome = AuditOutcome.DENIED
            result = ConfirmationResult.DENIED

        self.verification_repo.save(attempt_id, attempt, code)
        self._write_audit(attempt, outcome, now)
        return result

    def check_and_apply_timeout(self, ticket_id: str, *, now: datetime) -> None:
        """Idempotent: safe to call on every page load of the ticket
        status view. Writes a final EXPIRED audit record only once retries
        are exhausted — a transient expiry with retries remaining is not
        yet a verification record (docs/decisions/closure-semantics.md)."""
        latest = self.verification_repo.latest_for_ticket(ticket_id)
        if latest is None:
            return
        attempt_id, attempt, code = latest
        if attempt.state != VerificationState.PENDING_CONFIRMATION:
            return
        if not attempt.check_timeout(now):
            return
        self.verification_repo.save(attempt_id, attempt, code)
        if not attempt.can_retry():
            self._write_audit(attempt, AuditOutcome.EXPIRED, now)

    def retry_verification(self, ticket_id: str, *, now: datetime) -> str | None:
        latest = self.verification_repo.latest_for_ticket(ticket_id)
        if latest is None:
            return None
        attempt_id, attempt, _old_code = latest
        if attempt.state != VerificationState.EXPIRED or not attempt.can_retry():
            return None

        enrollment = self._enrollment_for_channel_id(attempt.channel_id)
        if enrollment is None:
            return None

        new_code = generate_code()
        attempt.retry(now=now)
        self.verification_repo.save(attempt_id, attempt, new_code)
        self._send(enrollment, ticket_id, new_code, now)
        return attempt_id

    def _dispatch_new_attempt(
        self,
        ticket_id: str,
        requested_action: SensitiveAction,
        enrollment: ChannelEnrollment,
        now: datetime,
    ) -> str:
        code = generate_code()
        attempt_id, attempt = self.verification_repo.create(
            ticket_id=ticket_id,
            requested_action=requested_action,
            channel_id=enrollment.id,
            code=code,
            max_attempts=self.max_attempts,
            timeout=self.timeout,
        )
        attempt.start(has_enrolled_channel=True, now=now)
        self.verification_repo.save(attempt_id, attempt, code)
        self._send(enrollment, ticket_id, code, now)
        return attempt_id

    def _send(
        self, enrollment: ChannelEnrollment, ticket_id: str, code: str, now: datetime
    ) -> None:
        adapter = (
            self.push_adapter if enrollment.channel_type == ChannelType.PUSH else self.pstn_adapter
        )
        adapter.send_confirmation(channel_id=enrollment.id, ticket_id=ticket_id, code=code, now=now)

    def _enrollment_for_channel_id(self, channel_id: str | None) -> ChannelEnrollment | None:
        if channel_id is None:
            return None
        return self.channel_repo.get_by_id(channel_id)

    def _write_audit(
        self, attempt: VerificationAttempt, outcome: AuditOutcome, now: datetime
    ) -> None:
        enrollment = self._enrollment_for_channel_id(attempt.channel_id)
        self.audit_log.append(
            ticket_id=attempt.ticket_id,
            actor_id=enrollment.subscriber_id if enrollment else "unknown",
            actor_role=ACCOUNT_HOLDER_ROLE,
            requested_action=attempt.requested_action,
            channel_type=enrollment.channel_type if enrollment else None,
            outcome=outcome,
            timestamp=now,
        )
