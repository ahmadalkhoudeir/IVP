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

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto

from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.adapters.notification.rate_limit import RateLimitExceeded
from ivp.audit.record import CLOSURE_SATISFYING_OUTCOMES, AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction, TicketStatus
from ivp.core.state_machine import VerificationAttempt, VerificationState
from ivp.core.ticket import Ticket
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import ChannelEnrollment, SqliteChannelRepository
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository
from ivp.db.sqlite_verification_repository import SqliteVerificationRepository

ACCOUNT_HOLDER_ROLE = "account_holder"


def generate_code() -> str:
    """Six-digit number-matching code from the OS CSPRNG. An attacker who
    could predict the code (Python's `random` is a Mersenne Twister, whose
    state is recoverable from its outputs) could coach a victim into
    approving, which is exactly what number matching exists to prevent."""
    return f"{secrets.randbelow(1_000_000):06d}"


class ConfirmationResult(Enum):
    APPROVED = auto()
    DENIED = auto()
    FRAUD_REPORTED = auto()
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
        """Returns the new attempt's id, or None if verification could not
        be started. Every "could not start" case writes its own audit record
        with the reason, so the agent sees why and the gap is on the record:

        - NO_CHANNEL_BLOCKED: nothing enrolled, or every channel is still in
          its enrollment cooling-off period.
        - RISK_BLOCKED: every usable channel is PSTN and the carrier reports
          a SIM swap or number port (NIST SP 800-63B-4 restricted
          authenticator guidance).
        - RATE_LIMITED: the destination-keyed send limit refused the send
          (push-bombing defense).

        None of these is a verification record, so the ticket stays OPEN.
        """
        enrollments = self.channel_repo.list_for_subscriber(ticket.subscriber_id)
        if not enrollments:
            self._write_block(ticket, AuditOutcome.NO_CHANNEL_BLOCKED, None, None, now)
            return None

        usable = [e for e in enrollments if e.is_usable(now)]
        if not usable:
            soonest = min(e.usable_from or e.enrolled_at for e in enrollments)
            self._write_block(
                ticket,
                AuditOutcome.NO_CHANNEL_BLOCKED,
                None,
                f"all enrolled channels are in enrollment cooling-off until {soonest.isoformat()}",
                now,
            )
            return None

        # Prefer PUSH over PSTN: PSTN is a NIST restricted authenticator
        # (docs/threat-model.md). Stable sort keeps enrollment order otherwise.
        ordered = sorted(usable, key=lambda e: e.channel_type != ChannelType.PUSH)
        safe = [e for e in ordered if not self._has_risk(e)]
        if not safe:
            self._write_block(
                ticket,
                AuditOutcome.RISK_BLOCKED,
                ChannelType.PSTN,
                "carrier risk signal (SIM swap or number port) on every usable channel",
                now,
            )
            return None

        enrollment = safe[0]
        code = generate_code()
        try:
            self._send(enrollment, ticket.id, code, now)
        except RateLimitExceeded as exc:
            self._write_block(
                ticket, AuditOutcome.RATE_LIMITED, enrollment.channel_type, str(exc), now
            )
            return None
        return self._create_attempt(ticket.id, ticket.requested_action, enrollment, code, now)

    def restart_verification(self, ticket_id: str, *, now: datetime) -> str | None:
        """Try again on a ticket whose verification never started (blocked
        by one of the reasons above), e.g. after the rate-limit window
        passes or an admin enrolls a channel through the separate
        enrollment flow. Refused once any verification record exists or an
        attempt is already underway: this is not a way to re-roll a DENIED
        result."""
        ticket = self.ticket_repo.get(ticket_id)
        if ticket.status != TicketStatus.OPEN:
            return None
        if self.verification_repo.latest_for_ticket(ticket_id) is not None:
            return None
        records = self.audit_log.records_for_ticket(ticket_id)
        if any(r.outcome in CLOSURE_SATISFYING_OUTCOMES for r in records):
            return None
        return self.start_verification(ticket, now=now)

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

    def report_fraud(self, attempt_id: str, *, now: datetime) -> ConfirmationResult:
        """The holder says they did not request this at all. The attempt is
        DENIED (so the action can never be authorized from it) and the audit
        record is FRAUD_REPORTED rather than DENIED, so supervisors can tell
        "wrong code" apart from "someone is impersonating me"."""
        attempt, code = self.verification_repo.get(attempt_id)
        if attempt.state != VerificationState.PENDING_CONFIRMATION:
            self._write_audit(attempt, AuditOutcome.REJECTED, now)
            return ConfirmationResult.ALREADY_RESOLVED
        attempt.deny()
        self.verification_repo.save(attempt_id, attempt, code)
        self._write_audit(
            attempt,
            AuditOutcome.FRAUD_REPORTED,
            now,
            reason="account holder reported they did not request this action",
        )
        return ConfirmationResult.FRAUD_REPORTED

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
        try:
            self._send(enrollment, ticket_id, new_code, now)
        except RateLimitExceeded as exc:
            # The attempt stays EXPIRED with its retry unspent, so the agent
            # can try again once the window passes.
            ticket = self.ticket_repo.get(ticket_id)
            self._write_block(
                ticket, AuditOutcome.RATE_LIMITED, enrollment.channel_type, str(exc), now
            )
            return None
        attempt.retry(now=now)
        self.verification_repo.save(attempt_id, attempt, new_code)
        return attempt_id

    def _has_risk(self, enrollment: ChannelEnrollment) -> bool:
        if enrollment.channel_type != ChannelType.PSTN:
            return False
        return self.pstn_adapter.check_risk_signals(enrollment.id).has_risk

    def _create_attempt(
        self,
        ticket_id: str,
        requested_action: SensitiveAction,
        enrollment: ChannelEnrollment,
        code: str,
        now: datetime,
    ) -> str:
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

    def _write_block(
        self,
        ticket: Ticket,
        outcome: AuditOutcome,
        channel_type: ChannelType | None,
        reason: str | None,
        now: datetime,
    ) -> None:
        self.audit_log.append(
            ticket_id=ticket.id,
            actor_id=ticket.agent_id,
            actor_role="agent",
            requested_action=ticket.requested_action,
            channel_type=channel_type,
            outcome=outcome,
            timestamp=now,
            reason=reason,
        )

    def _write_audit(
        self,
        attempt: VerificationAttempt,
        outcome: AuditOutcome,
        now: datetime,
        reason: str | None = None,
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
            reason=reason,
        )
