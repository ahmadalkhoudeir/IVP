"""Verification metrics for supervisors and admins.

The brief's first adoption driver is speed ("verification completes in
under 30 seconds", hard requirement 5), so the headline number is time to
verify: from ticket creation to the holder's response (approve, deny or
fraud report). Computed from the tickets table and the audit log only, so
the numbers are exactly as trustworthy as the hash-chained record behind
them.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

from ivp.audit.record import (
    BLOCKING_OUTCOMES,
    CLOSURE_SATISFYING_OUTCOMES,
    AuditOutcome,
    AuditRecord,
)
from ivp.core.models import TicketStatus
from ivp.core.ticket import Ticket

TARGET_SECONDS = 30
HOLDER_RESPONSE_OUTCOMES = frozenset(
    {AuditOutcome.APPROVED, AuditOutcome.DENIED, AuditOutcome.FRAUD_REPORTED}
)
# Display order for the resolution breakdown.
RESOLUTION_ORDER = (
    "APPROVED",
    "DENIED",
    "FRAUD_REPORTED",
    "EXPIRED",
    "ADMIN_OVERRIDE",
    "BLOCKED",
    "PENDING",
)


class AuditLookup(Protocol):
    def records_for_ticket(self, ticket_id: str) -> list[AuditRecord]: ...


@dataclass(frozen=True)
class AgentRow:
    agent_id: str
    tickets: int
    approved: int
    fraud_reports: int
    overrides: int


@dataclass
class Metrics:
    total_tickets: int = 0
    open_tickets: int = 0
    closed_tickets: int = 0
    resolutions: dict[str, int] = field(default_factory=dict)
    verify_samples: int = 0
    median_seconds: float | None = None
    p90_seconds: float | None = None
    within_target_pct: float | None = None
    fraud_ticket_ids: list[str] = field(default_factory=list)
    agents: list[AgentRow] = field(default_factory=list)
    target_seconds: int = TARGET_SECONDS

    @property
    def resolution_rows(self) -> list[tuple[str, int, float]]:
        """(label, count, percent of all tickets) in display order."""
        total = self.total_tickets or 1
        return [
            (label, self.resolutions.get(label, 0), 100 * self.resolutions.get(label, 0) / total)
            for label in RESOLUTION_ORDER
        ]


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile. `values` need not be sorted."""
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def resolution_of(records: list[AuditRecord]) -> str:
    for record in records:
        if record.outcome in CLOSURE_SATISFYING_OUTCOMES:
            return record.outcome.value
    if any(r.outcome in BLOCKING_OUTCOMES for r in records):
        return "BLOCKED"
    return "PENDING"


def time_to_verify(ticket: Ticket, records: list[AuditRecord]) -> timedelta | None:
    if ticket.created_at is None:
        return None
    for record in records:
        if record.outcome in HOLDER_RESPONSE_OUTCOMES:
            return record.timestamp - ticket.created_at
    return None


def compute_metrics(tickets: list[Ticket], audit_log: AuditLookup) -> Metrics:
    metrics = Metrics(total_tickets=len(tickets))
    resolutions: Counter[str] = Counter()
    samples: list[float] = []
    per_agent: dict[str, Counter[str]] = {}

    for ticket in tickets:
        records = audit_log.records_for_ticket(ticket.id)
        if ticket.status == TicketStatus.OPEN:
            metrics.open_tickets += 1
        else:
            metrics.closed_tickets += 1

        resolution = resolution_of(records)
        resolutions[resolution] += 1

        elapsed = time_to_verify(ticket, records)
        if elapsed is not None:
            samples.append(elapsed.total_seconds())

        agent = per_agent.setdefault(ticket.agent_id, Counter())
        agent["tickets"] += 1
        if resolution == "APPROVED":
            agent["approved"] += 1
        if any(r.outcome == AuditOutcome.FRAUD_REPORTED for r in records):
            agent["fraud"] += 1
            metrics.fraud_ticket_ids.append(ticket.id)
        if any(r.outcome == AuditOutcome.ADMIN_OVERRIDE for r in records):
            agent["overrides"] += 1

    metrics.resolutions = dict(resolutions)
    metrics.verify_samples = len(samples)
    if samples:
        metrics.median_seconds = percentile(samples, 50)
        metrics.p90_seconds = percentile(samples, 90)
        within = sum(1 for s in samples if s <= TARGET_SECONDS)
        metrics.within_target_pct = 100 * within / len(samples)
    metrics.agents = sorted(
        (
            AgentRow(
                agent_id=agent_id,
                tickets=c["tickets"],
                approved=c["approved"],
                fraud_reports=c["fraud"],
                overrides=c["overrides"],
            )
            for agent_id, c in per_agent.items()
        ),
        key=lambda row: row.agent_id,
    )
    return metrics
