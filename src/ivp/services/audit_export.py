"""CSV export of audit records, for handing evidence to an auditor or an
incident responder.

Spreadsheet formula injection (OWASP "CSV Injection"): a cell starting with
=, +, -, @, tab or carriage return can be executed as a formula when the
file is opened in Excel or Sheets. Free-text fields such as an override
reason are written by people, so every cell that starts with one of those
characters is prefixed with a single quote.

The export includes prev_hash and record_hash so the recipient can
recompute the chain independently (docs/architecture.md shows how).
"""

from __future__ import annotations

import csv
import io

from ivp.audit.record import AuditRecord

COLUMNS = (
    "sequence",
    "ticket_id",
    "actor_id",
    "actor_role",
    "requested_action",
    "channel_type",
    "outcome",
    "timestamp",
    "reason",
    "prev_hash",
    "record_hash",
)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: str) -> str:
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


def records_to_csv(records: list[AuditRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(COLUMNS)
    for r in records:
        writer.writerow(
            [
                str(r.sequence),
                neutralize(r.ticket_id),
                neutralize(r.actor_id),
                neutralize(r.actor_role),
                r.requested_action.value,
                r.channel_type.value if r.channel_type else "",
                r.outcome.value,
                r.timestamp.isoformat(),
                neutralize(r.reason or ""),
                r.prev_hash,
                r.record_hash,
            ]
        )
    return buffer.getvalue()
