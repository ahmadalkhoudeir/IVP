import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from ivp.audit.log import GENESIS_HASH, AuditLog, TamperDetected
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def append_sample(log: AuditLog, ticket_id: str = "T-1", **overrides) -> None:
    defaults = {
        "ticket_id": ticket_id,
        "actor_id": "agent-1",
        "actor_role": "agent",
        "requested_action": SensitiveAction.PASSWORD_RESET,
        "channel_type": ChannelType.PUSH,
        "outcome": AuditOutcome.APPROVED,
        "timestamp": T0,
    }
    defaults.update(overrides)
    log.append(**defaults)


def test_first_record_chains_from_genesis():
    log = AuditLog()
    append_sample(log)
    [record] = log.all_records()
    assert record.sequence == 0
    assert record.prev_hash == GENESIS_HASH
    assert len(record.record_hash) == 64


def test_records_chain_sequentially():
    log = AuditLog()
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=5))
    records = log.all_records()
    assert records[1].prev_hash == records[0].record_hash
    assert records[1].sequence == 1


def test_verify_integrity_passes_on_untouched_log():
    log = AuditLog()
    for i in range(5):
        append_sample(log, ticket_id=f"T-{i}", timestamp=T0 + timedelta(seconds=i))
    log.verify_integrity()  # must not raise


def test_records_for_ticket_filters():
    log = AuditLog()
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    append_sample(
        log, ticket_id="T-1", timestamp=T0 + timedelta(seconds=2), outcome=AuditOutcome.DENIED
    )
    matches = log.records_for_ticket("T-1")
    assert [r.sequence for r in matches] == [0, 2]


def test_admin_override_requires_reason():
    log = AuditLog()
    with pytest.raises(ValueError):
        append_sample(
            log, outcome=AuditOutcome.ADMIN_OVERRIDE, actor_id="admin-1", actor_role="admin"
        )


def test_admin_override_with_reason_is_recorded():
    log = AuditLog()
    append_sample(
        log,
        outcome=AuditOutcome.ADMIN_OVERRIDE,
        actor_id="admin-1",
        actor_role="admin",
        reason="Identity proofed in person; caller had no enrolled channel.",
    )
    [record] = log.all_records()
    assert record.outcome == AuditOutcome.ADMIN_OVERRIDE
    assert record.reason


def _tamper(log: AuditLog, sequence: int, **field_overrides) -> None:
    """Directly mutate a record's field in place, simulating an attacker
    with raw storage access editing a row after the fact. AuditRecord is a
    frozen dataclass (no legitimate update path); this reaches around that
    on purpose to prove verify_integrity() catches it."""
    records = log._records  # type: ignore[attr-defined]
    records[sequence] = dataclasses.replace(records[sequence], **field_overrides)


def test_verify_integrity_detects_field_tampering():
    log = AuditLog()
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))

    _tamper(log, 0, outcome=AuditOutcome.DENIED)  # flip an approval to a denial

    with pytest.raises(TamperDetected) as exc_info:
        log.verify_integrity()
    assert exc_info.value.sequence == 0


def test_verify_integrity_detects_hash_forgery():
    """Tampering the payload AND recomputing record_hash to match still
    breaks the chain, because it invalidates prev_hash on the next record."""
    log = AuditLog()
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))

    tampered = dataclasses.replace(log._records[0], outcome=AuditOutcome.DENIED)  # type: ignore[attr-defined]
    from ivp.audit.log import compute_record_hash

    forged_hash = compute_record_hash(
        sequence=tampered.sequence,
        ticket_id=tampered.ticket_id,
        actor_id=tampered.actor_id,
        actor_role=tampered.actor_role,
        requested_action=tampered.requested_action,
        channel_type=tampered.channel_type,
        outcome=tampered.outcome,
        timestamp=tampered.timestamp,
        reason=tampered.reason,
        prev_hash=tampered.prev_hash,
    )
    log._records[0] = dataclasses.replace(tampered, record_hash=forged_hash)  # type: ignore[attr-defined]

    with pytest.raises(TamperDetected) as exc_info:
        log.verify_integrity()
    assert exc_info.value.sequence == 1  # detected via broken prev_hash on the next record


def test_verify_integrity_detects_deleted_record():
    log = AuditLog()
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    append_sample(log, ticket_id="T-3", timestamp=T0 + timedelta(seconds=2))

    del log._records[1]  # type: ignore[attr-defined]

    with pytest.raises(TamperDetected):
        log.verify_integrity()


def test_no_update_or_delete_methods_exist():
    """Structural guard: the append-only contract must not be a convention
    that a future PR can quietly break by adding a method."""
    log = AuditLog()
    forbidden = {"update", "edit", "delete", "remove", "set", "modify"}
    public_methods = {name for name in dir(log) if not name.startswith("_")}
    assert not (public_methods & forbidden)
