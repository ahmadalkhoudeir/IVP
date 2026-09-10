import dataclasses
import tempfile
from datetime import UTC, datetime, timedelta

import pytest

from ivp.adapters.anchoring.local_file import LocalFileAnchorAdapter
from ivp.audit.log import AuditLog
from ivp.audit.log import compute_record_hash as audit_compute_record_hash
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.services.anchor_service import AnchorVerificationFailed, AuditAnchorService

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def append_sample(log: AuditLog, ticket_id: str = "T-1", **overrides):
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
    return log.append(**defaults)


def build_service(tmp_path) -> tuple[AuditAnchorService, AuditLog]:
    log = AuditLog()
    adapter = LocalFileAnchorAdapter(str(tmp_path / "anchors.jsonl"))
    return AuditAnchorService(audit_log=log, anchor_adapter=adapter), log


def test_checkpoint_if_new_records_returns_none_for_empty_log(tmp_path):
    service, _log = build_service(tmp_path)
    assert service.checkpoint_if_new_records(now=T0) is None


def test_checkpoint_if_new_records_publishes_covering_the_latest_record(tmp_path):
    service, log = build_service(tmp_path)
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))

    receipt = service.checkpoint_if_new_records(now=T0 + timedelta(minutes=1))
    assert receipt.sequence_up_to == 1
    assert receipt.chain_hash == log.all_records()[-1].record_hash


def test_checkpoint_if_new_records_is_a_noop_when_nothing_changed(tmp_path):
    service, log = build_service(tmp_path)
    append_sample(log)
    service.checkpoint_if_new_records(now=T0)
    assert service.checkpoint_if_new_records(now=T0 + timedelta(minutes=1)) is None
    assert len(service.anchor_adapter.list_checkpoints()) == 1


def test_checkpoint_if_new_records_publishes_again_after_new_records_arrive(tmp_path):
    service, log = build_service(tmp_path)
    append_sample(log, ticket_id="T-1")
    service.checkpoint_if_new_records(now=T0)

    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    receipt = service.checkpoint_if_new_records(now=T0 + timedelta(minutes=1))
    assert receipt is not None
    assert receipt.sequence_up_to == 1
    assert len(service.anchor_adapter.list_checkpoints()) == 2


def test_verify_against_anchors_passes_on_untouched_log(tmp_path):
    service, log = build_service(tmp_path)
    append_sample(log, ticket_id="T-1")
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    service.checkpoint_if_new_records(now=T0 + timedelta(minutes=1))
    service.verify_against_anchors()  # must not raise


def test_verify_against_anchors_fails_if_anchored_record_is_missing(tmp_path):
    """Simulates an attacker deleting a record that was already checkpointed."""
    service, log = build_service(tmp_path)
    append_sample(log, ticket_id="T-1")
    service.checkpoint_if_new_records(now=T0)

    del log._records[0]  # type: ignore[attr-defined]

    with pytest.raises(AnchorVerificationFailed) as exc_info:
        service.verify_against_anchors()
    assert exc_info.value.sequence_up_to == 0
    assert exc_info.value.actual_hash is None


def test_verify_against_anchors_catches_a_fully_consistent_rewrite():
    """The property external anchoring exists for: an attacker with full
    database access tampers with a record AND recomputes every hash
    forward so the chain is internally consistent again (verify_integrity()
    on its own would NOT catch this). The checkpoint published before the
    rewrite still won't match, because it was stored outside the database.
    """
    log = AuditLog()
    append_sample(log, ticket_id="T-1", outcome=AuditOutcome.APPROVED)
    append_sample(log, ticket_id="T-2", timestamp=T0 + timedelta(seconds=1))
    append_sample(log, ticket_id="T-3", timestamp=T0 + timedelta(seconds=2))

    with tempfile.TemporaryDirectory() as tmp_path:
        adapter = LocalFileAnchorAdapter(f"{tmp_path}/anchors.jsonl")
        service = AuditAnchorService(audit_log=log, anchor_adapter=adapter)
        service.checkpoint_if_new_records(now=T0 + timedelta(minutes=1))  # anchors sequence 2

        # Attacker rewrites record 0 (flip APPROVED -> DENIED) and recomputes
        # every hash forward so log.verify_integrity() alone would pass.
        tampered = dataclasses.replace(log._records[0], outcome=AuditOutcome.DENIED)  # type: ignore[attr-defined]
        prev_hash = "0" * 64
        new_records = []
        for i, record in enumerate(log._records):  # type: ignore[attr-defined]
            source = tampered if i == 0 else record
            recomputed_hash = audit_compute_record_hash(
                sequence=source.sequence,
                ticket_id=source.ticket_id,
                actor_id=source.actor_id,
                actor_role=source.actor_role,
                requested_action=source.requested_action,
                channel_type=source.channel_type,
                outcome=tampered.outcome if i == 0 else source.outcome,
                timestamp=source.timestamp,
                reason=source.reason,
                prev_hash=prev_hash,
            )
            new_record = dataclasses.replace(
                source,
                outcome=tampered.outcome if i == 0 else source.outcome,
                prev_hash=prev_hash,
                record_hash=recomputed_hash,
            )
            new_records.append(new_record)
            prev_hash = recomputed_hash
        log._records[:] = new_records  # type: ignore[attr-defined]

        log.verify_integrity()  # the internal chain is self-consistent again

        with pytest.raises(AnchorVerificationFailed):
            service.verify_against_anchors()  # but the external anchor catches it
