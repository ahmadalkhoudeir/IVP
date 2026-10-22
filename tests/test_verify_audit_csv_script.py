"""The standalone verifier must agree with the app's own hashing, so an
auditor's independent check means something."""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ivp.audit.log import AuditLog
from ivp.audit.record import AuditOutcome
from ivp.core.models import ChannelType, SensitiveAction
from ivp.services.audit_export import records_to_csv

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_audit_csv.py"
_spec = importlib.util.spec_from_file_location("verify_audit_csv", SCRIPT)
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _log() -> AuditLog:
    log = AuditLog()
    log.append(
        ticket_id="T-1",
        actor_id="sub-1",
        actor_role="account_holder",
        requested_action=SensitiveAction.PASSWORD_RESET,
        channel_type=ChannelType.PUSH,
        outcome=AuditOutcome.APPROVED,
        timestamp=T0,
    )
    log.append(
        ticket_id="T-2",
        actor_id="admin-1",
        actor_role="ADMIN",
        requested_action=SensitiveAction.MFA_RESET,
        channel_type=None,
        outcome=AuditOutcome.ADMIN_OVERRIDE,
        timestamp=T0 + timedelta(seconds=1),
        reason="=SUM(A1) identity proofed in person",
    )
    log.append(
        ticket_id="ENR-abc",
        actor_id="admin-1",
        actor_role="ADMIN",
        requested_action=SensitiveAction.CHANNEL_ENROLLMENT,
        channel_type=ChannelType.PSTN,
        outcome=AuditOutcome.CHANNEL_ENROLLED,
        timestamp=T0 + timedelta(seconds=2),
        reason="subscriber=sub-1; label=Cell",
    )
    return log


def _write(tmp_path, text):
    path = tmp_path / "export.csv"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_full_export_verifies_including_neutralized_formula(tmp_path, capsys):
    log = _log()
    path = _write(tmp_path, records_to_csv(log.all_records()))
    head = log.all_records()[-1]
    assert verifier.main([path, "--anchor-seq", "2", "--anchor-hash", head.record_hash]) == 0
    assert "full chain from genesis" in capsys.readouterr().out


def test_edited_export_is_caught(tmp_path, capsys):
    text = records_to_csv(_log().all_records()).replace("APPROVED", "DENIED", 1)
    assert verifier.main([_write(tmp_path, text)]) == 1
    assert "sequence 0" in capsys.readouterr().out


def test_wrong_anchor_is_caught(tmp_path):
    path = _write(tmp_path, records_to_csv(_log().all_records()))
    assert verifier.main([path, "--anchor-seq", "1", "--anchor-hash", "f" * 64]) == 1


def test_partial_export_checks_record_hashes_only(tmp_path, capsys):
    records = _log().all_records()
    path = _write(tmp_path, records_to_csv([records[0], records[2]]))
    assert verifier.main([path]) == 0
    assert "partial export" in capsys.readouterr().out
