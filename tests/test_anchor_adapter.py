from datetime import UTC, datetime, timedelta

from ivp.adapters.anchoring.local_file import LocalFileAnchorAdapter

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_publish_and_list_round_trips(tmp_path):
    adapter = LocalFileAnchorAdapter(str(tmp_path / "anchors.jsonl"))
    adapter.publish_checkpoint(sequence_up_to=4, chain_hash="abc123", now=T0)
    [checkpoint] = adapter.list_checkpoints()
    assert checkpoint.sequence_up_to == 4
    assert checkpoint.chain_hash == "abc123"
    assert checkpoint.published_at == T0


def test_latest_checkpoint_is_the_most_recently_published(tmp_path):
    adapter = LocalFileAnchorAdapter(str(tmp_path / "anchors.jsonl"))
    adapter.publish_checkpoint(sequence_up_to=1, chain_hash="hash-1", now=T0)
    adapter.publish_checkpoint(
        sequence_up_to=5, chain_hash="hash-2", now=T0 + timedelta(minutes=10)
    )
    latest = adapter.latest_checkpoint()
    assert latest.sequence_up_to == 5
    assert latest.chain_hash == "hash-2"


def test_latest_checkpoint_none_when_empty(tmp_path):
    adapter = LocalFileAnchorAdapter(str(tmp_path / "anchors.jsonl"))
    assert adapter.latest_checkpoint() is None
    assert adapter.list_checkpoints() == []


def test_checkpoints_persist_across_a_fresh_adapter_instance(tmp_path):
    """The whole point: a separate process/session reading this file later
    (e.g. an auditor) sees the same checkpoints."""
    path = str(tmp_path / "anchors.jsonl")
    LocalFileAnchorAdapter(path).publish_checkpoint(
        sequence_up_to=2, chain_hash="hash-x", now=T0
    )
    reopened = LocalFileAnchorAdapter(path)
    assert reopened.latest_checkpoint().chain_hash == "hash-x"


def test_no_update_or_delete_methods_exist(tmp_path):
    adapter = LocalFileAnchorAdapter(str(tmp_path / "anchors.jsonl"))
    forbidden = {"update", "edit", "delete", "remove", "set", "modify", "rewrite"}
    public_methods = {name for name in dir(adapter) if not name.startswith("_")}
    assert not (public_methods & forbidden)
