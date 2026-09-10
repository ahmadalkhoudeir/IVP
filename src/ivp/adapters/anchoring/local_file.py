"""Demo-grade AnchorAdapter: append-only JSON-lines file, deliberately kept
outside the application's SQLite database (a different file, and in the
docker-compose demo, could be mounted from a different volume entirely).

This is illustrative, not a real security boundary: anyone with filesystem
access to this file can rewrite it too. A production deployment would
publish checkpoints to something the database administrator does not also
control — a separate signing/timestamping service, a WORM object store
with object-lock, or a public transparency log — none of which are
implemented here, consistent with every other adapter in this project
(mocks only, no vendor assumed).

Each line is still individually append-only in the sense that this class
exposes no method to rewrite or remove a line — the same enforcement
pattern used by AuditLog and SqliteAuditLog.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ivp.adapters.anchoring.interface import AnchorReceipt


class LocalFileAnchorAdapter:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    def publish_checkpoint(
        self, *, sequence_up_to: int, chain_hash: str, now: datetime
    ) -> AnchorReceipt:
        receipt = AnchorReceipt(
            sequence_up_to=sequence_up_to, chain_hash=chain_hash, published_at=now
        )
        line = json.dumps(
            {
                "sequence_up_to": receipt.sequence_up_to,
                "chain_hash": receipt.chain_hash,
                "published_at": receipt.published_at.isoformat(),
            }
        )
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        return receipt

    def list_checkpoints(self) -> list[AnchorReceipt]:
        if not self._path.exists():
            return []
        checkpoints = []
        with self._path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                checkpoints.append(
                    AnchorReceipt(
                        sequence_up_to=data["sequence_up_to"],
                        chain_hash=data["chain_hash"],
                        published_at=datetime.fromisoformat(data["published_at"]),
                    )
                )
        return checkpoints

    def latest_checkpoint(self) -> AnchorReceipt | None:
        checkpoints = self.list_checkpoints()
        return checkpoints[-1] if checkpoints else None
