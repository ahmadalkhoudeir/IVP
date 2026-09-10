"""External anchoring port for the audit log's hash chain.

This closes the residual risk named in docs/threat-model.md: the chain is
self-consistent, but self-consistency alone doesn't help against an
attacker with full database access — they can rewrite every record and
recompute every hash forward, and verify_integrity() would still pass,
because it only checks the chain against itself.

Anchoring publishes the chain's current head hash to a store the attacker
who compromised the database does NOT also control. Periodically
"checkpointing" (sequence_up_to, chain_hash) means: even a full, internally
consistent rewrite of history up to that point can no longer match the
independently-stored chain_hash for that sequence, because that hash was
computed and published before the rewrite happened.

Security property, stated precisely: anchoring protects everything up to
the most recent published checkpoint. Records appended after the last
checkpoint (not yet anchored) are only as protected as the in-database hash
chain alone — narrowing that window is a matter of checkpointing
frequently, not something a single checkpoint can fix retroactively.

Only a local-file mock implementation exists here (see local_file.py) —
consistent with every other adapter in this project, no real external
service (a separate signing service, a WORM object store, a public
transparency log) is assumed or implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class AnchorReceipt:
    sequence_up_to: int
    chain_hash: str
    published_at: datetime


class AnchorAdapter(Protocol):
    def publish_checkpoint(
        self, *, sequence_up_to: int, chain_hash: str, now: datetime
    ) -> AnchorReceipt: ...

    def list_checkpoints(self) -> list[AnchorReceipt]:
        """Ascending by sequence_up_to."""
        ...

    def latest_checkpoint(self) -> AnchorReceipt | None: ...
