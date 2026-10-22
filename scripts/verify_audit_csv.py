#!/usr/bin/env python3
"""Independently verify an IVP audit-log CSV export.

Recomputes every record's SHA-256 hash and the prev_hash links from the
exported columns alone. Standard library only and deliberately does NOT
import the ivp package: an auditor should be able to check the evidence
without trusting the application that produced it.

Usage:
    python3 scripts/verify_audit_csv.py ivp-audit-20261022T150000Z.csv
    python3 scripts/verify_audit_csv.py export.csv --anchor-hash <hex> --anchor-seq <n>

Exit code 0 when the chain verifies, 1 when it doesn't.

A full export starts at sequence 0 and is checked from the genesis hash. A
team export (supervisor) contains only some records, so only each record's
own hash can be checked, not the links between them.

The canonical form here must match ivp.audit.log._canonical_payload; the
test suite round-trips an export through this script to keep them in sync.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys

GENESIS_HASH = "0" * 64
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _unneutralize(value: str) -> str:
    """Undo the export's spreadsheet-formula protection (a leading ')."""
    if value.startswith("'") and value[1:].startswith(_FORMULA_PREFIXES):
        return value[1:]
    return value


def record_hash(row: dict[str, str]) -> str:
    payload = {
        "sequence": int(row["sequence"]),
        "ticket_id": _unneutralize(row["ticket_id"]),
        "actor_id": _unneutralize(row["actor_id"]),
        "actor_role": _unneutralize(row["actor_role"]),
        "requested_action": row["requested_action"],
        "channel_type": row["channel_type"] or None,
        "outcome": row["outcome"],
        "timestamp": row["timestamp"],
        "reason": _unneutralize(row["reason"]) or None,
        "prev_hash": row["prev_hash"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify(rows: list[dict[str, str]]) -> list[str]:
    """Returns a list of problems; empty means the export verifies."""
    problems = []
    contiguous = bool(rows) and all(int(r["sequence"]) == i for i, r in enumerate(rows))
    expected_prev = GENESIS_HASH
    for row in rows:
        seq = row["sequence"]
        if record_hash(row) != row["record_hash"]:
            problems.append(f"sequence {seq}: contents do not match record_hash")
        if contiguous and row["prev_hash"] != expected_prev:
            problems.append(f"sequence {seq}: prev_hash does not link to sequence {int(seq) - 1}")
        expected_prev = row["record_hash"]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("csv_path")
    parser.add_argument("--anchor-seq", type=int, help="sequence_up_to of a published checkpoint")
    parser.add_argument("--anchor-hash", help="chain_hash of that checkpoint")
    args = parser.parse_args(argv)

    with open(args.csv_path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    problems = verify(rows)
    if args.anchor_hash is not None and args.anchor_seq is not None:
        match = next((r for r in rows if int(r["sequence"]) == args.anchor_seq), None)
        if match is None:
            problems.append(f"anchor: sequence {args.anchor_seq} not in this export")
        elif match["record_hash"] != args.anchor_hash:
            problems.append(f"anchor: sequence {args.anchor_seq} hash differs from checkpoint")

    contiguous = bool(rows) and all(int(r["sequence"]) == i for i, r in enumerate(rows))
    scope = "full chain from genesis" if contiguous else "per-record hashes only (partial export)"
    if problems:
        print(f"FAILED ({len(rows)} records, {scope}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: {len(rows)} records verified ({scope}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
