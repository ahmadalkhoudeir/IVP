# IVP — Help Desk Identity Verification Protocol

A workflow enforcement layer — not an authenticator app — that wraps a help
desk ticketing system. When an agent requests a sensitive action (password
reset, MFA reset/change, account unlock), the system sends an out-of-band
confirmation to a channel the account holder enrolled *before* the call. A
sensitive ticket cannot be closed without a verification record attached.

Status: early scaffolding. See `docs/state-machine.md` and
`docs/threat-model.md` for the design, and `docs/decisions/` for the
reasoning behind the choices below.

## Design highlights
- No knowledge-based verification anywhere (NIST SP 800-63A-4 §2.5.1).
- Confirmation channels are enrolled before the request; nothing in a live
  ticket can supply or change the destination channel.
- Append-only, hash-chained audit log — no update/delete path exists for any
  role.
- Ticketing and notification systems are accessed only through adapter
  interfaces; only mock implementations exist so far (no vendor lock-in).
- Email is deliberately not implemented as an out-of-band channel — see
  `docs/decisions/email-channel.md` for the NIST-based reasoning.

## Stack
Python + FastAPI, Jinja2 + htmx (no separate JS framework), SQLite by
default, dependencies pinned with `uv`. Distributed via Docker Compose with
mock adapters and synthetic demo data so it runs out of the box.

## Development
```bash
uv sync
uv run pytest
```

## Status of NIST/CISA alignment claims
This project cites NIST SP 800-63A-4, NIST SP 800-63B-4, and CISA guidance
for its identity-verification design choices. See `docs/threat-model.md` for
the specific citations and an explicit caveat on how they were verified.
