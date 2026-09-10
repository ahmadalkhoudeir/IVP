# IVP — Help Desk Identity Verification Protocol

A workflow enforcement layer — not an authenticator app — that wraps a help
desk ticketing system. When an agent requests a sensitive action (password
reset, MFA reset/change, account unlock), the system sends an out-of-band
confirmation to a channel the account holder enrolled *before* the call. A
sensitive ticket cannot be closed without a verification record attached.

Self-hosted browser dashboard with three RBAC roles (agent, supervisor,
admin) plus a separate "holder console" that simulates the account
holder's own device — see `docs/state-machine.md` and `docs/threat-model.md`
for the design, and `docs/decisions/` for the reasoning behind each choice
below.

## Design highlights
- No knowledge-based verification anywhere (NIST SP 800-63A-4 §2.5.1).
- Confirmation channels are enrolled before the request; nothing in a live
  ticket can supply or change the destination channel.
- Append-only, hash-chained audit log, enforced at two layers: the Python
  class exposes no update/delete method, and the SQLite table itself has
  triggers that reject UPDATE/DELETE outright.
- Ticketing and notification systems are accessed only through adapter
  interfaces; only mock implementations exist (no vendor lock-in). The mock
  ticketing adapter re-validates every closure/action-performed call
  against the audit log itself — it never trusts a caller's claim.
- Number matching (CISA guidance) for push/PSTN confirmations, with a
  destination-keyed rate limiter for push-bombing defense.
- Email is deliberately not implemented as an out-of-band channel — see
  `docs/decisions/email-channel.md` for the NIST-based reasoning.
- RBAC enforced server-side on every route; a ticket-closure override
  exists only for admins, requires a reason, and writes its own distinct
  audit outcome (`ADMIN_OVERRIDE`) rather than a synthetic approval.
- The audit log's hash-chain head is periodically anchored outside the
  database (`docs/decisions/audit-anchoring.md`), so a full rewrite of the
  database that recomputes every hash forward still doesn't pass
  verification — `/admin/audit` has "Create checkpoint now" and "Verify
  against anchors" actions.

## Stack
Python + FastAPI, Jinja2 + htmx (no separate JS framework — htmx is
vendored locally, not loaded from a CDN, so the app works fully offline
once running). SQLite by default. Dependencies pinned with `uv`.

## Running it

**Locally:**
```bash
uv sync
uv run uvicorn ivp.main:app --reload
```
Then open http://127.0.0.1:8000 and log in with a demo account (see
`src/ivp/services/demo_seed.py` — synthetic credentials only, seeded
automatically on first run when `IVP_SEED_DEMO_DATA=true`, the default).

**Docker Compose:**
```bash
docker compose up --build
```
Verified: built and ran via `colima` + `docker compose` (Docker isn't
preinstalled in the dev environment this was built in). Confirmed the full
happy-path flow works inside the container exactly as it does locally, and
that ticket data survives a `docker compose restart` via the named volume.

**Tests:**
```bash
uv run pytest
uv run ruff check src tests
```

## Demo walkthrough
1. Log in as `agent1`.
2. Open a ticket for `sub-alice` (has an enrolled push channel) — a
   confirmation is sent and a 6-digit code is shown to read aloud.
3. Open the holder-console link on the ticket page (clearly marked DEMO
   ONLY — a real deployment would never show an agent this link) in another
   tab, and select the matching code.
4. Back on the ticket page, authorize the action and close the ticket.
5. Try the same flow with `sub-carol` (no enrolled channel) — closure is
   blocked until an admin (`admin1`) records an override with a reason, or
   enrolls a channel for her at `/admin/subscribers` (deliberately not
   linked from the ticket flow — see hard requirement 2).
6. As `admin1`, visit `/admin/audit` and click "Create checkpoint now",
   then "Verify against anchors" — it should report a match. To see it
   catch tampering, stop the app, edit a row in the SQLite database
   directly (e.g. `sqlite3 demo_data/ivp.db "UPDATE audit_log SET outcome='DENIED' WHERE sequence=0"` —
   this only works if you've dropped the anti-tamper triggers, since they
   reject it by design), restart, and verify again.

## Status of NIST/CISA alignment claims
This project cites NIST SP 800-63A-4, NIST SP 800-63B-4, and CISA guidance
for its identity-verification design choices. See `docs/threat-model.md` for
the specific citations and an explicit caveat on how they were verified.

## What's not built yet
- Cooling-off notice to existing channels when a new one is enrolled for the
  same subscriber (noted as a simplification on the enrollment page itself).
- A real external anchor store. The anchoring implemented here
  (`docs/decisions/audit-anchoring.md`) uses a local file kept outside the
  database, which demonstrates the pattern and is genuinely testable, but
  is not itself a security boundary — see that ADR for what a production
  deployment would need instead.
