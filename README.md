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
This has been reviewed but not run in this environment (Docker isn't
available here) — the image build follows a standard `uv sync --frozen`
pattern and the app itself has been run and manually exercised outside a
container. Please verify `docker compose up` on your machine before relying
on it, and open an issue/note if it doesn't build cleanly.

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
   blocked until an admin (`admin1`) records an override with a reason.

## Status of NIST/CISA alignment claims
This project cites NIST SP 800-63A-4, NIST SP 800-63B-4, and CISA guidance
for its identity-verification design choices. See `docs/threat-model.md` for
the specific citations and an explicit caveat on how they were verified.

## What's not built yet
- External anchoring for the audit log's hash chain (documented as a
  residual risk in `docs/threat-model.md`, not implemented in v1).
- A dedicated channel-enrollment UI (enrollments exist in the schema and
  are seeded as demo data, but there's no staff- or holder-facing screen to
  create one).
