# IVP — Help Desk Identity Verification Protocol

A workflow enforcement layer — not an authenticator app — that wraps a help
desk ticketing system. When an agent requests a sensitive action (password
reset, MFA reset/change, account unlock), the system sends an out-of-band
confirmation to a channel the account holder enrolled *before* the call. A
sensitive ticket cannot be closed without a verification record attached.

Self-hosted browser dashboard with three RBAC roles (agent, supervisor,
admin) plus a separate "holder console" that simulates the account
holder's own device. See `docs/architecture.md`, `docs/state-machine.md`
and `docs/threat-model.md` for the design, and `docs/decisions/` for the
reasoning behind each choice below.

For a non-technical overview, read `docs/portfolio-writeup.md`.

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

### New in v1.1
- **"I did not request this."** The holder can report an unrequested
  prompt. The attempt is denied, recorded as `FRAUD_REPORTED`, and flagged
  on supervisor and admin dashboards (`docs/decisions/fraud-reporting.md`).
- **SIM-swap / number-port check.** PSTN channels with a carrier risk
  signal are never used (`RISK_BLOCKED`); push is used instead when the
  subscriber has one. The carrier feed is simulated.
- **Enrollment cooling-off.** Adding a channel notifies the existing ones
  (NIST SP 800-63B-4 §4.1.2.1), holds the new one for 24 hours, and writes a
  `CHANNEL_ENROLLED` audit record (`docs/decisions/enrollment-cooling-off.md`).
- **Graceful blocks.** A tripped push-bombing rate limit is recorded as
  `RATE_LIMITED` and explained to the agent instead of crashing; blocked
  tickets have a "Try verification again" button.
- **Metrics** for supervisors (team) and admins (all): median and
  90th-percentile time to verify against the 30-second target, how tickets
  resolved, and a per-agent table.
- **Verification receipts.** A printable per-ticket page with every audit
  record's hash and a live integrity and anchor check.
- **CSV export** of the audit log (formula-injection safe) plus
  `scripts/verify_audit_csv.py`, a standard-library verifier that recomputes
  the chain without importing the app.
- **Hardening:** CSPRNG codes, staff login lockout, 1-hour admin sessions,
  CSP and anti-framing headers, Origin-based CSRF checks, input validation
  (`docs/decisions/web-hardening.md`).
- A pending ticket shows a live countdown to expiry.

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

**Deploy a public demo (Render, free):** this repo includes a Render
Blueprint (`render.yaml`). In Render, choose New > Blueprint, connect this
GitHub repository, and click Apply. Render builds the Dockerfile, generates
a random session secret, and gives you an `https://...onrender.com` URL.
On the free plan the service sleeps when idle (the first request takes
about a minute) and the demo database resets on every restart.

The demo accounts below are public by design, so anyone with the URL can
log in as any role. Everything they can touch is synthetic demo data.

**Tests:**
```bash
uv run pytest
uv run ruff check src tests
```

## Demo walkthrough

Demo accounts (synthetic, seeded on first run):

| Username | Password | Role |
|---|---|---|
| `agent1` | `agent-demo-pass-1` | Agent |
| `agent2` | `agent-demo-pass-2` | Agent |
| `supervisor1` | `supervisor-demo-pass-1` | Supervisor |
| `admin1` | `admin-demo-pass-1` | Admin |

Demo subscribers: `sub-alice` (push), `sub-bob` (SMS), `sub-carol` (no
channel), `sub-erin` (SMS on a number the simulated carrier says was just
ported).

1. **Happy path.** Log in as `agent1` and open a ticket for `sub-alice`. A
   6-digit code appears with a countdown. Open the holder-console link
   (marked DEMO ONLY: a real deployment would never show an agent this
   link) in another tab and pick the matching code. Back on the ticket,
   authorize the action and close it.
2. **Impersonation.** Open another ticket for `sub-alice`. In the holder
   console, press "I did not request this". The agent sees a
   likely-impersonation banner and can't authorize the action.
3. **SIM swap.** Open a ticket for `sub-erin`. It is `RISK_BLOCKED`, and no
   SMS is sent.
4. **No channel.** Open a ticket for `sub-carol`. Closure is blocked until
   `admin1` records an override with a reason, or enrolls a channel at
   `/admin/subscribers` (deliberately not linked from the ticket flow; see
   hard requirement 2) and the agent presses "Try verification again".
5. **Supervisor view.** Log in as `supervisor1`. The dashboard flags the
   fraud report. Open **Metrics**, and click a ticket id for its
   verification receipt.
6. **Enrollment cooling-off.** As `admin1`, open **Channel enrollments** and
   add a second channel for `sub-alice`. The page shows a notice sent to
   Alice's phone and marks the new channel "cooling off". Alice's tickets
   keep using her phone.
7. **Tamper evidence.** As `admin1`, open **Full audit log**, click "Create
   checkpoint now", then "Verify against anchors". It should report a
   match. Click **Export CSV** and check the file independently:

   ```bash
   python3 scripts/verify_audit_csv.py ~/Downloads/ivp-audit-*.csv
   ```

   To see tampering caught, stop the app and edit a row directly. This only
   works after dropping the anti-tamper triggers, since they reject it by
   design:
   `sqlite3 demo_data/ivp.db "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET outcome='DENIED' WHERE sequence=0"`.
   Restart and verify again, or open any receipt.

Note: five wrong passwords lock a username for 15 minutes. Restarting the
app clears the lockout.

## Status of NIST/CISA alignment claims
This project cites NIST SP 800-63A-4, NIST SP 800-63B-4, and CISA guidance
for its identity-verification design choices. See `docs/threat-model.md` for
the specific citations and an explicit caveat on how they were verified.

## What's not built yet
- A holder-side "this wasn't me" response to an enrollment notice that
  revokes the new channel (needs a real notification channel with a
  callback).
- Per-form CSRF tokens; the Origin check is the current defense
  (`docs/decisions/web-hardening.md`).
- Shared storage for the login throttle and send rate limits, and
  server-side sessions, before running more than one worker
  (`docs/architecture.md`).
- A real external anchor store. The anchoring implemented here
  (`docs/decisions/audit-anchoring.md`) uses a local file kept outside the
  database, which demonstrates the pattern and is genuinely testable, but
  is not itself a security boundary — see that ADR for what a production
  deployment would need instead.
