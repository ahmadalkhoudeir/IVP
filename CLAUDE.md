# IVP — Help Desk Identity Verification Protocol

## What this is
A self-hosted browser dashboard (agent/supervisor/admin roles, RBAC) that
wraps a help desk ticketing workflow with an out-of-band identity
verification gate and an append-only, hash-chained audit log. It is NOT an
authenticator app. Sensitive actions (password reset, MFA reset/change,
account unlock) require an out-of-band confirmation from a channel enrolled
before the call, and a sensitive ticket cannot be closed without a
verification record attached.

## Hard requirements
Do not violate any of these without writing a new file in
`docs/decisions/` explaining why.

1. No knowledge-based authentication/verification anywhere (no security
   questions, DOB, last-4 checks) — NIST SP 800-63A-4 §2.5.1.
2. Confirmation channels are enrolled BEFORE the request. No route, in any
   role including admin, may supply or change the destination channel
   mid-ticket. Channel enrollment/changes are a separate flow with their own
   verification.
3. Ticket closure is blocked until a verification record exists for that
   ticket. Per `docs/decisions/closure-semantics.md`, this means the ticket
   stays OPEN — with no shortcut, even to abandon it — until some record
   exists: APPROVED, DENIED, a final EXPIRED (retries exhausted), or an
   ADMIN_OVERRIDE record.
4. The audit log is append-only and hash-chained. No UPDATE/DELETE path is
   ever exposed, for any role, anywhere in the codebase. Every record:
   ticket ID, actor ID, requested action, channel used, timestamps, outcome.
5. Target end-to-end verification time under 30 seconds for the happy path.
   This is a UX target, not a safe timeout to abandon a live caller — the
   actual PENDING_CONFIRMATION timeout is configurable
   (`IVP_CONFIRMATION_TIMEOUT_SECONDS`, default 240s / 4 min).
6. Ticketing and notification systems are accessed only through adapter
   interfaces (`src/ivp/adapters/*/interface.py`). Mock implementations are
   the only ones that exist until told otherwise. Never hardcode assumptions
   about a specific vendor (ServiceNow, Jira, Twilio, etc.).
7. No real credentials, API keys, or personal data anywhere in the repo.
   `.env.example` only; synthetic demo data only (`demo_data/`).
8. Email is never used to satisfy the closure gate — NIST SP 800-63B-4
   prohibits email for out-of-band authentication. See
   `docs/decisions/email-channel.md`. It is not implemented as an adapter at
   all in v1.
9. Every dashboard route enforces its role requirement server-side via the
   central RBAC dependency in `src/ivp/auth/deps.py` — never rely on hiding
   UI elements to restrict access.
10. Only admins may override the closure gate (close a ticket without a
    completed OOB record), and only by writing a distinct `ADMIN_OVERRIDE`
    audit record with a required reason and the admin's ID. Supervisors
    cannot override. See `docs/decisions/admin-override.md`.

## Stack & conventions
- Python + FastAPI. Jinja2 + htmx for the UI — no separate JS framework or
  build step.
- Dependencies pinned via `uv` (`uv.lock`). Run `uv sync` to install,
  `uv run pytest` to test, `uv add <pkg>` to add a dependency.
- SQLite by default (`IVP_DATABASE_PATH`), accessed only through the
  repository interface in `src/ivp/db/repository.py` — never import a
  driver directly outside `src/ivp/db/`.
- Docker Compose must run out of the box with mock adapters and seeded
  synthetic demo data (`docker compose up`).
- Test order for new work: state machine → timeouts → ticket-closure
  blocking → audit-log integrity → role permissions → UI screens. Don't
  build a UI screen before its underlying rule has a passing test.
- Small, working commits. Commit after each milestone, not at the end of a
  session.
- Cite primary sources (NIST/CISA/vendor docs) for any new security or
  compliance claim added to docs. Mark anything you could not verify as
  UNVERIFIED.
