# Verification attempt state machine

Implementation: `src/ivp/core/state_machine.py`. Tests: `tests/test_state_machine.py`.

```
                 (no enrolled channel for caller)
                          ┌─────────────────────────┐
                          ▼                          │
[REQUESTED] ──enroll check──> [NO_CHANNEL_BLOCKED] ───┘  (terminal for this ticket's
     │                                                    verification attempt —
     │ (channel exists)                                   requires an ADMIN_OVERRIDE
     ▼                                                    record to reach closure)
[PENDING_CONFIRMATION] ──send OOB, start timer
     │
     ├── caller/holder approves from enrolled channel ──> [APPROVED]           (closure-eligible)
     ├── caller/holder denies from enrolled channel ─────> [DENIED]            (closure-eligible)
     ├── holder reports "I did not request this" ────────> [DENIED]            (closure-eligible;
     │                                                         audit outcome FRAUD_REPORTED)
     └── timer elapses with no response ──────────────────> [EXPIRED]
                                                                 │
                                                    attempts remaining? ── yes ──> retry() ──> [PENDING_CONFIRMATION]
                                                                 │
                                                                 no
                                                                 │
                                                                 ▼
                                                     [EXPIRED, final]           (closure-eligible)
```

Key design points:

- **A verification record exists for every terminal outcome**, including
  denials and exhausted-retry expirations — per
  `docs/decisions/closure-semantics.md`, the ticket cannot close on zero
  record, but a record of *refusal* still counts.
- **NO_CHANNEL_BLOCKED is a hard stop inside this system.** Falling back to
  knowledge-based verification to produce a record would violate hard
  requirement 1. The only path out is an `ADMIN_OVERRIDE` record (see
  `docs/decisions/admin-override.md`), which is deliberately not part of
  this state machine — it lives at the audit-log/ticket layer since it's an
  administrative act, not a verification outcome.
- **The confirmation timeout (`IVP_CONFIRMATION_TIMEOUT_SECONDS`, default
  240s) is a separate parameter from the "under 30 seconds" target.** 30
  seconds is a happy-path UX target (push round-trip), not a safe timeout to
  abandon a real human on a call.
- **Retries are capped** (`IVP_MAX_CONFIRMATION_ATTEMPTS`, default 3) so an
  expired confirmation can't be resent indefinitely — indefinite resends
  would themselves be a push-bombing vector against the real account
  holder.

## Before an attempt exists (v1.1)

Some tickets never get an attempt because verification can't start. Each
case writes an audit record with its reason and leaves the ticket OPEN.
None of them is closure-eligible:

- `NO_CHANNEL_BLOCKED`: nothing enrolled, or every channel is still in
  enrollment cooling-off.
- `RISK_BLOCKED`: every usable channel is PSTN with a SIM-swap or
  number-port signal.
- `RATE_LIMITED`: the per-destination send limit refused the send.

The agent can retry with `restart`, which only works while the ticket has
no attempt and no verification record. See
`docs/decisions/verification-blocks.md`.
