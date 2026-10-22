# ADR: Closure semantics

## Decision
A ticket stays OPEN until *some* verification record exists for it — there
is no path to close a ticket with zero record, not even to abandon it. A
record with outcome APPROVED, DENIED, or a final EXPIRED (retries exhausted)
all satisfy the gate equally. NO_CHANNEL_BLOCKED does not satisfy the gate on
its own — see `admin-override.md` for how those tickets get closed.

## Why
Explicit project owner decision: "it must stay open until some record exists
then it closes." This is the stricter of the two options considered (the
other being: allow closing with zero record as long as the *action* itself
stays gated on APPROVED). The stricter version leaves no path to
silently drop a sensitive request without an accountable outcome.

## Consequence
`VerificationAttempt.is_closure_eligible` (see
`src/ivp/core/state_machine.py`) returns True only for APPROVED, DENIED, and
EXPIRED-with-no-retries-left. The ticket-level closure gate (built on top of
this) must check for a closure-eligible attempt OR an ADMIN_OVERRIDE record
before allowing any close operation, for any role.

## Amendment (v1.1)
`FRAUD_REPORTED` also satisfies the closure gate, and it never authorizes
the action. See `fraud-reporting.md` for why it is a separate outcome
rather than a plain DENIED.
