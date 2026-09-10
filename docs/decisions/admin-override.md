# ADR: Admin override

## Decision
Only the **admin** role may close a ticket without a completed OOB
verification record. Supervisors cannot. Every override:

- writes its own distinct audit record type, `ADMIN_OVERRIDE` (not a
  synthetic APPROVED/DENIED — it must be visibly distinguishable in the
  audit log from a real account-holder response),
- requires a mandatory reason string from the admin,
- captures the admin's ID and timestamp like any other audit record,
- is subject to the same append-only, hash-chained, no-UPDATE/DELETE rules
  as every other audit record.

This is the primary (and, in v1, only) path for closing a `NO_CHANNEL_BLOCKED`
ticket: the admin attests that identity was proofed some other way outside
this system (e.g., in person, notarized request) and records why.

## Why
Explicit project owner decision, in response to "should supervisors be able
to override closure" — answer restricted override capability to admins only.
Restricting to a single, more privileged, more accountable role limits the
blast radius of this necessarily risky escape hatch (see threat model:
"a supervisor override becomes the loophole that defeats requirement 3").

## Consequence
- The audit log schema must support an `ADMIN_OVERRIDE` outcome value distinct
  from `APPROVED`/`DENIED`/`EXPIRED`.
- The RBAC layer (`src/ivp/auth/deps.py`) must expose a `require_role(Role.ADMIN)`
  dependency guarding the override route specifically — the general admin
  role check is not sufficient documentation of *why* this route is
  restricted, so the route itself should assert intent in code/comments.
- `docs/threat-model.md` must carry this as a named risk, not just an
  implementation detail.

## Follow-up decision: does an override authorize performing the action?
`TicketClosureGate` (`src/ivp/core/closure.py`) treats `ADMIN_OVERRIDE` as
authorizing *both* ticket closure and marking the sensitive action
performed — not just closure. `DENIED` and a plain `EXPIRED` record close
the ticket but never authorize the action.

This was not explicitly specified by the project owner and is called out
here as a judgment call, not a settled requirement — **flagged for
confirmation**. The reasoning: an admin override exists primarily for the
`NO_CHANNEL_BLOCKED` case, where the account holder was identity-proofed by
some out-of-system means (e.g., in person). If the override could close the
ticket but never let the action be marked performed, the escape hatch would
be useless for its stated purpose. The trade-off is real, though: this makes
`ADMIN_OVERRIDE` the single highest-value target in the system for a
compromised or coerced admin account, since it's the one record type that
can authorize a sensitive action with no OOB confirmation at all. If that
trade-off is unacceptable, the alternative is to split this into two
distinct record types (e.g. `ADMIN_OVERRIDE_CLOSE_ONLY` vs.
`ADMIN_OVERRIDE_AUTHORIZE_ACTION`), so an admin must explicitly choose the
stronger claim rather than one override doing both silently.
