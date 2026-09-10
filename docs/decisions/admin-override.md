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
