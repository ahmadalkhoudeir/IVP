# ADR: Persistence, lockfile tool, and staff auth (delegated decisions)

The project owner delegated these to be decided directly rather than asked
as blocking questions. Recorded here for traceability.

## Persistence: SQLite by default
Accessed only through `src/ivp/db/repository.py` so a Postgres
implementation can be added later without touching `core`/`audit` logic.
SQLite fits `docker compose up`-with-zero-setup distribution, and its
single-writer model is actually a good fit for a hash-chained audit log,
which must be appended sequentially anyway — the usual "SQLite doesn't
scale to concurrent writers" concern is not a real cost here.

## Lockfile tool: uv
Chosen over Poetry for speed and simpler Docker layer caching
(`uv sync --frozen` in a build stage). `uv.lock` is committed.

## Staff authentication: local username/password
Argon2-hashed passwords (`passlib[argon2]`), server-side session cookie
(HttpOnly, Secure, SameSite), demo accounts seeded with synthetic
credentials when `IVP_SEED_DEMO_DATA=true`. No SSO/OIDC in v1. This is
authentication of *staff to the dashboard*, a separate concern from the
account holder's out-of-band verification — the two must not be conflated
in code or in the audit log's actor fields.

## Audit-log tamper-evidence scope: in-database hash chain only
Each audit record embeds the hash of the previous record
(`src/ivp/audit/log.py`). External anchoring (periodically publishing the
chain head to a separate write-once store, to defend against an attacker
with full database access) is a documented future enhancement, not built in
v1 — noted in `docs/threat-model.md` as a residual risk.
