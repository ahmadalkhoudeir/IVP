# ADR: Web-layer hardening

## Decisions

**Confirmation codes from a CSPRNG.** `secrets.randbelow`, not `random`.
Python's `random` is a Mersenne Twister whose internal state can be
recovered from enough outputs; a predictable code would let an attacker
coach a victim to "pick 123456", defeating number matching.

**Staff login throttling.** 5 failures per username in 15 minutes locks
that username for the rest of the window, checked before the password so a
correct guess during lockout gives no signal. NIST SP 800-63B-4 §3.2.2
caps consecutive failures at 100 and says "agencies MAY impose lower
limits"; staff accounts here are password-only and guard every subscriber,
so the limit is much lower. Keyed by username, not IP, so a distributed
spray is still counted per account. Unknown usernames are counted the same
way, so lockout doesn't reveal which usernames exist. In-memory: a restart
clears it, and multiple workers would each keep their own count
(docs/architecture.md, scaling notes).

**Admin sessions last 1 hour**, other roles 8 hours, enforced server-side on
every request. NIST SP 800-63B-4 §2.3.3 puts the AAL3 overall reauthentication
timeout at no more than 12 hours and the inactivity timeout at no more than
15 minutes. This app has no inactivity timer; a 1-hour absolute limit for
the role that can override the closure gate is the compromise.

**Security headers on every response.** CSP with scripts from self only
(htmx is vendored), `frame-ancestors 'none'` and `X-Frame-Options: DENY`
against clickjacking the approve buttons, `Referrer-Policy: same-origin`
because the holder-console URL carries the attempt id (not `no-referrer`:
under the Fetch standard that makes browsers send `Origin: null` on every
POST, which would break the CSRF check below), `Cache-Control:
no-store` on dynamic pages so audit data and codes don't persist in a
browser cache after logout.

**CSRF.** Every state-changing request must carry an Origin header naming
this host, or a Referer naming it when Origin is absent. Missing headers
and `Origin: null` are rejected with 403. This follows the OWASP CSRF
Prevention Cheat Sheet ("If the Origin header is present, verify that its
value matches the target origin"; "Missing headers and `Origin: null` are
not evidence of a same-origin request"):
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
Session cookies are also `SameSite=Lax`, which OWASP calls "useful as a
defense-in-depth control but it does not replace a proper CSRF defense".

Per-form CSRF tokens were not added. OWASP lists Origin verification under
defense in depth and recommends tokens as the primary defense, so this is a
known gap: the app has no state-changing GET routes and no untrusted
subdomains, which is where header checks are weakest. Tokens are listed as
future work in docs/architecture.md.

**CSV export neutralizes formulas.** Cells starting with `= + - @`, tab or
carriage return get a leading `'`, because override reasons are free text
written by people and would otherwise execute when an auditor opens the
file in a spreadsheet (OWASP "CSV Injection").

**Input validation.** Ticket creation accepts only the three ticket actions
and a known subscriber. Staff accounts need a valid role and a password of
at least 12 characters.
