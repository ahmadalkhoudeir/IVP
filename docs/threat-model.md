# Threat model (STRIDE)

| STRIDE category | Threat | Mitigation in design |
|---|---|---|
| Spoofing | Social-engineered agent bypasses/self-approves verification | Approval can only originate from the enrolled channel's callback, never from the agent's dashboard |
| Spoofing | Attacker asks to change the enrolled channel mid-call | No route in any role (including admin, mid-ticket) lets a live request supply or alter the destination channel; channel changes are a separate enrollment flow with its own verification |
| Spoofing | Attacker social-engineers an admin into enrolling an attacker-controlled channel, then calls the help desk | Every enrollment is audited; existing channels are notified (NIST SP 800-63B-4 §4.1.2.1); the new channel is unusable during a cooling-off period, so the real holder can react first (`docs/decisions/enrollment-cooling-off.md`). Residual: a subscriber's first channel has no one to notify and is usable immediately |
| Spoofing | Caller is an impersonator and the real holder receives the prompt | Holder can answer "I did not request this": the attempt is denied, recorded as FRAUD_REPORTED, and flagged to supervisors (`docs/decisions/fraud-reporting.md`) |
| Spoofing | Predictable number-matching code lets an attacker coach the victim | Codes come from the OS CSPRNG (`secrets`), not `random` |
| Spoofing | Brute-forcing a staff password | Per-username lockout after 5 failures in 15 minutes (NIST SP 800-63B-4 §3.2.2 allows lower limits than 100); Argon2 hashes; 12-character minimum for new accounts |
| Spoofing | SIM swap / number porting defeats SMS/voice OOB | NIST SP 800-63B-4 §3.1.3.3 classifies PSTN-delivered OOB as a restricted authenticator specifically because of this; push is preferred, and a PSTN channel with a carrier risk signal is never used (RISK_BLOCKED, `docs/decisions/verification-blocks.md`). The carrier feed is simulated |
| Spoofing | Staff session hijacking/fixation on the dashboard | HttpOnly, SameSite=Lax cookies (Secure when served over HTTPS); a new signed cookie on every login; 1-hour admin sessions vs 8 hours for other roles. Residual: cookies are stateless, so logout can't revoke a stolen copy before it expires |
| Spoofing | Cross-site request forgery against approve/override/enroll actions | State-changing requests must carry an Origin (or Referer) naming this host; missing or `null` origins are rejected (OWASP CSRF Prevention Cheat Sheet); SameSite=Lax as a second layer. Residual: no per-form tokens (`docs/decisions/web-hardening.md`) |
| Tampering | Clickjacking the holder's approve buttons in a hidden frame | `frame-ancestors 'none'` and `X-Frame-Options: DENY` on every response |
| Tampering | Insider or compromised account edits/deletes audit log entries, including via an admin UI screen | Append-only, hash-chained log; no route of any kind, for any role, ever calls UPDATE/DELETE on audit records — enforced at the repository layer, not just hidden from the UI |
| Tampering | Attacker with full database access rewrites the audit log wholesale and recomputes every hash forward, so the in-database chain alone would pass `verify_integrity()` | Chain head hash is periodically published to a store outside the database (`docs/decisions/audit-anchoring.md`); a later rewrite can no longer match a checkpoint published before it happened |
| Tampering | Replayed confirmation link reused after the attempt resolved | Each attempt has an unguessable UUID4 id bound to one ticket; any submission to an attempt that is no longer PENDING is logged as REJECTED and never changes the outcome. Residual: the state check is not a single atomic UPDATE (docs/architecture.md) |
| Tampering | Formula injection in an exported audit CSV executes in an auditor's spreadsheet | Cells starting with `= + - @`, tab or CR are prefixed with `'` (OWASP CSV Injection) |
| Repudiation | Agent or account holder later denies the request/approval | Full audit record (ticket ID, actor ID, action, channel, timestamps, outcome); hash chain makes the record's position in time tamper-evident; per-ticket verification receipt and a standalone CSV verifier (`scripts/verify_audit_csv.py`) let a third party check it without trusting the app |
| Information Disclosure | Audit log or ticket payload leaks PII/secrets; supervisor/admin views over-expose data | Synthetic data only; store channel type + hashed channel identifier, not raw phone/email; supervisor view scoped to their own team, not global |
| Denial of Service | MFA fatigue / push-bombing the real account holder | Rate-limited OOB sends per destination across tickets, recorded as RATE_LIMITED rather than crashing; number matching (CISA guidance) instead of a bare accept/deny |
| Elevation of Privilege | Agent or supervisor account reaches admin-only routes (enrollment/adapter config, user management) | Every route checks role server-side via a central FastAPI dependency (`src/ivp/auth/deps.py`); never duplicated ad hoc per view |
| Elevation of Privilege | Admin override becomes a de facto bypass of requirement 3 if not tightly scoped | Restricted to the admin role only (not supervisor); writes its own distinct `ADMIN_OVERRIDE` audit record with a required reason — see `docs/decisions/admin-override.md` |

## Residual risk after external anchoring
Anchoring (`docs/decisions/audit-anchoring.md`) protects everything up to
the most recently published checkpoint, not records appended after it —
narrowing that window is a matter of checkpointing frequently, not
something a single checkpoint fixes retroactively. It also isn't a real
security boundary in this project as built: the anchor store is a
demo-grade local file, not a genuinely separate system an attacker with
filesystem access couldn't also reach. A production deployment would
publish checkpoints to something the database administrator does not
control — a separate signing/timestamping service, a WORM object store, or
a public transparency log.

## Out-of-band channel evaluation

Primary source: NIST SP 800-63B-4, "Digital Identity Guidelines:
Authentication and Authenticator Management" —
https://pages.nist.gov/800-63-4/sp800-63b.html

| Channel | NIST 800-63B-4 classification | Notes for this project |
|---|---|---|
| Push (authenticated app) | Not classified as restricted; §3.2.9 area discusses push notification rate-limiting | Preferred channel. Paired with number matching per CISA guidance rather than a bare approve/deny, to resist push-bombing. |
| SMS / voice (PSTN) | Restricted authenticator, §3.1.3.3 ("Authentication Using the Public Switched Telephone Network"). Verifiers SHALL offer an unrestricted alternative, give subscribers meaningful notice of risk, address it in a risk assessment, and maintain a migration plan. SHOULD consider risk indicators (device swap, SIM change, number porting) before sending. | Usable, not exclusive: a non-PSTN alternative is always offered at enrollment; risk-signal checking is a mock/simulated adapter for this project, not a live carrier integration. |
| Email | Prohibited for out-of-band authentication ("Email SHALL NOT be used for out-of-band authentication...") | Not implemented at all — see `docs/decisions/email-channel.md`. |

**Citations:**
- NIST SP 800-63A-4 §2.5.1 (KBV/KBA prohibition): https://pages.nist.gov/800-63-4/sp800-63a.html
- NIST SP 800-63B-4 §3.1.3.3 + restricted-authenticator requirements, email OOB prohibition: https://pages.nist.gov/800-63-4/sp800-63b.html, https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
- CISA, phishing-resistant/number-matching MFA guidance (Oct 2022): https://www.cisa.gov/news-events/alerts/2022/10/31/cisa-releases-guidance-phishing-resistant-and-numbers-matching-multifactor-authentication
- CISA fact sheet, number matching: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf

- NIST SP 800-63B-4 §4.1.2.1 (notify subscriber when an authenticator is added), §3.2.2 (rate limiting, 100-attempt upper bound), §2.3.3 (AAL3 reauthentication timeouts): https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

**Caveat:** section numbers above were extracted via a fetch/summarize step
rather than read byte-for-byte by a human or by careful manual review of the
raw spec text. The substance (KBV prohibition, PSTN-restricted,
email-prohibited-for-OOB) is consistent with long-standing content carried
since 800-63B Rev. 3; treat exact section numbers as worth a quick manual
spot-check before repeating them as a citation outside this project.
