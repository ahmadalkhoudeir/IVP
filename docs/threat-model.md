# Threat model (STRIDE)

| STRIDE category | Threat | Mitigation in design |
|---|---|---|
| Spoofing | Social-engineered agent bypasses/self-approves verification | Approval can only originate from the enrolled channel's callback, never from the agent's dashboard |
| Spoofing | Attacker asks to change the enrolled channel mid-call | No route in any role (including admin, mid-ticket) lets a live request supply or alter the destination channel; channel changes are a separate enrollment flow with its own verification |
| Spoofing | SIM swap / number porting defeats SMS/voice OOB | NIST SP 800-63B-4 §3.1.3.3 classifies PSTN-delivered OOB as a restricted authenticator specifically because of this; see channel evaluation below |
| Spoofing | Staff session hijacking/fixation on the dashboard | HttpOnly, Secure, SameSite cookies; session rotation on login; short session lifetime for the admin role |
| Tampering | Insider or compromised account edits/deletes audit log entries, including via an admin UI screen | Append-only, hash-chained log; no route of any kind, for any role, ever calls UPDATE/DELETE on audit records — enforced at the repository layer, not just hidden from the UI |
| Tampering | Replayed confirmation token reused against a different ticket | Single-use, ticket+nonce-bound token; atomic check-and-invalidate |
| Repudiation | Agent or account holder later denies the request/approval | Full audit record (ticket ID, actor ID, action, channel, timestamps, outcome); hash chain makes the record's position in time tamper-evident |
| Information Disclosure | Audit log or ticket payload leaks PII/secrets; supervisor/admin views over-expose data | Synthetic data only; store channel type + hashed channel identifier, not raw phone/email; supervisor view scoped to their own team, not global |
| Denial of Service | MFA fatigue / push-bombing the real account holder | Rate-limited OOB sends; number matching (CISA guidance) instead of a bare accept/deny |
| Elevation of Privilege | Agent or supervisor account reaches admin-only routes (enrollment/adapter config, user management) | Every route checks role server-side via a central FastAPI dependency (`src/ivp/auth/deps.py`); never duplicated ad hoc per view |
| Elevation of Privilege | Admin override becomes a de facto bypass of requirement 3 if not tightly scoped | Restricted to the admin role only (not supervisor); writes its own distinct `ADMIN_OVERRIDE` audit record with a required reason — see `docs/decisions/admin-override.md` |

## Residual risk, documented not built in v1
- **Audit log external anchoring.** The hash chain is self-consistent but
  lives in the same database an attacker with full DB access could rewrite
  wholesale (recomputing every hash forward). External anchoring (e.g.
  periodically publishing the chain head hash to a separate write-once
  store) would close this gap. See `docs/decisions/persistence-and-tooling.md`.

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

**Caveat:** section numbers above were extracted via a fetch/summarize step
rather than read byte-for-byte by a human or by careful manual review of the
raw spec text. The substance (KBV prohibition, PSTN-restricted,
email-prohibited-for-OOB) is consistent with long-standing content carried
since 800-63B Rev. 3; treat exact section numbers as worth a quick manual
spot-check before repeating them as a citation outside this project.
