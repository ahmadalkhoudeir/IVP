# ADR: Fraud reporting ("I did not request this")

## Decision
The holder console offers a third response besides picking a code or "none
of these match": **"I did not request this — report it."** It:

- moves the attempt to `DENIED` in the state machine (no new state), so the
  sensitive action can never be authorized from it;
- writes a distinct `FRAUD_REPORTED` audit record, with the holder as actor
  and a fixed reason string;
- shows the agent a "likely impersonation, end the call" banner;
- flags the ticket to supervisors (team dashboard) and admins (all tickets),
  and counts it on the metrics pages.

## Change to hard requirement 3
`FRAUD_REPORTED` is added to the closure-satisfying outcomes (alongside
APPROVED, DENIED, final EXPIRED and ADMIN_OVERRIDE). It is **not** an
action-authorizing outcome. This is a deliberate extension of requirement 3,
recorded here as CLAUDE.md requires:

- It is a verification record in every sense requirement 3 cares about: an
  accountable response from the enrolled channel, on the hash chain.
- Without it, a fraud-reported ticket would be stuck OPEN forever or need
  an admin override, which would bury the most important signal the system
  produces under an administrative act.

## Why a separate outcome instead of plain DENIED
"Wrong code" and "someone is impersonating me" call for different
responses. A mismatch can be an honest mis-hearing; a fraud report is
evidence of a social-engineering attempt in progress, the exact attack this
project exists to stop (help desk impersonation leading to a password or
MFA reset). Collapsing them would throw that signal away.

Prior art: Microsoft Entra ID's "Report suspicious activity" setting. Per
Microsoft's documentation, "When an unknown and suspicious MFA prompt is
received, users can report the activity", and "Users who report an MFA
prompt as suspicious are set to High User Risk." Source:
https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#report-suspicious-activity

## What it does not do
It doesn't lock the subscriber's account or notify a security team; those
belong to the identity provider and the incident process, reached through
adapters a real deployment would add.
