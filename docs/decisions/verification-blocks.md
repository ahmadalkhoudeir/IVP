# ADR: When verification can't start

## Context
v1.0 had one "can't verify" outcome, NO_CHANNEL_BLOCKED. Two more cases
existed in the code but weren't handled:

- The destination-keyed send rate limit (push-bombing defense, CISA
  guidance) raised `RateLimitExceeded`, which nothing caught: ticket creation
  failed with an HTTP 500 after the ticket row was already written.
- `MockPstnAdapter.check_risk_signals` (SIM swap / number port) existed but
  was never called, so a PSTN channel with a carrier risk flag was used
  anyway.

## Decision
Every "verification could not start" case writes its own audit record with
the reason, leaves the ticket OPEN, and is not closure-satisfying:

| Outcome | When | Way out |
|---|---|---|
| `NO_CHANNEL_BLOCKED` | Nothing enrolled, or every channel still in enrollment cooling-off | Admin override, or retry after an enrollment |
| `RATE_LIMITED` | The send limit for that destination refused the send | Retry after the window |
| `RISK_BLOCKED` | Every usable channel is PSTN with a SIM-swap / port signal | Admin override after out-of-band proofing |

Channel choice is: skip channels in cooling-off; prefer PUSH over PSTN
(PSTN is a NIST SP 800-63B-4 restricted authenticator); skip PSTN channels
with a risk signal. NIST SP 800-63B-4 says verifiers SHOULD consider risk
indicators such as device swap, SIM change and number porting before using
PSTN (see docs/threat-model.md for the citation and its caveat).

The send happens before the attempt row is created, so a refused send never
leaves a phantom PENDING attempt. On a rate-limited *resend*, the attempt
stays EXPIRED with its retry unspent.

## Restart
`POST /agent/tickets/{id}/restart` re-runs channel selection for a ticket
with **no attempt and no verification record**. It refuses everything else,
so it can't be used to re-roll a DENIED or fraud-reported verification.
This is not a channel change (requirement 2): it only picks among channels
enrolled through the separate enrollment flow.
