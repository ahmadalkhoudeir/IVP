# ADR: Email is not an out-of-band confirmation channel

## Decision
Email is not implemented as a notification adapter in v1, in any form
(including notice-only). Only `PUSH` and `PSTN` channel types exist
(`src/ivp/core/models.py::ChannelType`).

## Why
NIST SP 800-63B-4 states: "Email SHALL NOT be used for out-of-band
authentication because it may be vulnerable to: Access using only a
password; Interception in transit or at intermediate mail servers;
Rerouting attacks, such as those caused by Domain Name System (DNS)
spoofing." (https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)

A notice-only email adapter was considered (send a non-authoritative "a
request was made on your account" notice that never satisfies the closure
gate) to make the compliance reasoning explicit in the demo. Decided against
building it: it adds an adapter, tests, and UI surface for a channel that
plays no role in the actual verification decision, without adding to the
portfolio's demonstrated reasoning — that reasoning is fully captured here
and in `docs/threat-model.md` without shipping the code path. If a future
milestone wants the notice behavior, it should be scoped as its own adapter
type (e.g. `NotificationOnly`) that is structurally incapable of producing a
`VerificationAttempt` outcome, not a variant of the confirmation channel.

## Consequence
`ChannelType` has no `EMAIL` member. Enrollment only ever offers `PUSH` and
`PSTN`. README/portfolio writeup should state this exclusion explicitly with
the citation above, since it is a compliance decision worth surfacing, not
just an omission.
