# ADR: Enrollment notification and cooling-off

## Context
Hard requirement 2 keeps channel changes out of the ticket flow. That moves
the attack, it doesn't remove it: a social engineer can call a *different*
admin and ask them to "add my new phone" before calling the help desk. v1.0
named this as a gap on the enrollment page itself.

## Decision
Channel enrollment goes through `ChannelEnrollmentService`, which:

1. **Notifies every existing channel** of the subscriber when a new one is
   added, through that existing channel. NIST SP 800-63B-4 §4.1.2.1: "When
   an authenticator is added, the CSP SHALL notify the subscriber via a
   mechanism independent of the transaction binding the new
   authenticator." (https://pages.nist.gov/800-63-4/sp800-63b.html)
2. **Holds the new channel in cooling-off** (`IVP_ENROLLMENT_COOLING_OFF_HOURS`,
   default 24) before verification may use it. Verification keeps using
   the older channels meanwhile. The delay is a **project design choice,
   not a NIST requirement**: notification without a delay lets an attacker
   enroll and use a channel in the same minute, before the real holder
   reads the notice.
3. **Audits the enrollment** as a `CHANNEL_ENROLLED` record on the same
   hash chain (ticket id `ENR-...`, actor = admin, reason = subscriber,
   label, usable-from time, number of channels notified). The raw
   destination is never logged; only its fingerprint is stored.
4. Rejects malformed subscriber ids, empty or overlong labels, and a
   destination already enrolled for that subscriber.

## Trade-off: the first channel is usable immediately
With no existing channel there is nobody to notify, and a delay would only
lock out a new user. The real protection for a first enrollment is the
identity proofing done before it (NIST SP 800-63A-4), which happens outside
this system. Recorded as a known residual risk in docs/threat-model.md.

## Not done
A holder-side "this wasn't me" button on the enrollment notice that
revokes the new channel. That needs a real notification channel with a
callback, which only a production adapter would have.
