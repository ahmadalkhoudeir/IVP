# Help Desk Identity Verification Protocol: Portfolio Write-up

**Ahmad Al Khoudeir** · B.S. Cybersecurity (Cyber Defense), CCSU

## The problem

Attackers don't have to break MFA if they can call the help desk and talk
an agent into resetting it. The 2023 MGM Resorts breach is the best-known
example: Scattered Spider reportedly got in by impersonating an employee on
a call to the IT help desk. Most help desks still "verify" callers with
knowledge-based questions (date of birth, last four of an SSN, a security
question) whose answers are often found in breach dumps or on social media.

NIST has said for years that this isn't acceptable. SP 800-63A-4 states
that knowledge-based verification SHALL NOT be used for identity
verification, and KBA hasn't been an acceptable authenticator since
SP 800-63-3 in 2017. The gap between the guidance and day-to-day help desk
practice is what this project addresses.

Source for the NIST text: https://pages.nist.gov/800-63-4/sp800-63a.html.
The MGM detail comes from public reporting on the incident and is not from
a primary source (UNVERIFIED).

## What I built

A self-hosted web application that sits in front of a help desk ticketing
system and enforces a process, rather than adding another authenticator:

1. An agent opens a ticket for a sensitive action (password reset, MFA
   reset, account unlock).
2. The system sends a confirmation to a channel the account holder enrolled
   **before** the call. Nothing in the ticket can choose or change it.
3. The agent reads a six-digit code aloud. The holder picks the matching
   code on their device (number matching, per CISA guidance), or reports
   "I did not request this."
4. The action can be performed only after APPROVED, and the ticket cannot
   close without some verification record on file.
5. Every step lands in an append-only, hash-chained audit log whose head is
   anchored outside the database.

## Design decisions worth discussing in an interview

- **No fallback to security questions, ever.** When a subscriber has no
  usable channel, the ticket is blocked until an admin records an override
  with a written reason. That override is its own audit outcome, not a fake
  approval.
- **Tamper evidence at three layers.** The Python class has no update or
  delete method. The SQLite table has triggers that reject UPDATE and
  DELETE. And because a database admin could still rewrite every row and
  recompute every hash, the chain head is periodically published to an
  external store, and a full rewrite no longer matches it.
- **Push-bombing defense.** Number matching instead of approve/deny, retry
  caps per ticket, and a per-destination send rate limit across tickets,
  because an attacker can open many tickets instead of retrying one.
- **Treating SMS as second-class.** NIST classifies PSTN delivery as a
  restricted authenticator. The system prefers push, consults a
  (simulated) carrier feed for SIM swaps and number ports, and refuses a
  flagged number rather than sending to it.
- **Closing the enrollment loophole.** Keeping channel changes out of the
  ticket flow just moves the social engineering to the enrollment desk. New
  channels trigger a notice to the existing ones (NIST SP 800-63B-4
  §4.1.2.1) and wait out a cooling-off period before they can be used.
- **Turning a denial into intelligence.** "I did not request this" is
  recorded separately from a mismatched code and flagged to supervisors,
  because it means an impersonation attempt is happening right now.

## Built for adoption, not just compliance

The brief's two adoption drivers shaped the UI:

- **Speed.** The target is under 30 seconds end to end. Supervisors get a
  metrics page with median and 90th-percentile time to verify and the share
  under target.
- **Agent self-protection.** Each ticket has a printable verification
  receipt with every audit record's hash and a live integrity check. If a
  reset is later found to be fraudulent, the agent can show exactly what
  the process required and what happened. An auditor can re-verify an
  exported CSV with a short standard-library script that doesn't import
  the application.

## Security engineering on the app itself

Role-based access enforced server-side on every route, Argon2 password
hashing, login lockout, one-hour admin sessions, a strict content security
policy, Origin-header CSRF checks, and formula-injection-safe CSV export.

One bug is worth telling. My first CSRF check combined a
`Referrer-Policy: no-referrer` header with rejecting `Origin: null`.
Under the Fetch standard, that policy makes browsers send `Origin: null`
on every POST, so the app would have rejected its own login form. Unit tests
missed it because the test client sends no Origin header. I caught it while
checking my approach against the OWASP cheat sheet, then confirmed the fix
by submitting the real form in headless Chrome.

## Engineering practice

- Python, FastAPI, Jinja2 and htmx, SQLite, Docker Compose, `uv`-pinned
  dependencies.
- 187 automated tests, written rule-first: state machine, timeouts, closure
  blocking, audit integrity, role permissions, then UI.
- Each decision has a short decision record in `docs/decisions/`, and every
  security claim cites a primary source or is marked UNVERIFIED.
- Ticketing, notification, and anchoring all sit behind interfaces with
  mock implementations, so nothing is tied to a vendor.

## Honest limitations

This is a working prototype, not a product. The adapters are mocks, the
anchor store is a local file, rate limits live in memory, and the holder's
"device" is a web page. `docs/architecture.md` lists each limitation and
what a production deployment would use instead.

## Where to look

- `README.md`: how to run it and a five-minute demo script
- `docs/threat-model.md`: STRIDE analysis and NIST channel evaluation
- `docs/architecture.md`: layers, data model, sequence diagram
- `docs/decisions/`: one page per design decision
