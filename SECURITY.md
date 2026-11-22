# Security

Warden is an **early MVP and is not production-secure.** Please read the threat model
below before relying on it.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's private
reporting instead: the repository's **Security** tab → **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it.
You'll get a reply as soon as possible. This is a small open-source project, so there is
no bug bounty.

## Supported versions

Only the latest release gets security fixes.

## Threat model

### What Warden is

A **checkpoint** that an agent runtime asks before running a tool. It answers `allow`,
`deny` or `require_approval`, deterministically, from a policy file. It never runs tools
and never uses an LLM to decide.

### What Warden protects against

Assuming the agent runtime calls Warden and obeys the answer:

- **An agent attempting an action the policy forbids**, including through tricks Warden
  checks for: wrong argument types, `..` in paths, upper/lower case in email addresses,
  missing arguments on deny rules, unexpected arguments (with a tool argument list).
- **Unapproved high-risk actions**: `require_approval` actions only run after a human
  approves that exact action.
- **Approval abuse**: replaying an approval, changing the action after approval, using an
  expired approval, deciding twice, or racing two requests on one approval.
- **Secret leaks through Warden itself**: tool arguments are never logged or written to
  disk, and error responses never echo input.
- **Silent failure**: any error, broken policy, or failed audit write results in `deny`.

### What Warden does NOT protect against

- **An agent that skips Warden.** Warden can't stop a tool call it's never asked about.
  Enforcement depends on the runtime calling Warden and running the tool only on `allow`.
- **Other programs on the same machine.** There's no authentication for `/v1/evaluate`,
  and `agent_id` is self-declared. Anything that can reach `127.0.0.1` can ask.
- **Whoever can edit the policy file.** It's trusted configuration and controls every
  decision.
- **Whoever has the admin key** (or can read the terminal it's printed in, or the
  environment of the Warden process: any program running as the same OS user usually can). It's one shared
  secret, so there's no record of *which* person approved.
- **Whoever can edit the audit database.** It's a plain SQLite file, not tamper-evident.
- **Things the rules don't express.** Text checks see text, not meaning:
  `endswith "@mycompany.com"` can't tell two recipients in one string apart, and
  conditions only look at top-level arguments.
- **Denial of service.** Request size is limited and recording of rejected requests is
  capped at 60 per minute (the rest are counted in one summary line), but requests
  themselves aren't rate limited: any local program can fill the approval queue (1,000
  pending) or keep Warden busy.

### Trust boundaries

| Component | Trusted? |
|---|---|
| Agent and its requests | **No**: all input is validated and treated as hostile |
| Agent runtime (calls Warden, obeys answer) | Yes, must be |
| Policy file | Yes |
| Admin key holder (approver) | Yes |
| Local machine and its users | Yes |
| Audit database file | Yes (not tamper-evident) |
