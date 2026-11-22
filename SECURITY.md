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

The full version, with every defence linked to its tests: [docs/threat-model.md](docs/threat-model.md).

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
- **Misleading the approver**: hidden and look-alike characters in arguments are shown
  escaped in the approval list.
- **Parser tricks**: request bodies that repeat a JSON key are refused, so Warden and the
  tool can't read different values.
- **A writable policy**: `warden serve` refuses a policy file other users could change
  (same for the agents file).
- **Agent impersonation** (with `--agents`): the agent id comes from a token; only hashes
  are stored; lookups are constant-time; one agent can't use another's approval.
- **Flooding by one agent**: per-agent rate limits and pending-approval caps.
- **Silent history edits**: the audit log is a hash chain; `warden audit verify` reports
  the first edited, deleted or inserted row.
- **Checked ≠ executed**: the SDK and the MCP proxy run a tool with exactly the object
  that was checked; the proxy refuses duplicate JSON keys, batches and unknown methods.
- **Approval loss or replay across restarts**: approval state is persisted (without
  arguments) and `used` is saved before an allow is returned. After a restart nothing
  can be approved until the human can see its arguments again.

### What Warden does NOT protect against

- **An agent that skips Warden.** Warden can't stop a tool call it's never asked about.
  The MCP proxy and the SDK only cover calls routed through them; a client configured
  to talk to the MCP server directly, or code calling the undecorated function, bypasses
  them.
- **Other programs on the same machine.** Without `--agents`, `agent_id` is
  self-declared and anything that can reach `127.0.0.1` can ask as any agent (and dodge
  per-agent rate limits with new ids). With tokens, a program that can read an agent's
  environment or memory has its token.
- **Whoever can edit the policy file.** It's trusted configuration and controls every
  decision.
- **Whoever has the admin key** (or can read the terminal it's printed in, or the
  environment of the Warden process: any program running as the same OS user usually can). It's one shared
  secret, so there's no record of *which* person approved.
- **Whoever can edit the audit database.** The hash chain shows edits, but someone who
  rewrites every later hash too (or cuts off the newest rows) is only caught by comparing
  with checkpoints kept elsewhere (`warden audit head`, `warden audit verify --expect`). They can also change approval state
  stored in the same file.
- **Things the rules don't express.** Text checks see text, not meaning:
  `endswith "@mycompany.com"` can't tell two recipients in one string apart; nested
  conditions don't search lists, and argument lists only cover top-level names.
- **Denial of service.** Request size, per-agent request rates, per-agent pending
  approvals and the recording of rejected requests are capped, but without agent tokens
  new agent ids get new budgets (up to 10,000 tracked agents), and nothing protects
  against a flood at the network level.
- **What MCP servers do on their own**, and server-to-client MCP requests (sampling,
  elicitation, roots), which the proxy forwards unchecked.

### Trust boundaries

| Component | Trusted? |
|---|---|
| Agent and its requests | **No**: all input is validated and treated as hostile |
| MCP client and MCP server behind the proxy | Yes (the proxy checks what the model asks for) |
| Agents file (token hashes) | Yes |
| Agent runtime (calls Warden, obeys answer) | Yes, must be |
| Policy file | Yes |
| Admin key holder (approver) | Yes |
| Local machine and its users | Yes |
| Audit database file | Yes (tamper-evident, not tamper-proof; also holds approval state) |

Latest audit: [docs/security-audit-2026-11-22-build-session.md](docs/security-audit-2026-11-22-build-session.md).
