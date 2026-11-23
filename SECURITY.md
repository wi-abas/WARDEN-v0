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
  that was checked; the proxy refuses duplicate JSON keys, batches and unknown methods,
  and `_meta` keys other than `progressToken` (configurable).
- **Bulk-approval tricks** (group approvals): a group decision names every approval by
  id (no filters, so nothing that arrived later is swept in) together with the
  `action_hash` the human was shown, never mixes agents or
  tools, is all or nothing under one lock, and is audited before it takes effect. The
  CLI shows every action in full, escaped, before asking.
- **Approval fatigue** (sticky rejections): after a human rejects or revokes an
  approval, the same agent asking for the same action is denied for the rejection window
  (default 15 minutes) instead of getting a new pending approval. Lifting one early needs
  the admin key and is audited before it takes effect.
- **Approving an id without having seen it** (v0.4): approving, rejecting a pending
  approval, and group rejects need the `action_hash` from the list, so an id pasted from
  an agent's message can't be decided without listing it. Only revoking an approved,
  unused approval works without it (it can only make things stricter). The MCP proxy
  hint never prints the hash.
- **Stale approvals swept in**: the approvals list shows only pending, unexpired
  approvals, each with its age (`list --max-age` narrows it). `warden approvals approve`
  warns when the chosen ids span separate runs (asked more than 2 minutes apart) and,
  with `--yes`, refuses unless `--across-runs` is given.
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
- **One agent using another agent's permissions.** Per-agent rules (`"agents": [...]`)
  give agents different permissions, and require agent tokens: `warden serve` refuses to
  start with a per-agent rule and no `--agents`, or with an agent name that isn't in the
  agents file. Remaining: a stolen token is that agent, with all its per-agent
  permissions; there are no groups or roles, so long lists repeat.
- **Whoever can edit the policy file.** It's trusted configuration and controls every
  decision.
- **Whoever has the admin key** (or can read the terminal it's printed in, or the
  environment of the Warden process: any program running as the same OS user usually can). It's one shared
  secret, so there's no record of *which* person approved. `warden approvals` sends the
  key to whatever listens on the Warden URL, so only use it while Warden is running.
- **Whoever can edit the audit database.** The hash chain shows edits, but someone who
  rewrites every later hash too (or cuts off the newest rows) is only caught by comparing
  with checkpoints kept elsewhere (`warden audit head`, `warden audit verify --expect`). They can also change approval state
  stored in the same file.
- **Re-asking with a slightly different action.** A sticky rejection covers the exact
  action only: one changed character in the arguments (or, without agent tokens, a new
  `agent_id`) is a new approval. Rate limits and pending quotas bound how often.
- **A reviewer who doesn't read.** Group approvals make a careful review possible, not
  certain: similar-looking actions in one group must still be compared, and a script
  with the admin key (or `--yes`) can decide ids nobody looked at. A required
  `action_hash` proves the list was fetched, not that it was read. The "separate runs"
  check is a timing heuristic in the CLI only: one slow run can look like two, two quick
  runs like one, and the HTTP API doesn't apply it.
- **Things the rules don't express.** Text checks see text, not meaning:
  `endswith "@mycompany.com"` can't tell two recipients in one string apart; nested
  conditions don't search lists, and argument lists only cover top-level names. A deny
  list of IP addresses can be dodged with other spellings (`http://2130706433/` is
  127.0.0.1): use allow lists. Look-alike letters from other scripts (Cyrillic `а` in
  `pаypal.com`) aren't flagged in the approval list.
- **Denial of service.** Request size, per-agent request rates, per-agent pending
  approvals and the recording of rejected requests are capped, but without agent tokens
  new agent ids get new budgets (up to 10,000 tracked agents), and nothing protects
  against a flood at the network level.
- **What MCP servers do on their own**, including what they answer. Server-to-client
  requests (sampling, elicitation, roots) are refused by the proxy unless listed in
  `allow_server_requests`; listed ones pass unchecked.

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
