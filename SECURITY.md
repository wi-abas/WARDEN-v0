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
  expired approval, deciding twice, or racing two requests on one approval, also across
  several servers sharing one database. A newer rejection always beats restoring a use.
- **Secret leaks through Warden itself**: tool arguments are never logged or written to
  disk, and error responses never echo input.
- **Silent failure**: any error, broken policy, or failed audit write results in `deny`.
- **Misleading the approver**: hidden and look-alike characters in arguments are shown
  escaped in the approval list; two argument names never display the same.
- **Parser tricks**: request bodies that repeat a JSON key are refused, so Warden and the
  tool can't read different values.
- **A writable policy**: `warden serve` refuses a policy or agents file that its group or
  other users can write, that another non-root user owns, or that is reached through a
  folder or symlink they could replace. ACLs aren't checked, and only startup is.
- **Agent impersonation** (with `--agents`): the agent id comes from a token; only token
  hashes are stored (plus a secret key per agent with which Warden proves itself, so keep
  the agents file private); lookups are constant-time; one agent can't use another's approval.
- **Flooding by one agent**: per-agent rate limits and pending-approval caps. Identity
  handshakes (`/v1/hello`) count against an agent's (or the admin's) budget only when the
  caller proves it holds the key, so a program that saw a key id can't lock its owner out.
- **Arguments read back from a database copy**: stored `action_hash` values are keyed
  (HMAC-SHA256) with a secret in its own file (`<audit-db>.hash-key`, mode 600), so a
  backup of the database alone can't be checked against guessed amounts or recipients.
  Back up the database without that file, or keep both equally private.
- **Silent history edits**: the audit log is a hash chain; `warden audit verify` reports
  the first edited, deleted or inserted row.
- **Checked ≠ executed**: the SDK and the MCP proxy run a tool with exactly the object
  that was checked; the proxy refuses duplicate JSON keys, batches, unknown methods,
  unexpected top-level keys, request ids still in use,
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
- **Other programs on the same machine.** With `--no-auth` (tokens are required otherwise),
  `agent_id` is
  self-declared and anything that can reach `127.0.0.1` can ask as any agent (and dodge
  per-agent rate limits with new ids). With tokens, a program that can read an agent's
  environment or memory has its token.
- **An impostor on Warden's port, without agent tokens.** If Warden isn't running, another
  local program can listen on its port. **With an agent token** (SDK, MCP proxy) or the
  admin key (`warden approvals`), the client demands proof first: the impostor gets no
  secret and no argument, and the answer is deny. Not covered: everything **without
  `--agents`** (no shared secret: the impostor receives the arguments, and its `allow` makes
  the **tool run**); clients that don't check (curl, plain HTTP, the `/docs` page); whoever
  can read the agents file (its `server_key`s imitate Warden to the agents; keep it mode
  600), the token, the admin key or a process's memory, often any program of the same OS
  user; and whoever can sniff or change loopback traffic (nothing is encrypted). An impostor
  can still make everything be denied.
  [docs/design/server-identity.md](docs/design/server-identity.md).
- **One agent using another agent's permissions.** Per-agent rules (`"agents": [...]`)
  give agents different permissions, and require agent tokens: `warden serve` refuses to
  start with a per-agent rule and no `--agents`, or with an agent name that isn't in the
  agents file. Remaining: a stolen token is that agent, with all its per-agent
  permissions; there are no groups or roles, so long lists repeat.
- **Whoever can edit the policy file.** It's trusted configuration and controls every
  decision.
- **Whoever has the admin key** (or can read the terminal it's printed in, or the
  environment of the Warden process: any program running as the same OS user usually can). It's one shared
  secret, so there's no record of *which* person approved. `warden approvals` only sends it
  to a server that has proven to be Warden; curl sends it to whatever listens. An impostor
  does see a hash derived from the key, so a guessable key you chose yourself (32+
  characters, but words or a pattern) could be guessed offline: use a random one.
- **Whoever can edit the audit database.** The hash chain shows edits, but someone who
  rewrites every later hash too (or cuts off the newest rows) is only caught by comparing
  with checkpoints kept elsewhere (`warden audit head`, `warden audit verify --expect`). They can also change approval state
  stored in the same file. A trigger can't make Warden allow without a record, but one
  added and removed again leaves no trace.
- **Text read differently by the tool.** Email rules refuse MIME encoded-words
  (`=?utf-8?q?...?=@x.com`) and local parts starting with `-` or `|`, but don't know
  every mail program's quirks (quoted local parts are refused, comments too). URL rules refuse
  known disguised dot segments but don't decode URLs. A compared text that is a path with
  `.`, `..` or empty segments (`./.env`, `a/../.env`, `a//b`) is refused, but paths aren't
  resolved: denying exactly `.env` doesn't stop `config/.env` (use `endswith "/.env"` too).
- **Floods without a valid token.** Invalid requests count toward a budget only with a valid
  agent token; others, and 411/413 refusals, are not rate limited.
- **URL paths in logs.** They are kept in the audit and access logs (query strings are not).
- **Re-asking with a slightly different action.** A sticky rejection covers the exact
  action only: one changed character in the arguments (or, without agent tokens, a new
  `agent_id`) is a new approval. Rate limits and pending quotas bound how often.
- **Several servers on one database**: pending quotas can be overshot by a few, and rate
  limits are per server.
- **A cancelled async call** can use up its approval if cancelled while a question is on
  its way to Warden (the tool doesn't run).
- **A call that already left the proxy.** It sits in the operating system's pipe, and the
  MCP server can still read and run it after the client disconnected.
- **A disconnected client's approval** stays valid until it expires, for the same agent
  and action.
- **Argument names that differ only in case**, if the tool ignores case: use tool
  argument lists.
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
  127.0.0.1): use allow lists. `contains` is a tripwire, not a sandbox: `rm -fr` doesn't
  contain `"rm -rf"` (so it's refused in allow rules). `host_in` checks names, not where
  DNS sends them (non-http(s) schemes and odd ports are denied). Look-alike letters from other scripts (Cyrillic `а` in
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
| Agents file (token hashes, secret server keys) | Yes |
| Agent runtime (calls Warden, obeys answer) | Yes, must be |
| Policy file | Yes |
| Admin key holder (approver) | Yes |
| Local machine and its users | Yes |
| Audit database file | Yes (tamper-evident, not tamper-proof; also holds approval state) |
| Hash key file (`<audit-db>.hash-key`) | Yes (with the database, it lets someone guess arguments from stored hashes) |

Latest audit: [docs/security-audit-2026-11-22-build-session.md](docs/security-audit-2026-11-22-build-session.md).
