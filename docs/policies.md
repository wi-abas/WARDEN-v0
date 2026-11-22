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
- Tool names and rule ids: lowercase letters, digits, `_`, `.`, `-`, up to 64 characters.
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
  "when": [ { "arg": "amount", "op": "lte", "value": 500 } ] }
```

| `op` | Meaning | `value` |
|---|---|---|
| `eq`, `neq` | equals / doesn't equal | text, number or true/false |
| `gt`, `gte`, `lt`, `lte` | number comparison | number |
| `in` | is one of | list of 1–100 text/number values |
| `startswith`, `endswith` | text starts / ends with | non-empty text |
| `exists`, `missing` | argument is present / absent | *(no value)* |
| `host_in` | a URL's real host is one of these (any scheme, port or case; `".x.com"` = x.com and its subdomains) | list of lowercase host names |

- **Warden never gives a looser answer because an argument is missing.** On a `deny` or
  `require_approval` rule a missing argument counts as matching (the rule applies); on an
  `allow` rule it doesn't. So `deny send_email when recipient startswith "evil"` can't be
  dodged by leaving `recipient` out. Use `exists` / `missing` to say exactly what you mean.
- An argument of the **wrong type** (e.g. `"50000"` as text for `gt`), or a value containing
  `..` for `startswith`, **denies the whole request**. This stops a `deny` rule being dodged.
- `true` is never treated as the number `1`.
- Add `"ignore_case": true` to compare text without caring about upper/lower case
  (works with `eq`, `neq`, `in`, `startswith`, `endswith`). Use it for email domains:
  `{ "arg": "to", "op": "endswith", "value": "@mycompany.com", "ignore_case": true }`.
- **Blocking or allowing sites:** use `host_in`, not `startswith`. It compares the URL's
  real host, so `http://`, ports, upper case and trailing dots can't dodge it:
  `{ "arg": "url", "op": "host_in", "value": ["evil.net", ".evil.net"] }`. International host
  names must be written in punycode (`xn--strae-oqa.de`, not `straße.de`), both in the
  policy and in requests; the Unicode form is refused because different software
  converts it differently.
- Text a rule compares may not contain invisible characters or look-alike Unicode
  (full-width letters, look-alike dots), and paths may not contain `%`-escapes; such
  requests are denied.
- No regex, no code.

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
- Tools without an entry work as before. Names only for now, not types.

## Rate limits and approval quotas

Optional. Each agent gets a request budget and a cap on how many approvals it may have
waiting, so one agent can't flood Warden or crowd out the others:

```json
"limits": {
  "default": { "requests_per_minute": 600, "max_pending_approvals": 50 },
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
- Without agent tokens (`--agents`), an agent can dodge its limit by using a new
  `agent_id`. Limits reset when Warden restarts.

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
| W003 | A rule can never apply, because a stricter unconditional rule always wins |
| W004 | A rule duplicates another |
| W005 | A path prefix without a trailing `/` (`"/data"` also matches `"/database"`) |
| W006 | A tool has an argument list but no rules: it's always denied |
| W007 | A condition checks an argument that isn't in the tool's argument list (typo?) |
| W008 | An email address is compared case-sensitively (`x@EVIL.com` would slip past) |
| W009 | A deny rule compares a path or URL case-sensitively (`/ETC/passwd`, `HTTPS://EVIL.NET/` slip past) |
| W010 | An `allow` rule uses `neq` or `missing` ("allow everything except X"), a deny-list in disguise |
| W011 | A URL prefix has no `/` after the host (`"https://api.x.com"` also matches `"https://api.x.com.evil.net"`) |
| W012 | A deny rule blocks a URL by comparing text; use `host_in` instead |
| W013 | A deny rule checks a nested value (`["headers", "to"]`): other keys in that object aren't checked |

Exit code `1` on errors; with `--strict`, also on warnings (useful in CI).
