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
  "$schema": "https://raw.githubusercontent.com/wi-abas/agent-warden/main/policy.schema.json",
  "rules": [ ... ]
}
```

`warden init` adds it for you. `uv run warden schema` prints the schema.

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
- Conditions only look at top-level arguments. No regex, no code.

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

Exit code `1` on errors; with `--strict`, also on warnings (useful in CI).
