# WARDEN-v0

A deterministic, local-first policy layer for AI agent tool calls.

Before an agent runs a tool, it asks Warden. Warden checks a rulebook and answers:

- `allow`: run the tool
- `deny`: don't
- `require_approval`: a human must approve first (the approval workflow is not built yet)

Warden never runs tools itself and never uses an LLM to decide.

> **Status: early MVP. Not production-secure.** It has no authentication and is meant
> to run on your own machine only. See [Known limitations](#known-limitations).

## Quick start

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run warden
```

The server listens on `http://127.0.0.1:8000` (this machine only).
Open **http://127.0.0.1:8000/docs** for an interactive page where you can send requests.

## Example

```sh
curl -s -X POST http://127.0.0.1:8000/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{"agent_id": "agent-1", "tool": "send_email", "arguments": {"to": "a@b.c"}}'
```

```json
{
  "decision": "require_approval",
  "reason": "matched rule 'approve-send'",
  "matched_rule": "approve-send",
  "action_hash": "…64 hex characters…"
}
```

| Endpoint | Purpose |
|---|---|
| `GET /health` | `{"status": "ok", "rules_loaded": 3}`. `rules_loaded: 0` means the policy file is broken. |
| `POST /v1/evaluate` | Send an action, get a decision. |

## Writing a policy

Rules live in `policies/default.json`:

```json
{
  "rules": [
    { "id": "allow-read",   "tool": "read_file",   "effect": "allow" },
    { "id": "approve-send", "tool": "send_email",  "effect": "require_approval" },
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

### Argument rules

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
| `startswith` | text starts with | non-empty text |

- A **missing** argument makes the condition false.
- An argument of the **wrong type** (e.g. `"50000"` as text for `gt`), or a value containing
  `..` for `startswith`, **denies the whole request**. This stops a `deny` rule being dodged.
- `true` is never treated as the number `1`.
- Conditions only look at top-level arguments. No regex, no code.

## Audit log

Every decision is saved to `warden-audit.db` (SQLite, in the folder you start Warden from):
time, agent, tool, decision, reason, matched rule and `action_hash`.
**Tool arguments are never stored.** If the log can't be written, Warden answers
`deny` (HTTP 503), so nothing is allowed without a record.

```sh
sqlite3 warden-audit.db "SELECT timestamp, tool, decision FROM decisions ORDER BY id DESC LIMIT 10"
```

## Rule for clients: fail closed

**Run the tool only if the response says `"decision": "allow"`.** Anything else means don't:
`deny`, `require_approval`, an error status, a timeout, or Warden being unreachable.
Every error response from Warden also carries `"decision": "deny"` to make this easy.

## Security properties

Each of these is covered by tests in `tests/`.

- Default deny, and the most restrictive rule wins.
- Any error inside Warden produces deny, never allow.
- Strict input validation: unknown fields, wrong types and odd tool names are rejected.
- Request bodies over 64 KB, or of undeclared size, are refused.
- Tool arguments are never logged or stored, and error responses never echo the input.
- Every decision is recorded in the audit log; if recording fails, the answer is deny.
- Every result carries an `action_hash`: a SHA-256 fingerprint of the exact action
  (agent, tool, arguments). Future approvals will be bound to it, so a changed action
  can't reuse an approval.

## Known limitations

- **No authentication.** Any process on this machine can call the API.
- **`agent_id` is self-declared** and is not used for decisions.
- **Warden is a checkpoint, not a sandbox.** An agent can skip asking. Enforcement depends
  on the agent runtime calling Warden and obeying the answer.
- **Conditions check top-level arguments only**, not nested values.
- **Deny-list rules are weaker than allow-lists.** A missing argument makes a condition
  false, so prefer "allow only when..." over "deny when...".
- **`require_approval` cannot be granted yet.** Treat it as "not allowed" for now.
- **The audit log is a plain local file.** Anyone who can edit it can change history.
  Invalid requests (HTTP 422) are not recorded.
- **The policy file is trusted.** Whoever can edit it controls every decision.

## Development

```sh
uv run pytest                  # tests
uv run ruff check .            # lint (includes security checks)
uv run ruff format .           # format
```

| File | Purpose |
|---|---|
| `src/warden/models.py` | Data shapes: requests, rules, results |
| `src/warden/engine.py` | The decision logic |
| `src/warden/policy.py` | Loads and validates the policy file |
| `src/warden/fingerprint.py` | Action fingerprints |
| `src/warden/audit.py` | Audit log (SQLite) |
| `src/warden/api.py` | HTTP API |

## Roadmap

1. ~~Argument rules~~ (done)
2. ~~SQLite audit log~~ (done)
3. Approval workflow bound to `action_hash`, single-use and expiring
4. Authentication, Python SDK, MCP integration

## License

[MIT](LICENSE)
