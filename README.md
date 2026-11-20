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
- Tool arguments are never logged, and error responses never echo the input.
- Every result carries an `action_hash`: a SHA-256 fingerprint of the exact action
  (agent, tool, arguments). Future approvals will be bound to it, so a changed action
  can't reuse an approval.

## Known limitations

- **No authentication.** Any process on this machine can call the API.
- **`agent_id` is self-declared** and is not used for decisions.
- **Warden is a checkpoint, not a sandbox.** An agent can skip asking. Enforcement depends
  on the agent runtime calling Warden and obeying the answer.
- **Rules match tool names only.** Arguments are not inspected yet.
- **`require_approval` cannot be granted yet.** Treat it as "not allowed" for now.
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
| `src/warden/api.py` | HTTP API |

## Roadmap

1. Argument rules (for example "invoices over €500 need approval")
2. SQLite audit log of every decision
3. Approval workflow bound to `action_hash`, single-use and expiring
4. Authentication, Python SDK, MCP integration
