# Warden

[![CI](https://github.com/wi-abas/agent-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/wi-abas/agent-warden/actions/workflows/ci.yml)

A deterministic, local-first policy layer for AI agent tool calls.

Before an agent runs a tool, it asks Warden. Warden checks a rulebook and answers:

- `allow`: run the tool
- `deny`: don't
- `require_approval`: a human must approve first

Warden never runs tools itself and never uses an LLM to decide.

> **Status: early MVP. Not production-secure.** It has no authentication and is meant
> to run on your own machine only. See [Known limitations](#known-limitations).

## See it in 30 seconds

```sh
uv sync
uv run python examples/demo.py
```

A pretend agent reads files, tries a path trick, emails colleagues (and tries a sneaky
`bcc`), sends invoices, gets one approved by a human, then tries to change the amount after
approval and to replay it. Warden's answer to each is shown and checked. The policy it uses
is [`examples/demo-policy.json`](examples/demo-policy.json).

## Use it from your agent

Ask Warden before every tool call, and run the tool **only** on `allow`. Standard library
only:

```python
import json, urllib.request


def ask_warden(tool: str, arguments: dict) -> dict:
    body = json.dumps({"agent_id": "my-agent", "tool": tool, "arguments": arguments})
    request = urllib.request.Request(
        "http://127.0.0.1:8000/v1/evaluate", body.encode(), {"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    except Exception:
        return {"decision": "deny", "reason": "Warden unreachable"}  # fail closed


answer = ask_warden("send_email", {"to": "bob@mycompany.com", "subject": "Hi"})
if answer["decision"] == "allow":
    send_email(to="bob@mycompany.com", subject="Hi")
else:
    print("Not allowed:", answer["reason"])  # deny, require_approval, or an error
```

[`examples/agent.py`](examples/agent.py) is a complete version: a small agent loop that
also waits for human approval (polling with the `approval_id`) and gives up after a timeout.

## Quick start

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run warden init      # creates policies/default.json (skip in this repo: it exists)
uv run warden check     # validates it
uv run warden           # starts the server
```

The server listens on `http://127.0.0.1:8000` (this machine only). Open
**http://127.0.0.1:8000/docs** for an interactive page where you can send requests.

### Settings

```sh
WARDEN_ADMIN_KEY="$(openssl rand -base64 32)" \
  uv run warden serve --policy my-rules.json --port 9000 --audit-db logs/audit.db --retention-days 365
```

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| Policy file | `--policy` | `WARDEN_POLICY` | `policies/default.json` |
| Port | `--port` | `WARDEN_PORT` | `8000` |
| Audit database | `--audit-db` | `WARDEN_AUDIT_DB` | `warden-audit.db` |
| Audit retention | `--retention-days` (`0` = forever) | `WARDEN_RETENTION_DAYS` | `90` |
| Admin key | *(no flag)* | `WARDEN_ADMIN_KEY` (32+ characters) | random, printed at startup |

Flags beat environment variables. The admin key has no flag on purpose: command lines are
visible to other programs (`ps`). An invalid setting stops Warden with a clear message
instead of falling back to a default. The host is always `127.0.0.1`.

## Example

```sh
curl -s -X POST http://127.0.0.1:8000/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{"agent_id": "agent-1", "tool": "write_file", "arguments": {"path": "/workspace/a.txt", "content": "hi"}}'
```

```json
{
  "decision": "require_approval",
  "reason": "Writing files needs a human to approve",
  "matched_rule": "write-workspace",
  "action_hash": "…64 hex characters…",
  "approval_id": "…32 characters…"
}
```

| Endpoint | Purpose |
|---|---|
| `GET /health` | `{"status": "ok", "rules_loaded": 4}`, or HTTP 503 `"degraded"` when no rules loaded (broken or empty policy file: everything is denied). |
| `POST /v1/evaluate` | Send an action, get a decision. |
| `GET /v1/approvals` | Admin: list pending approvals, with their arguments. |
| `POST /v1/approvals/{id}/approve` | Admin: approve one (once). |
| `POST /v1/approvals/{id}/deny` | Admin: deny one (once). |

## Approvals

1. The agent asks. A rule says `require_approval`, and the response includes an `approval_id`.
2. You look at what's waiting and approve it. Admin calls need the key Warden prints in
   the terminal at startup (a new one every start):
   ```sh
   curl -s http://127.0.0.1:8000/v1/approvals -H 'X-Warden-Admin-Key: <key>'
   curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/approve -H 'X-Warden-Admin-Key: <key>'
   ```
3. The agent sends the **exact same action** again, plus `"approval_id": "<approval_id>"`.
   While the human hasn't decided, the answer stays `require_approval` ("waiting for a human
   to approve"), so the agent can poll. Once approved it gets `allow`, once. A human "no"
   gives `deny` ("denied by a human").

An approval works **once**, only for the **exact action** that was approved (same agent,
tool and arguments, checked via `action_hash`), and **expires after 15 minutes**. It can
never turn a `deny` into `allow`. Each approval can be decided only once. Approvals are kept
in memory only (arguments never touch disk), so restarting Warden clears them.

## Writing a policy

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

### Tool argument lists

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

## Audit log

Every decision is saved to `warden-audit.db` (SQLite, in the folder you start Warden from):
time, agent, tool, decision, reason, matched rule and `action_hash`.
**Tool arguments are never stored.** If the log can't be written, Warden answers
`deny` (HTTP 503), so nothing is allowed without a record.

A second table, `events`, records everything else: a human approving or denying (if that
record can't be written, the approval doesn't happen), failed approve/deny attempts, and
rejected requests (wrong admin key, bad input, oversized body, errors), with method and URL
path but never the body or query string. Failed approval retries keep the `approval_id`
that was tried, so misuse is visible.

**Retention:** entries older than 90 days are deleted at startup and then once a day.
Each deletion is itself recorded as an `audit_purged` event ("deleted 120 decisions and
4 events older than 90 days"), so gaps in the history are explained. Retention can be
turned off with `--retention-days 0`.

```sh
sqlite3 warden-audit.db "SELECT timestamp, tool, decision FROM decisions ORDER BY id DESC LIMIT 10"
sqlite3 warden-audit.db "SELECT timestamp, kind, http_status, reason FROM events ORDER BY id DESC LIMIT 10"
```

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
- Approvals are single-use, expire, are bound to the exact action, and can't be
  replayed, modified, double-decided, or used by two requests at once.
- Every result carries an `action_hash`: a SHA-256 fingerprint of the exact action
  (agent, tool, arguments). Future approvals will be bound to it, so a changed action
  can't reuse an approval.

## Known limitations

- **No authentication for agents.** Any process on this machine can call `/v1/evaluate`.
- **`agent_id` is self-declared** and is not used for decisions.
- **Warden is a checkpoint, not a sandbox.** An agent can skip asking. Enforcement depends
  on the agent runtime calling Warden and obeying the answer.
- **Conditions check top-level arguments only**, not nested values.
- **Text checks see text, not parsed values.** `endswith "@mycompany.com"` also matches
  `"evil@x.com, bob@mycompany.com"`. If a tool accepts several recipients in one string,
  the rule can't tell them apart.
- **Without a tool argument list, arguments no rule mentions aren't checked.** Add a
  `tools` entry for every tool with "deny when..." rules.
- **The admin key is one shared secret, not real user accounts.** Any program that can
  read your terminal output can approve. There's no record of *who* approved.
- **Approvals are lost on restart** (in memory only).
- **The audit log is a plain local file.** Anyone who can edit it can change history.
  Old entries are deleted after 90 days, but a flood of requests within that window
  can still grow it.
- **The policy file is trusted.** Whoever can edit it controls every decision.

## Development

```sh
uv run pytest                  # tests
uv run ruff check .            # lint (includes security checks)
uv run ruff format .           # format
uv run mypy                    # type check (strict)
```

| File | Purpose |
|---|---|
| `src/warden/models.py` | Data shapes: requests, rules, results |
| `src/warden/engine.py` | The decision logic |
| `src/warden/policy.py` | Loads and validates the policy file |
| `src/warden/fingerprint.py` | Action fingerprints |
| `src/warden/audit.py` | Audit log (SQLite) |
| `src/warden/approvals.py` | Human approvals |
| `src/warden/api.py` | HTTP API |
| `src/warden/cli.py` | The `warden` command (`serve`, `check`) |
| `src/warden/check.py` | Policy checks and warnings |
| `src/warden/settings.py` | Server settings (flags and environment variables) |
| `examples/demo.py` | The 30-second demo (also run as a test) |
| `examples/agent.py` | An agent loop guarded by Warden (also run as a test) |

## Roadmap

Done in v0.2.0: argument rules, tool argument lists, audit log with retention, human
approvals, `warden check`, settings, demo, CI. See [CHANGELOG.md](CHANGELOG.md).

Next, shaped by feedback from early users:

1. Python SDK (`@warden.guard`) and an MCP proxy, so existing agents can use Warden in minutes
2. Argument types in tool argument lists
3. Agent authentication and persistent approvals
4. Approvals from Slack, per-person accounts, tamper-evident audit log

**Trying Warden? Please open an issue with what worked and what didn't.**

## Security and contributing

See [SECURITY.md](SECURITY.md) for the threat model (what Warden does and doesn't protect
against) and how to report a vulnerability, and [CONTRIBUTING.md](CONTRIBUTING.md) to help.

## License

[MIT](LICENSE)
