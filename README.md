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

<img src="https://raw.githubusercontent.com/wi-abas/agent-warden/main/docs/demo.svg" alt="Demo output: allow, deny and require_approval decisions, a blocked path trick, a blocked bcc, a human approval, and a rejected modified-after-approval attempt" width="700">

A pretend agent reads files, tries a path trick, emails colleagues (and tries a sneaky
`bcc`), sends invoices, gets one approved by a human, then tries to change the amount after
approval and to replay it. Warden's answer to each is shown and checked. The policy it uses
is [`examples/demo-policy.json`](https://github.com/wi-abas/agent-warden/blob/main/examples/demo-policy.json).

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

[`examples/agent.py`](https://github.com/wi-abas/agent-warden/blob/main/examples/agent.py) is a complete version: a small agent loop that
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

Settings (`--policy`, `--port`, the admin key, ...): see [docs/api.md](https://github.com/wi-abas/agent-warden/blob/main/docs/api.md#settings).

## Speed

About **1 ms per tool call** over HTTP on an Apple M1, including the audit-log write
(p99 under 2 ms). The decision itself takes about 5 microseconds. Measure on your machine:
`uv run python scripts/benchmark.py`.

## Documentation

- [Writing policies](https://github.com/wi-abas/agent-warden/blob/main/docs/policies.md): rules, argument conditions, tool argument lists, `warden check`
- [API and operations](https://github.com/wi-abas/agent-warden/blob/main/docs/api.md): endpoints, approvals, audit log, settings
- [Security](https://github.com/wi-abas/agent-warden/blob/main/SECURITY.md): threat model, what Warden does and doesn't protect against

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
uv run mypy                    # type check (strict, incl. tests)
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
approvals, `warden check`, settings, demo, CI. See [CHANGELOG.md](https://github.com/wi-abas/agent-warden/blob/main/CHANGELOG.md).

Next, shaped by feedback from early users:

1. Python SDK (`@warden.guard`) and an MCP proxy, so existing agents can use Warden in minutes
2. Argument types in tool argument lists
3. Agent authentication and persistent approvals
4. Approvals from Slack, per-person accounts, tamper-evident audit log

**Trying Warden? Please open an issue with what worked and what didn't.**

## Security and contributing

See [SECURITY.md](https://github.com/wi-abas/agent-warden/blob/main/SECURITY.md) for the threat model (what Warden does and doesn't protect
against) and how to report a vulnerability, and [CONTRIBUTING.md](https://github.com/wi-abas/agent-warden/blob/main/CONTRIBUTING.md) to help.

## License

[MIT](https://github.com/wi-abas/agent-warden/blob/main/LICENSE)
