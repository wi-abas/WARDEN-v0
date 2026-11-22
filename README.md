# Warden

[![CI](https://github.com/wi-abas/agent-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/wi-abas/agent-warden/actions/workflows/ci.yml)

A deterministic, local-first policy layer for AI agent tool calls.

Before an agent runs a tool, it asks Warden. Warden checks a rulebook and answers:

- `allow`: run the tool
- `deny`: don't
- `require_approval`: a human must approve first

Warden never runs tools itself and never uses an LLM to decide.

> **Status: early MVP. Not production-secure.** It is meant to run on your own machine
> only. See [Known limitations](#known-limitations).

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

Three ways, from least to most work on your side.

### 1. MCP servers: `warden proxy`

Put Warden between your MCP client (Claude Desktop, Cursor, Claude Code) and any stdio
MCP server. Every `tools/call` is checked; denied calls never reach the server.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agent-warden", "warden", "proxy",
               "--tool-prefix", "fs.", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/workspace"]
    }
  }
}
```

Setup, config file and approvals: [docs/mcp-proxy.md](https://github.com/wi-abas/agent-warden/blob/main/docs/mcp-proxy.md).

### 2. Python tools: `@guard`

```python
from warden.sdk import NotAllowed, WardenClient, guard

warden = WardenClient(agent_id="billing-agent")  # or token=... with agent tokens


@guard(client=warden, wait_for_approval=120)
def send_invoice(to: str, amount: int) -> str: ...


try:
    send_invoice(to="acme", amount=200)  # runs only on allow
except NotAllowed as blocked:
    print("Not allowed:", blocked)
```

The arguments are frozen before the check and the function receives exactly what Warden
checked, so changing them afterwards has no effect. Warden down means not allowed.
`require_approval` raises `ApprovalPending` (or waits, with `wait_for_approval`).

### 3. Anything else: plain HTTP

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
(That page loads its scripts and styles from cdn.jsdelivr.net, so your browser contacts a
third party. Warden itself never makes outside connections.)

Settings (`--policy`, `--port`, the admin key, ...): see [docs/api.md](https://github.com/wi-abas/agent-warden/blob/main/docs/api.md#settings).

## Speed

About **1.1 ms per tool call** over HTTP on an Apple M1, including the hash-chained
audit-log write (p99 under 2 ms). The decision itself takes about 10 microseconds.
Through the MCP proxy, a `tools/call` takes about **1.3 ms more** than calling the server
directly. Measure on your machine: `uv run python scripts/benchmark.py`.

## Documentation

- [Writing policies](https://github.com/wi-abas/agent-warden/blob/main/docs/policies.md): rules, argument conditions (incl. nested), tool argument lists, rate limits, `warden check`
- [API and operations](https://github.com/wi-abas/agent-warden/blob/main/docs/api.md): endpoints, agent tokens, approvals, audit log, settings
- [MCP proxy](https://github.com/wi-abas/agent-warden/blob/main/docs/mcp-proxy.md): `warden proxy` for Claude Desktop, Cursor, Claude Code
- [Design notes](https://github.com/wi-abas/agent-warden/tree/main/docs/design): how each feature works and what it doesn't cover
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
  The log is a hash chain: `warden audit verify` finds the first edited or deleted row.
- Approvals are single-use, expire, are bound to the exact action and the agent that
  asked, and can't be replayed (also across restarts), modified, double-decided, used by
  two requests at once, or approved without seeing the arguments.
- Every result carries an `action_hash`: a SHA-256 fingerprint of the exact action
  (agent, tool, arguments). Approvals are bound to it.
- Optional agent tokens: the agent id comes from a secret, not from the request.
- Per-agent rate limits and caps on pending approvals.
- The SDK and the MCP proxy run a tool with exactly the arguments that were checked.

## Known limitations

- **Agent tokens are optional.** Without `--agents`, any process on this machine can call
  `/v1/evaluate` with any `agent_id` (and dodge per-agent limits by inventing new ones).
- **Warden is a checkpoint, not a sandbox.** An agent can skip asking. The MCP proxy and
  the SDK enforce the answer only for calls that go through them.
- **Nested conditions don't search lists**, and argument lists only cover top-level names.
- **Text checks see text.** Paths and emails are checked for common tricks (`//`, `/./`,
  `/../`, backslashes; spaces, display names, recipient lists, trailing dots), but Warden
  doesn't resolve symlinks or URL-decode. Prefer "allow only..." rules for paths and emails.
- **Without a tool argument list, arguments no rule mentions aren't checked.** Add a
  `tools` entry for every tool with "deny when..." rules.
- **The admin key is one shared secret, not real user accounts.** Any program that can
  read your terminal output can approve. There's no record of *who* approved.
- **After a restart, pending approvals can't be approved until the agent asks again**
  (arguments are never written to disk, so the human couldn't see them).
- **The audit log is tamper-evident, not tamper-proof.** Someone who can edit the file
  can rewrite the whole chain; keep a copy of the hashes `warden audit verify` prints.
- **Import name clash.** The package installs as `agent-warden` but is imported as `warden`,
  the same import name as the unrelated `warden` package on PyPI. Don't install both in one
  environment.
- **The policy file is trusted.** Whoever can edit it controls every decision.

## Development

```sh
uv run pytest --cov            # tests + coverage (CI requires 98%+)
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
| `src/warden/approvals.py` | Human approvals (persisted state, no arguments on disk) |
| `src/warden/agents.py` | Agent tokens |
| `src/warden/limits.py` | Per-agent rate limits and approval quotas |
| `src/warden/api.py` | HTTP API |
| `src/warden/client.py` | Small HTTP client used by the SDK and the proxy |
| `src/warden/sdk.py` | Python SDK (`@guard`) |
| `src/warden/mcp_proxy.py` | MCP proxy (`warden proxy`) |
| `src/warden/cli.py` | The `warden` command (`serve`, `check`, `init`, `schema`, `agent`, `audit`, `proxy`) |
| `src/warden/check.py` | Policy checks and warnings |
| `src/warden/settings.py` | Server settings (flags and environment variables) |
| `examples/demo.py` | The 30-second demo (also run as a test) |
| `examples/agent.py` | An agent loop guarded by Warden (also run as a test) |

## Roadmap

Done in v0.2.0: argument rules, tool argument lists, audit log with retention, human
approvals, `warden check`, settings, demo, CI. See [CHANGELOG.md](https://github.com/wi-abas/agent-warden/blob/main/CHANGELOG.md).

Unreleased: MCP proxy, Python SDK, agent tokens, rate limits, persistent approvals,
tamper-evident audit log, nested argument conditions.

Next, shaped by feedback from early users:

1. Argument types in tool argument lists
2. Approvals from Slack, per-person accounts
3. HTTP transport for the MCP proxy

**Trying Warden? Please open an issue with what worked and what didn't.**

## Security and contributing

See [SECURITY.md](https://github.com/wi-abas/agent-warden/blob/main/SECURITY.md) for the threat model (what Warden does and doesn't protect
against) and how to report a vulnerability, and [CONTRIBUTING.md](https://github.com/wi-abas/agent-warden/blob/main/CONTRIBUTING.md) to help.

## License

[MIT](https://github.com/wi-abas/agent-warden/blob/main/LICENSE)
