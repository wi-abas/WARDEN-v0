# MCP proxy (`warden proxy`)

Put Warden in front of any **stdio MCP server** without changing the server or the client.
Your MCP client (Claude Desktop, Cursor, Claude Code, ...) launches `warden proxy`; the
proxy launches the real server and checks every `tools/call` with Warden first.

| Warden says | What the client gets |
|---|---|
| `allow` | The call goes to the server, exactly as checked. |
| `deny` | A tool error, `Blocked by Warden: <reason>`. The server never sees the call. |
| `require_approval` | `wait` mode: the call is held until a human approves (then it runs) or says no / times out. `error` mode: a tool error saying approval is pending; retry the same call after approving. |
| Warden not running | A tool error (fail closed). |

## 1. Start Warden

```sh
export WARDEN_ADMIN_KEY="$(openssl rand -hex 32)"
uv run warden serve --policy my-policy.json
```

Rules see the tool names as `<tool_prefix><MCP tool name>`, e.g. `fs.read_file`, and the
call's `arguments` object as the arguments:

```json
{
  "rules": [
    { "id": "read-workspace", "tool": "fs.read_file", "effect": "allow",
      "when": [{ "arg": "path", "op": "startswith", "value": "/Users/me/workspace/" }] },
    { "id": "write-needs-ok", "tool": "fs.write_file", "effect": "require_approval",
      "when": [{ "arg": "path", "op": "startswith", "value": "/Users/me/workspace/" }] }
  ]
}
```

Everything else (including the server's other tools) is denied, as always.

## 2. Write a proxy config

[`examples/proxy-config.json`](../examples/proxy-config.json):

```json
{
  "warden_url": "http://127.0.0.1:8000",
  "agent_id": "claude-desktop",
  "tool_prefix": "fs.",
  "server": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/workspace"],
    "env": {}
  },
  "approval": { "mode": "wait", "timeout_seconds": 120, "poll_seconds": 2 },
  "allow_server_requests": ["roots/list"]
}
```

| Key | Meaning | Default |
|---|---|---|
| `server.command`, `server.args` | How to start the real MCP server | required |
| `server.env` | Extra environment variables for the server (never logged) | `{}` |
| `warden_url` | Warden on this machine (`127.0.0.1`, `localhost` or `::1` only) | `http://127.0.0.1:8000` |
| `agent_id` | The agent id Warden records | `mcp-proxy` |
| `tool_prefix` | Added in front of tool names sent to Warden, so two servers' `search` tools can have different rules | `""` |
| `approval.mode` | `wait` or `error` (see above) | `wait` |
| `approval.timeout_seconds`, `approval.poll_seconds` | How long to wait, how often to ask | `300`, `2` |
| `allow_methods` | Extra MCP methods to pass through unchecked, e.g. `["resources/read", "prompts/get"]` | `[]` |
| `allow_server_requests` | Requests the **server** may send the client, e.g. `["roots/list"]` (see below) | `[]` |
| `allow_meta_keys` | Keys a `tools/call` may carry in `_meta` | `["progressToken"]` |
| `warden_timeout_seconds` | Timeout for each question to Warden | `5` |

Unknown keys are an error, so a typo can't silently weaken the setup. Without a config
file, flags work too: `warden proxy --agent-id cursor --tool-prefix fs. -- npx -y
@modelcontextprotocol/server-filesystem /Users/me/workspace`.

## 3. Point your client at the proxy

**Claude Desktop** (`claude_desktop_config.json`; Cursor's `~/.cursor/mcp.json` has the
same shape). Use absolute paths: these apps start servers with a minimal `PATH`.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/me/.local/bin/uv",
      "args": [
        "run", "--directory", "/Users/me/agent-warden",
        "warden", "proxy", "--config", "/Users/me/agent-warden/examples/proxy-config.json"
      ]
    }
  }
}
```

**Claude Code:**

```sh
claude mcp add filesystem -- uv run --directory /Users/me/agent-warden \
  warden proxy --config /Users/me/agent-warden/examples/proxy-config.json
```

Remove the server's direct entry: the proxy only protects calls that go through it.

If Warden uses agent tokens (`--agents`), give the proxy its token through the
environment, never the config file: in Claude Desktop / Cursor add
`"env": {"WARDEN_AGENT_TOKEN": "wdn_..."}` next to `"args"`. The agent id then comes from
the token.

## Approving

When a call needs approval, the proxy writes the approve command to its stderr (Claude
Desktop keeps it in its MCP log). Or list what's waiting:

```sh
curl -s http://127.0.0.1:8000/v1/approvals -H "X-Warden-Admin-Key: $WARDEN_ADMIN_KEY"
curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/approve \
  -H "X-Warden-Admin-Key: $WARDEN_ADMIN_KEY"
```

MCP clients have their own time limit per tool call. If yours gives up before you can
approve, use `"mode": "error"`: the model is told approval is pending, and retrying the
same call after you approve goes through (once).

## What the proxy refuses

- Any MCP method other than `tools/call` (checked) and the protocol basics
  (`initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`,
  `prompts/list`, `logging/setLevel`, and `notifications/*`), unless listed in
  `allow_methods`. `tools/call` itself can't be listed.
- Messages that repeat a JSON key, JSON-RPC batches, `NaN`/`Infinity`, invalid JSON.
  These could make the proxy and the server read different things.
- A `tools/call` sent as a notification (no `id`): dropped.
- A `tools/call` whose `_meta` holds anything but keys from `allow_meta_keys` (default
  only `progressToken`), each with short printable text (1-256 characters) or a whole
  number: the whole call is refused (`-32602`), nothing is stripped. A server that reads
  flags from `_meta` would otherwise act on something Warden never checked.

Allowed calls are re-encoded from the exact object Warden checked, never passed on as
raw bytes.

## Requests from the server

An MCP server can send the client requests of its own: `sampling/createMessage` (run an
LLM call), `roots/list` (which folders the user shared), `elicitation/create` (ask the
user something). By default the proxy refuses all of them: it answers the server with
an error and the client never sees the request. A server `ping` is answered by the
proxy itself. To let specific ones through:

```json
{ "allow_server_requests": ["roots/list"] }
```

The proxy also removes the `sampling`, `elicitation` and `roots` capabilities from the
client's `initialize` unless the matching request is allowed, so servers know not to ask.

Responses and `notifications/*` from the server pass. Anything else from the server
(invalid JSON, repeated keys, batches, a message that is both a request and a response,
a "request" without an id, a response to a call Warden is still holding) is dropped and
logged by type only.

## Limits

- Stdio servers only (no HTTP/SSE transport yet).
- Only protects clients configured to use it. The server itself runs with your
  permissions and is trusted.
- Server requests you allow in `allow_server_requests` pass unchecked (Warden doesn't
  look at a sampling prompt or a roots answer).
- The server is trusted for what it answers: a tool result can still be misleading.
- Tool names Warden doesn't accept (uppercase letters, spaces) are always denied.

Design and threat model: [design/mcp-proxy.md](design/mcp-proxy.md),
[design/proxy-hardening.md](design/proxy-hardening.md).
