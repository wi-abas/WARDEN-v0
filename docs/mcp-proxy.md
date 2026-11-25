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
| `server.env` | Extra environment variables for the server (never logged). The server gets the proxy's environment **without** `WARDEN_ADMIN_KEY` and `WARDEN_AGENT_TOKEN` | `{}` |
| `warden_url` | Warden on this machine (`127.0.0.1`, `localhost` or `::1` only). Order: `--warden-url`, then this key, then the `WARDEN_URL` environment variable (the config file wins over the environment: it's the specific setting for this proxy) | `http://127.0.0.1:8000` |
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

If the server can't be started (no such command, for example), the proxy says so on stderr
and exits with code 2. Nothing is relayed.

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
the token. Leave `agent_id` out of the config, or set it to the token's agent: if they
don't match, every call is denied.

## Approving

When a call needs approval, the proxy writes what to do to its stderr (Claude Desktop
keeps it in its MCP log):

```text
Warden: write_file needs approval (id <approval id>).
  1. Check what it would do:  warden approvals list --agent <agent id> --warden-url <url>
  2. Then approve it:         warden approvals approve <approval id> --warden-url <url>
```

With an agent token the list command has no `--agent`: only Warden knows which agent the
token belongs to.

Both need `WARDEN_ADMIN_KEY`. `warden approvals approve` shows the action again and sends
its `action_hash` for you. The hint never prints the `action_hash` itself: since v0.4
Warden refuses an approve without it, and the point is that you copy it from the list.
With curl, list first, then send the `action_hash` you were shown:

```sh
curl -s http://127.0.0.1:8000/v1/approvals -H "X-Warden-Admin-Key: $WARDEN_ADMIN_KEY"
curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/approve \
  -H "X-Warden-Admin-Key: $WARDEN_ADMIN_KEY" \
  -H 'content-type: application/json' -d '{"action_hash": "<action_hash from the list>"}'
```

MCP clients have their own time limit per tool call. If yours gives up before you can
approve, use `"mode": "error"`: the model is told approval is pending, and retrying the
same call after you approve goes through (once).

If the client disconnects (closes the proxy's input) while a call waits for approval, the
call is refused and never runs, even if you approve it later. The approval itself stays
in Warden until it expires (or is used up, if it was just being used): the same agent asking for the same action again could use it.

The wait never runs past `timeout_seconds`: a long `Retry-After` is cut short, the last
question is asked just before the end, and an approval that only arrives after it doesn't
run the call (if it was on its way to the proxy, it is used up).

If Warden restarts during a wait, the proxy keeps asking until the approval timeout.

## What the proxy refuses

- Any MCP method other than `tools/call` (checked) and the protocol basics
  (`initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`,
  `prompts/list`, `logging/setLevel`, and `notifications/*`), unless listed in
  `allow_methods`. `tools/call` itself can't be listed, nor the same name in other case.
- Messages that repeat a JSON key, JSON-RPC batches, `NaN`/`Infinity`, numbers too large
  for a 64-bit float (`1e999`), invalid JSON.
  These could make the proxy and the server read different things.
- Requests and notifications with any top-level key other than `jsonrpc`, `id`, `method`
  and `params` (exact spelling), and responses that aren't exactly `jsonrpc`, `id` and one
  of `result` / `error`. A server that ignores case could read `"Method"` as `"method"`
  and run a call Warden never checked.
- A request whose id is still in use: its first request is held by Warden, or the server
  hasn't answered it yet (also after a cancel, since the server may still answer). `1` and
  `"1"` count as the same id. The error has id `null`, so it can't be taken for the first
  request's answer. Ids over 256 characters or beyond ±(2^53 − 1), and requests past
  10,000 unanswered ones, are refused too. When those 10,000 are reached, the oldest
  *cancelled* request makes room (servers usually don't answer one). Its id can't be used
  again in that session. These ids are remembered in a fixed 1 MiB: after very many
  (1% after about 870,000) a new id can be refused as "already in use" by mistake.
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
(invalid JSON, repeated keys, too large numbers, batches, a message that is both a request and a response,
a "request" without an id, a response to a call Warden is still holding) is dropped and
logged by type only. If a dropped answer with a repeated key or a too large number
clearly belongs to one request, the client gets an error for that request instead.

## Limits

- Stdio servers only (no HTTP/SSE transport yet).
- Only protects clients configured to use it. The server itself runs with your
  permissions and is trusted.
- Server requests you allow in `allow_server_requests` pass unchecked (Warden doesn't
  look at a sampling prompt or a roots answer).
- The server is trusted for what it answers: a tool result can still be misleading.
- Keys inside `arguments` are the policy's job: if your server ignores case there (reads
  `"Path"` as `"path"`), use tool argument lists so unknown argument names are denied.
- Tool names Warden doesn't accept (uppercase letters, spaces) are always denied.

Design and threat model: [design/mcp-proxy.md](design/mcp-proxy.md),
[design/proxy-hardening.md](design/proxy-hardening.md).
