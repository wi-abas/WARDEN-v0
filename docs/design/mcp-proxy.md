# Design: MCP proxy (`warden proxy`)

## Problem

Warden only advises: an agent runtime has to ask it and obey the answer. Most agent
tools today are reached through MCP (Model Context Protocol) servers, launched by a
client such as Claude Desktop, Cursor or Claude Code. None of them ask Warden. We want
enforcement without changing either the client or the server.

## Approach

`warden proxy` is itself a stdio MCP server. The client launches it instead of the real
server; the proxy launches the real server as a child process and relays messages
(newline-delimited JSON-RPC 2.0) in both directions.

```
client ──stdin/stdout──▶ warden proxy ──stdin/stdout──▶ real MCP server
                              │
                              └── HTTP 127.0.0.1 ──▶ warden serve (policy, audit, approvals)
```

Client → server messages:

- `tools/call` requests are checked with Warden (`POST /v1/evaluate`, tool = the MCP
  tool name with an optional prefix, arguments = the call's `arguments`).
  - `allow`: forwarded, built from the **same parsed object that was checked** (never the
    raw bytes), so the server can't see anything Warden didn't.
  - `deny`: the proxy answers itself with a tool error (`isError: true`, "Blocked by
    Warden: ..."), so the model sees why. The server never sees the call.
  - `require_approval`: the proxy prints the approve command on stderr and, in `wait`
    mode, polls Warden with the `approval_id` until allow / deny / timeout. In `error`
    mode it answers at once with a "pending approval" tool error; the agent can retry the
    same call later, and the proxy re-checks with the reused `approval_id`.
  - Warden unreachable, bad answer, tool name Warden won't accept: deny.
- Other requests: forwarded only if the method is on a pass-through list (initialize,
  ping, list methods, ...). Unknown methods get a JSON-RPC error. Methods like
  `resources/read` or `prompts/get` can be added explicitly in the config.
- Notifications and responses (to server → client requests) are forwarded.
- Any message with a repeated JSON key, a JSON-RPC batch (array), or invalid JSON is
  refused and never forwarded.

Server → client messages are forwarded unchanged (the server is the tool; the client is
trusted to handle its own protocol).

Config is a strict JSON file (unknown keys rejected). The Warden URL must be on this
machine (`127.0.0.1`, `localhost`, `::1`), so tool arguments are never sent elsewhere.

See also [proxy-stuck-server.md](proxy-stuck-server.md) (a server that stops reading).

## Threat model

Protects against (assuming the client only reaches the server through the proxy):

- A model-driven `tools/call` the policy forbids or that needs approval.
- Parser differentials: duplicate keys (`{"method":"tools/call","method":"ping"}`)
  could make the proxy and the server see different methods or arguments. Refused.
- Checked ≠ executed: the forwarded call is re-serialized from the checked object.
- Smuggling side effects through methods other than `tools/call`: default-deny method list.
- Warden down or slow: fail closed.

## What it doesn't cover

- A client configured to talk to the real server directly (the proxy is opt-in config).
- Anything the server does on its own (it's trusted code running as the user).
- Server → client requests (sampling, elicitation, roots) are not checked.
- HTTP/SSE ("streamable HTTP") MCP transports: stdio only for now.
- Tool names Warden doesn't accept (uppercase, spaces): always denied.
- What a tool's arguments *mean*: that's the policy's job, with all its limits.
