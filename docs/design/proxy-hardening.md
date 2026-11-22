# Design: MCP proxy hardening (`_meta` and server-to-client requests)

## Problem

Two gaps listed as known weaknesses of `warden proxy` (see `design/mcp-proxy.md`):

1. **`_meta` in `tools/call` is forwarded unchecked.** Warden only sees `name` and
   `arguments`. A lenient server that reads arguments or flags from `params._meta` would
   act on something Warden never checked.
2. **Server-to-client requests are forwarded unchecked.** An MCP server can ask the
   client for `sampling/createMessage` (an LLM call), `roots/list` (the user's file
   roots) or `elicitation/create` (input from the user). A malicious or compromised
   server could get an LLM call or user data through the client, with no policy involved.

## Approach

### `_meta` allow-list (client → server, `tools/call` only)

- New config key `allow_meta_keys`, default `["progressToken"]`. Each key must match
  `^[A-Za-z][A-Za-z0-9._/-]{0,63}$` (ASCII only, so no look-alike or `__proto__` keys
  can be configured).
- In a `tools/call`, `_meta` must be an object whose keys are all on that list (exact,
  case-sensitive comparison, no Unicode normalisation), and each value must be text of
  1-256 printable ASCII characters, or a whole number within ±(2^53 − 1) (booleans are
  not numbers here). `{}` is fine.
- Anything else refuses the **whole call** with JSON-RPC `-32602`, before Warden is asked.
  Nothing is stripped: the server never sees a partly cleaned message, and what is
  forwarded is still re-encoded from the exact object that was checked.
- Repeated keys inside `_meta` were already refused for the whole message
  (`parse_message`); there is a test for it.

### Server → client

Every line from the server is now parsed with the same strict parser as client lines
(no repeated keys, no `NaN`, no batches) and sorted into exactly one shape:

| Shape | Rule | What happens |
|---|---|---|
| response | `jsonrpc`, `id`, exactly one of `result` / `error` | forwarded |
| notification | `jsonrpc`, `method` (text), optional `params` object | forwarded |
| request | `jsonrpc`, `id` (text or whole number), `method`, optional `params` object | forwarded only if `method` is in `allow_server_requests`; else the proxy answers the server with `-32601` and the client never sees it |
| anything else | invalid JSON, repeated key, array, wrong `jsonrpc`, extra keys, ... | dropped, logged by type only |

- New config key `allow_server_requests`, default `[]`, method names checked against
  `^[a-z][A-Za-z0-9_]*(/[a-z][A-Za-z0-9_]*)*$` (at most 64 characters).
- What's forwarded is re-encoded from the parsed object (like client → server), so the
  client reads exactly what the proxy classified.
- **Server `ping`** (decision): if not allowed, the proxy answers it itself with an empty
  result instead of an error. No data reaches the client either way, and some servers
  treat a failed ping as a dead connection.
- **Capability advertising** (decision: done, it stays simple): in the client's
  `initialize`, `params.capabilities.sampling`, `.elicitation` and `.roots` are removed
  unless `sampling/createMessage`, `elicitation/create` or `roots/list` respectively is
  allowed. Well-behaved servers then don't try. It's a convenience only: requests are
  refused whether or not a server asks anyway.
- **Held calls** (decision): a server response whose id is a `tools/call` the proxy is
  still holding (being checked or waiting for approval, so not yet sent to the server)
  is dropped. Otherwise a server could make the client believe a call finished before a
  human decided.

### Logging

Only method names (through `_safe_name`, bounded and escaped) and error types. Never
arguments, `_meta` contents or message bodies.

## Threat model

Protects against (as before, only for clients that reach the server through the proxy):

- Data or flags smuggled to the server through `_meta` (unknown keys, look-alike keys,
  nested objects, huge values, wrong types).
- A server using the client as a resource: LLM calls, the user's file roots, questions
  to the user, or any future request type (default deny by method).
- Requests disguised as responses or notifications (strict shapes; a message with both
  `method` and `result`, or a repeated key, is dropped).
- A server answering a call the proxy hasn't forwarded yet.

## What it doesn't cover

- HTTP/SSE ("streamable HTTP") transports: still stdio only.
- A server returning misleading tool results or notifications: the server is the tool
  and stays trusted for what it says.
- `_meta` (and other `params`) on methods other than `tools/call`: pass-through methods
  carry no tool side effects, and methods in `allow_methods` are passed unchecked by
  design.
- A server that floods requests: each gets an error reply; if the server stops reading
  its input, its own session stalls (fail closed: no tool runs).
- A client answering a server request it never saw (the client is trusted; its responses
  are forwarded as before).

## Decisions and deviations

- `allow_methods` names are not pattern-checked (unchanged): tightening it could break
  existing configs and is outside this change.
- The brief asked to extend the existing Hypothesis fuzz property in
  `tests/test_adversarial_build_session.py`. That file is outside this branch's allowed
  files, so the new server-side property lives in `tests/test_mcp_proxy_hardening.py`;
  the existing property keeps running unchanged (its random `_meta` now gets refused,
  which it allows).
- The CLI has no flags for the new keys: they are set in the config file. `cli.py` is off
  limits for this branch and nothing there needs changing (the config round-trips).

- `tests/test_mcp_proxy.py::test_protocol_basics_pass_and_server_requests_round_trip`
  relied on a server `roots/list` reaching the client by default. That default is now
  the opposite, so the test runs with `allow_server_requests: ["roots/list"]`; it still
  checks the full round trip. Refusal by default is tested in the new file.
- Server notifications must be `notifications/...`, mirroring the client side: a
  `sampling/createMessage` without an id is dropped, since a sloppy client might act on it.
- Bounds for `_meta` values (256 characters, ±(2^53 − 1)) and the `allow_meta_keys`
  pattern are chosen to cover progress tokens (usually short ids or counters) and
  namespaced keys like `io.example/trace`, nothing more.

## Blocked

- `docs/design/mcp-proxy.md` still says server-to-client requests aren't checked and
  `_meta` is forwarded unchecked. It's outside this branch's allowed files; it should
  get a one-line pointer to this note when the branches are merged.

## Re-audit findings

(Filled in at the end.)
