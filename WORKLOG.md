# Work log: long autonomous build session

Branch `build/long-session` (from `main` at `2a01ff1`). Baseline: 703 tests, 99.00%
coverage, ruff/format/mypy clean.

## Decisions

- **Shared HTTP client** (`warden.client`): the proxy and the SDK both need "ask Warden,
  fail closed". One small stdlib-only client (`urllib`), no new dependency.
- **Client URL restricted to this machine** (`127.0.0.1`, `localhost`, `::1`): Warden only
  listens locally, and tool arguments (which may hold secrets) must never be sent elsewhere.
- **MCP proxy forwards the checked object, not the raw bytes**, and refuses duplicate
  keys and batches: closes parser-differential and checked-vs-executed gaps.
- **MCP proxy default-denies unknown methods**; a pass-through list covers the protocol
  basics. `resources/read`, `prompts/get` etc. must be opted into.
- **Warden deny → MCP tool error** (`isError: true`), not a JSON-RPC protocol error, so the
  model sees the reason (per the MCP spec's guidance on tool errors).
- No MCP SDK dependency: stdio MCP is newline-delimited JSON-RPC; the proxy only needs
  to parse and relay it.

## Blocked / needs Wissam

(none yet)

## Progress

- [x] 1. MCP proxy: `bfe5d89` (code + tests), docs next commit. Found and fixed while
  testing: proxy hung if the server's output broke but the process stayed alive; calls in
  flight were dropped when the client closed its input (`echo ... | warden proxy`).
