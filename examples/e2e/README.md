# End-to-end scenario

Runs Warden the way it is used for real: a `warden serve` process, agents talking to it
over HTTP, `warden proxy` in front of an MCP server, a "human" using the approvals CLI,
a restart, and the audit log checks. Roughly 270 checks in about 10-15 seconds.

```sh
bash examples/e2e/run_all.sh
```

It prints one `PASS` / `FAIL` line per check and a `RESULT:` line, and exits non-zero if
anything failed. `tests/test_e2e_scenario.py` runs it as part of `uv run pytest`.

Every run is self-contained: a fresh temp folder (deleted at the end) holds the agent
tokens, admin key, audit database and logs, all generated for that run; Warden gets a free
port; every process started is stopped, even on failure or Ctrl-C. `E2E_KEEP=1` keeps
the temp folder for debugging.

## What each part checks

| File | Checks |
|---|---|
| `run_all.sh` | Orchestrates everything. Also: the policy passes `warden check --strict` and `warden test`; agent tokens via `warden agent add`; the approvals CLI (approve, reject, group decisions are one agent + one tool, an id listed twice is refused); `warden audit verify`, a checkpoint, and that a changed row or a cut-off newest row is detected (on a copy); no tool argument, agent token or admin key appears in the audit database, the server log or the proxy logs. |
| `good_agent.py` | A normal agent with `WardenClient` and `@guard`: allowed calls run, denied ones don't, approvals are queued; an approved call runs exactly once; a replayed or changed call is queued again; a rejected call is refused (sticky rejection) until the human lifts it, then queued again; an unreachable Warden fails closed; a remote Warden URL is refused. |
| `sneaky_agent.py` | Raw HTTP bypass attempts: path tricks (`..`, percent-encoding, look-alike Unicode, hidden characters), email tricks, tool-name tricks, URL tricks (incl. non-http schemes and bad ports), an `otherwise` rule (our domain allowed, others need approval), JSON tricks (duplicate keys, NaN, trailing data, deep nesting, extra fields), Host header (DNS rebinding) and token tricks. |
| `sneaky_approvals.py` | Approvals bound to the exact action and agent, single use, wrong `action_hash` refused, approve/reject without `action_hash` refused (422), revocation; hidden characters shown escaped to the human; admin endpoints need the right key and Host; body size limit (64 KiB) and odd HTTP framing. |
| `flood.py` | Per-agent pending-approval quota and rate limit (429 with `Retry-After`); other agents unaffected. |
| `mcp_client.py` + `e2e_mcp_server.py` | `warden proxy` in error mode and wait mode: only allowed `tools/call` reach the server; malformed messages, batches, odd `_meta`, unknown methods are refused; an approved call runs once; in wait mode the proxy keeps answering while it holds a call, and blocks on reject and on timeout; the server's sampling request never reaches the client; names with newlines or escape codes can't forge proxy log lines. |
| `sdk_wait.py` | `@guard(wait_for_approval=...)`: runs when approved while waiting, not when rejected; asking again after a rejection is refused. |
| `restart.py` | After a restart a pending approval can't be approved blind (arguments are never stored), can't be used for another action, and works once after the agent asks again; an approval granted before the restart still works exactly once. |
| `tamper.py` | Makes the tampered audit database copies for `run_all.sh`. |
| `e2e_common.py` | Shared helpers (raw HTTP, admin calls, PASS/FAIL output). |

`policy.json` is the policy the server runs; `policy-tests.json` its `warden test` cases.

