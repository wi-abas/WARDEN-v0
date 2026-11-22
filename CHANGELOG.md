# Changelog

## Unreleased

### Hardening
- **Stricter email check** (found by fuzzing): an address a rule compares must have a
  plain name before the `@`. `user%evil.net@x.com` (percent hack), `host!user@x.com`
  (bang path), `a:b@x.com`, `@x.com`, `.a@x.com`, `a..b@x.com` are now denied.
- **Fix: deeply nested JSON** (`[[[[...]]]]` thousands deep) raised RecursionError, which
  slipped past `except ValueError`: the API answered 500 instead of 422/400 (still deny),
  and one such message ended a whole MCP proxy session. Now refused as invalid input
  everywhere JSON is read (API, proxy, SDK, client, policy, config files, audit verify).
- **`warden test`**: policy tests. Example requests with expected decisions (and
  optionally rule and reason), run through the real engine; exit 1 on any failure.
  `examples/policy-tests.json` covers the default policy, including bypass tricks; CI runs it.
- **Audit checkpoints**: `warden audit head` prints the newest id + hash per table;
  `warden audit verify --expect FILE` proves the log still contains them, catching a full
  rewrite or a cut-off end that the hash chain alone can't see.

### New
- **MCP proxy** (`warden proxy`): put Warden in front of any stdio MCP server; every
  `tools/call` is checked (deny → tool error, approval → wait or "pending"). Config file
  or flags; Claude Desktop / Cursor / Claude Code setup in `docs/mcp-proxy.md`.
- **Python SDK** (`warden.sdk`): `@guard` and `run_guarded` freeze the arguments, check
  them, and run the tool with exactly what was checked. Async tools supported.
- **Agent tokens** (`warden agent add|list|remove`, `--agents`): the agent id comes from
  `Authorization: Bearer <token>`; only SHA-256 hashes are stored. Approvals are bound to
  the agent that asked. Optional; nothing changes without `--agents`.
- **Rate limits and quotas**: optional `limits` section in the policy; per-agent
  requests per minute (429 deny) and pending approvals. Built-in defaults 1,200/min and 100.
  `warden limits [set|reset]` shows and changes them without editing JSON.
- **Persistent approvals**: approval state survives restarts (stored without arguments).
  After a restart an approval can only be approved once the agent has asked again.
- **Tamper-evident audit log**: hash chain over decisions and events, kept intact by
  retention; `warden audit verify` reports the first broken row.
- **Nested argument conditions**: `"arg": ["headers", "to"]`. A plain name with a dot
  (`"file.name"`) still means the top-level argument of that name. `warden check` W013.
- CI: weekly and per-PR dependency scan (pip-audit), weekly mutation tests.

### Behaviour changes
- **Default per-agent limits now apply**: 1,200 requests per minute and 100 pending
  approvals per agent, even without a `limits` section (429 / deny above them). Raise
  them with `warden limits set` for high-volume agents.
- `agent_id` in `/v1/evaluate` is optional when an agent token is sent.

- Package renamed to **agent-warden** (`pip install agent-warden`); import name and the
  `warden` command are unchanged. Repository renamed to `wi-abas/agent-warden`.
- `warden init` creates a starter policy; `warden schema` prints a JSON Schema so editors
  autocomplete policy files (`"$schema"` key).
- New default policy showing argument lists, path and email-domain conditions and messages.
- Retrying with a pending `approval_id` now answers `require_approval` ("waiting for a
  human to approve") instead of `deny`; a human "no" says "denied by a human".
- `examples/agent.py`: an agent loop guarded by Warden, waiting for approvals.
- README rewritten and split into `docs/`; demo image; benchmark (~1 ms per call).
- Tests type-checked with strict mypy; CI on Python 3.12 and 3.13 with 98% coverage gate.

### Security fixes (from a full code review)
- Path and email tricks can no longer dodge rules: `//etc`, `/./etc`, backslashes,
  `"x@evil.com "`, `"x@evil.com."`, `"Evil <x@evil.com>"`, recipient lists. Harmless names
  like `notes..txt` are no longer refused. `warden check` W009 flags case-sensitive path rules.
- Requests not addressed to `127.0.0.1` / `localhost` are refused (blocks DNS rebinding).
- A human can revoke an approval before the agent uses it.
- The audit database is created readable by its owner only (0600).
- Duplicate keys in a policy file are an error instead of silently using the last one.
- 404 and 405 responses carry `"decision": "deny"` and are recorded.
- `warden serve` refuses to start with an invalid or empty policy.
- Approvals get a fresh expiry window when approved; asking again reuses an approved one.
- Audit retention purges run in the background and retry after a failure.
- Rule messages can't contain invisible Unicode (bidi overrides, zero-width characters).
- Recording of rejected requests is capped at 60 per minute.
- Policy schema moved to a versioned path: `schemas/policy-v1.json`.
- CI actions pinned to commit SHAs; Dependabot enabled.
- Docs corrected: programs running as the same OS user can usually read `WARDEN_ADMIN_KEY`.
- URL rules work (the `//` in `https://` was treated as a path trick), and URL tricks such
  as `https://good.com@evil.net` are blocked.
- Infinity and NaN in arguments are rejected as invalid input (422).
- `warden check`: new W010 (allow rules using `neq`/`missing`), W011 (URL prefix without
  `/` after the host), W009 now covers URLs, W004 no longer flags rules differing only in
  `ignore_case`.

### Bypass fixes (from fuzzing tens of thousands of disguised inputs)
- `%`-encoding can't escape path or URL rules (`/data/%2e%2e/etc/passwd`).
- Spaces at the start or end of a path are refused.
- Invisible characters (zero-width, soft hyphen, direction marks) and look-alike Unicode
  (full-width letters, look-alike dots) in compared text are refused.
- New `host_in` op compares a URL's real host (any scheme, port or case, punycode); W012
  suggests it for URL deny rules written as text.
- URL hosts with a trailing dot, an empty port or `::` are refused.

### Overnight security audit
- A locked audit database no longer freezes the server: rejected-request records are
  written by a background worker instead of on the main loop.
- The approval list shows hidden/look-alike characters as `\uXXXX` escapes, with a
  warning, so the approver sees the real action.
- Request bodies with duplicate JSON keys are refused (parser-differential protection).
- `warden serve` refuses a policy that other users could change; `warden init` writes 644.
- Rule values with typos that could never match (invisible characters, look-alikes,
  stray spaces around paths/URLs/emails/exact values) fail to load.
- A corrupted or unwritable audit database gives a clear startup error instead of a crash.
- The example agent runs tools with a frozen copy of exactly what was checked.
- `host_in` requires punycode host names (IDNA2003 vs IDNA2008 mismatch).
- Settings accept only plain 0-9 numbers; a symlinked audit database is refused; an
  approval isn't burned when the audit write fails.

## v0.2.0 (2026-11-22)

First release meant for other people to try. Still an early MVP, **not production-secure**:
read the threat model in [SECURITY.md](SECURITY.md).

### Policies
- **Argument rules**: `when` conditions with `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`,
  `startswith`, `endswith`, `exists`, `missing`.
- **`ignore_case`** for text comparisons, e.g. email domains.
- **Tool argument lists** (`"tools"` section): unexpected or missing required arguments
  are denied before any rule runs.
- **Custom `message`** per rule, shown as the decision's reason.
- **Fail-closed conditions**: a missing argument makes `deny` / `require_approval` rules
  apply; a wrong type or a `..` path denies the request.

### Approvals
- `require_approval` returns an `approval_id`; an admin approves or denies it once.
- Approvals are bound to the exact action (`action_hash`), single-use, expire after
  15 minutes, can't turn `deny` into `allow`, and are kept in memory only.

### Audit
- SQLite audit log of every decision (arguments never stored); a failed write denies.
- Events table: human decisions (recorded before they take effect), failed approval
  attempts, rejected requests.
- Retention: 90 days by default, each purge recorded.

### Tooling
- `warden check`: validates a policy and warns about risky rules (W001–W008).
- `warden serve` settings: `--policy`, `--port`, `--audit-db`, `--retention-days`,
  `WARDEN_ADMIN_KEY`.
- `/health` reports `degraded` (503) when no rules are loaded.
- 30-second demo: `uv run python examples/demo.py`.
- CI: lint, format, strict mypy, tests, policy checks and the demo on every push.

## v0.1.0

- Deterministic policy engine (default deny, most restrictive rule wins, fail closed).
- Strict request validation, body size limits, action fingerprints.
- FastAPI server on 127.0.0.1.
