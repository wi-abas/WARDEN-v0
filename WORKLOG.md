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

- **SDK freezes through JSON** (not `copy.deepcopy`): JSON is what Warden checks, so
  the frozen copy is checked and executed byte-for-byte the same. Non-JSON values
  (objects, sets, NaN, and therefore `self` on methods) are refused. Defaults are applied
  so Warden sees the full effective call. `*args` / positional-only parameters are
  refused at decoration time.
- **SDK default on `require_approval`: raise `ApprovalPending` at once** (no hidden
  blocking); `wait_for_approval=seconds` opts into polling.

- **Agent tokens in a JSON file** (not SQLite): it's configuration, reviewed and managed
  like the policy, checked for unsafe permissions the same way. SHA-256 (fast hash) is
  correct for 256-bit random tokens. Lookup compares every entry (no early exit).
- **Open mode stays the default** (backwards compatible) with a startup warning; with
  `--agents`, the token decides `agent_id` and a mismatching body `agent_id` is a 403.
- **Proxy token from `WARDEN_AGENT_TOKEN` env only**, never the proxy config file.

- **Limits live in the policy file** (`limits` section, optional, schema stays v1 and
  backwards compatible): limits are trusted config like rules. Built-in defaults apply
  without it: 600 requests/minute and 50 pending approvals per agent (previously only a
  global 1,000 pending). Token bucket, injectable monotonic clock. 429 + Retry-After,
  recorded through the capped rejection log. Pending quota checked under the store lock.
  Note: SDK/proxy polling counts against the limit (2 s polls = 30/min per waiting call).

- **Persistent approvals keep arguments off disk**: state only, in an `approvals` table
  of the audit database. Arguments come back when the agent re-sends the same action
  (hash must match); approving is refused while they're unknown (no blind approvals).
  Write-through: the DB write happens before the in-memory change. Wall clock for expiry
  when persisted. Known gap: if the audit event for a human decision is written but the
  approvals write then fails, the API answers 503 "nothing changed" yet the events table
  has an approve entry (the state really didn't change). Acceptable; noted.

- **Audit chain: one chain per table**, prefix-only retention deletes with anchors
  (stored in `audit_anchors` and in the chained purge event), `BEGIN IMMEDIATE` around
  every write. Kept the purge reason text unchanged (existing tests assert it). No
  HMAC key: a key on the same disk adds little; documented that a full rewrite needs an
  outside copy of the head hash to detect.

- **Nested args: dotted string = path** (as asked). Argument names could already contain
  dots, so this changes the meaning of such old rules, but provably only toward deny
  (tested). List form `["a.b"]` reaches a literal dotted key. A non-object on the path
  denies the whole request; lists are never searched; max depth 8. New warning W013.

## Blocked / needs Wissam

(none yet)

## Progress

- [x] 1. MCP proxy: `bfe5d89` (code + tests), docs next commit. Found and fixed while
  testing: proxy hung if the server's output broke but the process stayed alive; calls in
  flight were dropped when the client closed its input (`echo ... | warden proxy`).
- [x] 2. Python SDK (`warden.sdk`): guard, run_guarded(_async), freeze, ApprovalPending.
- [x] 3. Per-agent tokens (`warden agent add/list/remove`, `--agents`, Bearer auth).
- [x] 4. Per-agent rate limits and pending-approval quotas (`limits` in the policy).
- [x] 5. Persistent approvals (state in SQLite, arguments never on disk).
- [x] 6. Tamper-evident audit log + `warden audit verify`.
- [x] 7. Conditions on nested arguments (+ W013, schema, docs).
