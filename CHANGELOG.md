# Changelog

## v0.4.2 (2026-11-26, alpha)

### Security
- Warden proves its identity. With an agent token (SDK, MCP proxy) or the admin key
  (`warden approvals`), nothing secret is sent before that, and only signed answers count;
  otherwise deny. The agents file now holds a secret `server_key` per agent (add agents
  again) and must not be readable by others. Without `--agents` nothing is proven.
- Requests with `Transfer-Encoding` are refused (411), also with `Content-Length`, and body
  bytes are counted as they arrive. Together the two headers bypassed the 64 KB limit.
- With `ignore_case`, text whose upper/lower case is ambiguous (ß/ss, ς/σ, İ/ı/i) denies:
  `eve@busineß.com` no longer matches `@business.com`.
- `startswith` denies `..` segments for prefixes without a slash too.
- URLs whose host has illegal characters (`evil.net;.good.com`) deny. URL text rules deny
  disguised dot segments (`..;`, `%c0%ae`, `%u002e`) and malformed escapes.
- `warden serve` refuses a policy or agents file if it, or any folder or symlink on its
  path, is owned by anyone but root or Warden's user, or if a folder on the path is
  group-writable without the sticky bit. A 0775 home folder needs `chmod go-w ~`.
- An audit row SQLite silently dropped or changed (trigger, view, ON CONFLICT IGNORE) counts
  as a failed write: 503 deny. Triggers, views and virtual tables in the audit database are
  refused at startup and on every write, and reported by `audit verify`.
- Approval waits never outlast their timeout; a late allow doesn't run the tool.
- Invalid `/v1/evaluate` requests with a valid agent token use that agent's request budget.
- The approval list escapes line separators, blank-looking, private-use and unassigned
  characters, with a warning. The access log omits query strings.

### Changed
- `warden proxy`: cancelled, unanswered requests no longer block it (their ids stay refused);
  numbers too large for a float (`1e999`) are refused instead of becoming `Infinity`.
- SDK: dicts with non-text keys are refused; refusals name the argument and explain methods.
- `warden check`: new W018 and W019; W005 covers relative paths.
- `warden approvals list` is much faster with many large approvals, and a timeout is no
  longer reported as "can't reach Warden".
- `warden serve` on a busy port stops before printing an admin key; `warden init` next steps
  work without uv; `audit verify` and `head` explain a leftover SQLite journal.
- Docs: not on PyPI yet, tagged installs; amount examples have a lower bound.
- `warden init` makes its folders 755 whatever the umask, so `serve` accepts them.
- `ignore_case` checks of a long argument against a long list are about ten times faster.

## v0.4.1 (2026-11-25, alpha)

### Security
- `warden proxy` refuses client requests and notifications with any top-level key other
  than `jsonrpc`, `id`, `method`, `params`, and look-alikes of `tools/call` in
  `allow_methods`. A hidden `Method`/`Params` pair could reach the server unchecked.
- `warden proxy` never runs a call waiting for approval once the client disconnected, also
  when the server had stopped reading (it is cut off instead), and refuses a request id still in use (`1` and `"1"` are the same), overlong ids and more
  than 10,000 unanswered requests.
- Every character Unicode may draw as nothing (variation selectors, Hangul fillers,
  U+034F, ...) counts as hidden in compared text, rule values and the approval list.
  Emoji with U+FE0F are therefore refused in arguments a rule compares.
- The approval list uses `\UXXXXXXXX` above U+FFFF; two argument names can never display
  the same and hide one.
- The client and `warden approvals` refuse all HTTP redirects.
- Servers sharing one database can't each use the same approval; a newer rejection or
  revocation always beats restoring one.
- URLs whose host has an empty label (`https://..evil.net/`), or that ends in a dot
  right before `?` or `#` (`https://evil.net.?x`), are refused.
- A crash no longer puts the exception message or traceback (possibly tool arguments) in
  Uvicorn's log.
- `serve` checks the policy and agents file paths through symlinks and every folder.

### Changed
- `run_guarded` with an async function, or `run_guarded_async` with a plain one, raises
  `TypeError` before any check.
- Approval waits (SDK and proxy) survive a brief Warden restart. Async waits hold no
  threads and stop when cancelled.
- A trailing slash (`/v1/evaluate/`) is a 404 deny, not an empty redirect.
- `examples/agent.py` uses `WardenClient`.

### Fixed
- `warden limits` shows `rejection_window_seconds`, and `limits reset` keeps it.
- `warden agent` uses `WARDEN_AGENTS`.
- Clear errors instead of tracebacks for unreadable files or folders, over-long numbers,
  broken connections, unsendable admin keys and MCP servers that can't start.
- `warden proxy` no longer aborts when the server stops first; its approval hint no longer
  names the wrong agent when a token is used.
- Retention above 36500 days is refused (it broke every purge); use 0 for forever.
- `audit verify`, `audit head` and `--expect` don't call an honest log broken during a
  purge, and report BROKEN for value types Warden never writes.
- A client (SDK, `WardenClient`, proxy) given both a token and an `agent_id` sends both, so a
  mismatch is denied. Before, the `agent_id` was silently ignored.
- The sample in `docs/policies.md` is corrected and tested. Every test file must be mapped
  in `scripts/mutation.py` or exempted.

## v0.4.0 (2026-11-24, alpha)

### Changed
- **`action_hash` required** to decide what you haven't listed:
  - `POST /v1/approvals/{id}/approve` needs the body `{"action_hash": "..."}`.
  - `POST /v1/approvals/{id}/deny` on a **pending** approval needs it too. Revoking an
    approved, unused approval still works with no body (or `{}`); a sent hash is checked.
  - `POST /v1/approvals/decide` needs `action_hashes` for reject too (it already did for
    approve).
  - Missing: HTTP 422 `{"error": "action_hash required: list the approvals and send the
    action_hash you were shown"}` (`action_hashes required: ...` for groups); nothing
    changes and the refusal is audited. Wrong hash: 409, as before.
- **Migration**: scripts that call `/approve` or `/deny` without a body should list
  first (`GET /v1/approvals`) and send the `action_hash` from that list, or use
  `warden approvals approve|reject ID`, which does both (unchanged for CLI users). The
  MCP proxy and `examples/agent.py` now print `warden approvals list` / `approve`
  instead of a bodiless curl; they never print the hash.
- **`host_in` only accepts `http` and `https` URLs by default.** A URL with another
  scheme (`ftp://`, `gopher://`, `file://`, `ws://`, `git://`, ...) can't be checked and
  denies the whole request, for allow and deny rules alike (no protocol smuggling to an
  allowed host, no dodging a deny rule). Add `"schemes": [...]` to the condition if a
  tool really needs other schemes. Run `warden test` with such URLs before upgrading.
- **URLs with a port outside 1–65535 or with a leading zero** (`:0`, `:99999`, `:080`)
  are now denied wherever a rule compares URLs (`host_in` and text ops on URLs).

### Added
- **Approval hygiene**: `GET /v1/approvals` items carry `age_seconds`;
  `?max_age_seconds=N` (and `warden approvals list --max-age MINUTES`) shows only recent
  ones. The default list showing only pending, unexpired approvals is now a tested
  promise. The CLI prints "asked 8 min ago".
- `warden approvals approve` warns when the chosen ids span separate runs (asked more
  than 2 minutes apart), prints each run and asks about all of them; with `--yes` it
  refuses unless `--across-runs` is also given. Rejecting is never blocked.
- **`otherwise` on a rule**: one rule, two outcomes. `effect` when every `when`
  condition holds, `otherwise` when one doesn't or its argument is missing. It must be
  stricter than `effect` and needs a non-empty `when` (load errors), so it can never
  loosen an answer; an uncheckable argument still denies the whole request. The reason
  says which branch decided (`rule 'x': conditions not met`).
- **`contains` op**: the text argument contains a text (or any of 1–100 texts), with
  `ignore_case`. A tripwire for deny / require_approval rules; refused in allow rules
  (load error), since it compares text, not meaning.
- **`schemes` on a `host_in` condition**: the full list of URL schemes it accepts.
- `warden check`: W016 (`neq`/`missing` in a rule with `otherwise`), W017 (`host_in`
  conditions on one argument with different `schemes`). W003 knows a rule with
  `otherwise` always applies; W008/W009/W012 cover `contains`.
- `warden proxy` reads `WARDEN_URL`: `--warden-url`, then `warden_url` in the config
  file, then `WARDEN_URL`, then the default.
- Schema: `otherwise` on a rule, `contains`, `schemes` (still `policy-v1`, a superset).
- **Sticky rejections**: after a human rejects (or revokes) an approval, the same agent
  asking for the exact same action within `limits.rejection_window_seconds` (default
  900, `0` = off, max 7 days; per agent) gets `deny` ("rejected by a human; this exact
  action is refused until ...") instead of a new pending approval. Group rejects are
  sticky too; rejections don't count toward the pending quota; they survive a restart
  (approvals table, new `decided_at` column, migrated automatically).
- `GET /v1/approvals?status=rejected` and `warden approvals list --rejected`: standing
  rejections. `POST /v1/approvals/{id}/lift` and `warden approvals lift ID`: lift one,
  audited (`approval_rejection_lifted`) before it takes effect.
- Schema: `rejection_window_seconds` in `limits` (still `policy-v1`, a superset).
- **Per-agent rules**: a rule may list the agents it applies to
  (`"agents": ["billing-agent"]`); no key = every agent, as before. Exact,
  case-sensitive names; an empty list, `null` or duplicates are refused. Most
  restrictive still wins, so a per-agent allow never beats a deny for everyone.
- `warden serve` refuses to start when the policy has a per-agent rule but no
  `--agents` file, or names an agent (in a rule or `limits.agents`) that isn't in it.
- `warden check --agents FILE`: W014 (unknown agent name), W015 (names that differ only
  in case). W003/W004 take `agents` into account.
- Schema: `agents` on a rule (still `policy-v1`, a superset).

### Changed
- Asking again for a rejected action is now refused for the rejection window (it used
  to create a new pending approval at once). Set `rejection_window_seconds: 0` for the
  old behaviour.
- With `--agents`, a `limits.agents` entry for an agent that isn't in the agents file
  now stops `warden serve` from starting (it was silently unused).

## v0.3.0 (2026-11-22, alpha)

### Security fixes (full code review)
- **Host-name rules**: `endswith`/`eq` with a value like `evil.com` could be dodged with
  `x@evil.com.`, `x@evil.com>` or `evil.com.`; such text is now denied as uncheckable.
- **Approval display**: a key that looked like an escape (`note\u200b`) could hide another
  argument from the approver. The display is now one-to-one.
- **No HTTP proxies**: the client (SDK, MCP proxy) and `warden approvals` ignore
  `HTTP_PROXY`, which sent arguments and the admin key to the proxy.
- **MCP proxy**: the server no longer inherits `WARDEN_ADMIN_KEY` / `WARDEN_AGENT_TOKEN`.
- **Audit verify**: rows without hashes only pass as history in a database that really
  predates the chain (recorded when the columns are added); nulling hashes is reported.
- **Host check**: requests with more than one `Host` header are refused.

### Hardening
- **Threat model** (`docs/threat-model.md`): assets, attackers, every defence linked to
  its tests, and the risks that remain.
- **Release workflow** (prepared, not yet used): tag `vX.Y.Z` → checks, build, CycloneDX
  SBOM, GitHub build-provenance attestation, PyPI trusted publishing (no stored token)
  behind a protected `pypi` environment. Setup steps in `docs/releasing.md`.
- **Fuzzing**: five fuzz targets with independent oracles (`tests/fuzz_targets.py`),
  run through Hypothesis in every test run and weekly with Atheris in CI
  (`scripts/fuzz.py`, `.github/workflows/fuzz.yml`; Linux-only `fuzz` dependency group).
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
  rewrite or a cut-off end that the hash chain alone can't see. Older checkpoints that
  retention deleted are skipped; the newest per table must still match.

### New
- **Approval list filters**: `GET /v1/approvals?ids=A,B&agent_id=X&tool=Y` (and
  `warden approvals list --agent A --tool T`). `approve`/`reject` fetch only the ids
  they name, so a flood of pending approvals (the stress test made a 63 MB list) can no
  longer stop a reviewer from rejecting. Filters only narrow the view.
- **Group approvals**: `GET /v1/approvals?group=true` lists pending approvals grouped by
  agent and tool (every action in full); `POST /v1/approvals/decide` approves or rejects
  up to 100 exact ids, all or nothing, one agent and tool at a time, audited before it
  takes effect. CLI: `warden approvals list [--group]` and `warden approvals
  approve|reject ID ...` (shows every action, then asks; `--yes` for scripts; admin key
  from `WARDEN_ADMIN_KEY` only). Approving a group needs the `action_hash` shown for each
  id, so ids alone (e.g. pasted from an agent's message) can't be approved unseen.
- `/v1/approvals/{id}/approve` and `/deny` accept an optional `{"action_hash": ...}`
  body; when sent, it must match (409 otherwise).
- **MCP proxy** (`warden proxy`): put Warden in front of any stdio MCP server; every
  `tools/call` is checked (deny → tool error, approval → wait or "pending"). Config file
  or flags; Claude Desktop / Cursor / Claude Code setup in `docs/mcp-proxy.md`.
  Requests from the server (sampling, roots, elicitation) are refused unless listed in
  `allow_server_requests`; a `tools/call`'s `_meta` may only hold `allow_meta_keys`
  (default `progressToken`).
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
