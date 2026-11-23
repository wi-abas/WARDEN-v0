# Security audit, 2026-11-22 (long build session re-audit)

Branch: `build/long-session` (pushed, not merged). Base: `main` at `2a01ff1`.

Scope: everything built in this session: MCP proxy, Python SDK and client, agent tokens,
rate limits and quotas, persistent approvals, the audit hash chain and `audit verify`,
nested argument conditions. Warden is still an early MVP and **not production-secure**.

## Method

- Read the new code against its design notes (`docs/design/*.md`).
- Every finding below was reproduced with a proof-of-concept before fixing, and each fix
  has a regression test.
- Fuzzing (Hypothesis): random JSON-RPC traffic through the proxy (incl. method
  look-alikes, bad ids, extra fields, every duplicate-key placement); SDK arguments of any
  nested shape tampered in place during the check; 2,000 disguised nested arguments
  against a nested deny rule.
- Races: 24 threads using one persisted approval; 80 concurrent requests against a
  30/minute limit; 8 threads × 50 writes on the audit hash chain; 160 concurrent
  approval requests against a 7-per-agent quota.
- Mutation testing (`scripts/mutation.py`, new): 286 planted bugs in the new and
  security-critical modules, 83.2% caught before the gap tests below.
- Real processes: `warden serve` + `warden proxy` (with a fake MCP server) + `warden
  audit verify`, driven over stdin/stdout.
- Dependency scan: `pip-audit` over the locked dependencies (with hashes): no known
  vulnerabilities.

## Findings fixed

Severity is for Warden's own threat model (a local checkpoint trusted by its operator).

| # | Severity | Finding | Fix | Commit |
|---|---|---|---|---|
| 1 | **Medium** | **Proxy forwarded unchecked `tools/call` fields.** Only `name` and `arguments` were checked, but any other `params` field (e.g. `argumentsOverride`) reached the server. A server that reads such a field would act on something Warden never saw. | `params` may only hold `name`, `arguments`, `_meta`; anything else: -32602. | `2f64443` |
| 2 | **Medium** | **Proxy forwarded call-shaped messages without a method.** `{"id":1,"method":null,"params":{"name":"danger",...}}` (or `params` with no `method`) was treated as a response and forwarded unchecked; a lenient server could run it. | Only well-formed responses (`jsonrpc`, `id`, exactly one of `result`/`error`) are forwarded without a method; a present `method` must be text. Fuzz property extended. | `1814cba` |
| 3 | **Medium** | **`audit verify` could check a different file.** The path was pasted into a SQLite URI, so `#`, `?` or `%` changed the file opened (`audit#1.db` → `audit`): a tampered log could verify as OK. | `Path.as_uri()` escaping; test with decoy files. | `2d8c71f` |
| 4 | Low | **Approval hint encouraged blind approvals.** The proxy printed only the approve command. | Hint shows the review (list) command first. | `59acc2a` |
| 5 | Low (availability) | **A 429 while polling for approval ended the wait as a deny** (SDK and proxy), even when the human was about to approve. | `Answer.retry_after` from `Retry-After`; polling backs off and keeps waiting until its deadline. Never an allow. | `8fe1f4b` |
| 6 | Low | Found while building (fixed before the first proxy commit): the proxy could hang if the server's output broke while the process stayed alive, and dropped calls in flight when the client closed its input. | Unified shutdown; in-flight calls answered. | `bfe5d89` |
| 7 | Test gaps | Mutation survivors: `host_in ".x.com"` covering the bare domain, `apply_approval` leaving deny/allow untouched, IPv6 host suffixes, wall clock for persisted approvals, limit bounds, SDK default not waiting, error messages. | New tests; wider mutation target mappings. | `54425be`, `4bbac3a` |

## Follow-up: full code review (same day)

A line-by-line review of all of `src/warden/`. Each finding was reproduced with a
script before fixing, and each fix has a test that fails without it.

| # | Severity | Finding | Fix | Commit |
|---|---|---|---|---|
| 8 | **Medium** | **Host-name rule values could be dodged.** A value like `evil.com` (no `@`, no `/`) skipped every shape check: `x@evil.com.`, `x@evil.com>`, `<x@evil.com>,` or `evil.com.` slipped past a deny rule. | Text compared with a host-shaped value: no trailing dot, edge spaces, list/display-name characters or look-alike dots. | `e3dfa97` |
| 9 | **Medium** | **An argument could be hidden from the approver.** A literal `note\u200b` key displayed exactly like an escaped `note<ZWSP>`; with both present one overwrote the other in the approval list. | A backslash before `u` is escaped too, so the display is one-to-one (property test). | `44a8f41` |
| 10 | **Medium** | **Client honoured `HTTP_PROXY` for 127.0.0.1.** The SDK and MCP proxy sent tool arguments to the proxy (and trusted its answer); `warden approvals` sent it the admin key. | Opener with proxies switched off. | `3f5a963` |
| 11 | Low–Medium | **MCP server inherited Warden's secrets.** `WARDEN_ADMIN_KEY` (if exported) and `WARDEN_AGENT_TOKEN` reached the server's environment; with the admin key it could approve its own calls. | Removed unless the config's `server.env` sets them on purpose. | `8e208fb` |
| 12 | Low–Medium | **Nulling hashes hid edits from `audit verify`.** Rows without hashes counted as pre-chain history: change decisions, set the hash columns to NULL (plain SQL), and verify said OK. | Hash-less rows are accepted only up to the ids recorded (in the chain) when the columns were added to an old table; none otherwise. | `17838af` |
| 13 | Low | **Two `Host` headers**: only the last was checked. | Exactly one required. | `77b1cd4` |

## Verified as holding up

- Proxy fuzzing: no unchecked, modified or method-less call reached the server; every
  duplicate-key placement refused; forwarded calls are byte-for-byte the checked object.
- SDK: the tool always received exactly what was checked, whatever was tampered.
- Nested deny rules: no dodge across 2,000 disguised inputs (non-object on the path,
  look-alike Unicode, display names, lists, missing keys).
- One persisted approval → exactly one allow under 24 concurrent uses; still `used`
  after a restart. Arguments never reached the database file.
- Rate limit: exactly 30 of 80 concurrent requests allowed. Quota: exactly 7 of 160.
- Hash chain: one valid chain after 400 concurrent writes; every edit/delete/insert/
  reorder/anchor-edit test case reported at the right row.
- Agent tokens: only hashes on disk (mode 600), every lookup compares all entries,
  spoofed body `agent_id` → 403, another agent's approval → deny without burning it.

## Remaining weaknesses

| Severity | Issue | Notes |
|---|---|---|
| **Critical (by design)** | **Enforcement only where Warden is in the path.** A client configured to reach the MCP server directly, or code calling an undecorated function, bypasses Warden. | Proxy and SDK are opt-in. A sandbox is out of scope. |
| High | **Agent tokens are optional.** Without `--agents`, any local process can be any agent and dodge per-agent limits with new ids (up to 10,000 tracked). | Recommend `--agents` everywhere; maybe make it the default in a later release. |
| Medium | **Approving by id alone is still possible.** The admin API doesn't require having listed the approval; after a restart it does (no blind approvals), otherwise it relies on the human. | **Fixed in v0.4** (approval hygiene): `action_hash` from the list is required to approve, to reject a pending approval, and for group rejects; only revoking stays bodiless. Per-person approval UI (Slack, dashboard) still planned. |
| Medium | **One shared admin key**; no record of which person approved. | Unchanged. |
| Medium | **Audit chain is tamper-evident, not tamper-proof.** A full rewrite or cutting the newest rows is only caught with an outside copy of the head hashes. Approval state in the same file can be edited by whoever can write it. | No signing key (a key on the same disk adds little). |
| Low | Proxy forwards `_meta` and server→client requests (sampling, roots, elicitation) unchecked; stdio transport only. | Documented. |
| Low | Nested conditions don't search lists; argument lists only cover top-level names (W013 warns). | Feature work. |
| Low | Text and `host_in` rules see the host as written: `http://2130706433/` and `http://0x7f.1/` both reach 127.0.0.1, so a deny list of IP addresses can be dodged. | Prefer allow lists (`host_in` with the hosts you trust). |
| Low | Look-alike letters from other scripts (Cyrillic `а` in `pаypal.com`) aren't flagged in the approval list; only invisible and compatibility characters are. | Rules don't match them (exact text), but an approver can be fooled. |
| Low | Persisted approval expiry uses the wall clock (jumps shorten/extend it); one Warden per database. | Documented. |
| Low | When the 10,000-agent table is full, each new agent triggers an O(n) scan for idle buckets. | Only reachable without tokens. |
| Info | Mutation score 83% before the gap tests; most remaining survivors are equivalent mutants (constants, `strict=True` already enforced by the parent model). | Weekly CI job, floor 80%. |

## Final results

See the session's final report (test count, coverage, lint/types) and `WORKLOG.md`.
