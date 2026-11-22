# Security audit, 2026-11-22 (overnight session)

Branch: `security/overnight-audit` (local only, not pushed). Base: `main` at `39f79f5`.

Warden is still an early MVP and **not production-secure**; this audit doesn't change
that. It found and fixed verified weaknesses, and lists what remains.

## Method

- Read all source (`src/warden/*`), tests, README, SECURITY.md, docs, CHANGELOG, CLAUDE.md.
- Baseline: 652 tests passing, 99.41% coverage, ruff/format/mypy clean, clean worktree.
- Every finding below was reproduced against the real code before fixing.
- Tools: hand-written proof-of-concept scripts; a mutation tester (326 → 338 planted
  bugs); Hypothesis property tests (deep profile, 60,000 inputs); a bypass fuzzer
  (15,000 disguised paths/URLs/emails per run); a live chaos test (30 threads, 1,755
  concurrent requests against a real server); a real-process start/use/Ctrl-C run.

## Findings fixed in this session

Severity is for Warden's own threat model (a local checkpoint trusted by its operator).

| # | Severity | Finding | Fix | Commit |
|---|---|---|---|---|
| 1 | **High** | **Server freeze (DoS).** `api.py` `_Warden.record_rejection` wrote to SQLite synchronously on the event loop. While another process held the database (e.g. someone browsing it), every rejected request blocked the whole server for 5 s. PoC: hold `BEGIN EXCLUSIVE`, send a bad-Host request, `/health` took 5.05 s. | Rejection records go to a single background worker (`_emit`); tests use a synchronous switch. | `0805268` |
| 2 | **High** | **Approver spoofing.** `GET /v1/approvals` returned arguments raw, so `U+202E` (right-to-left override), zero-width and full-width characters made the human *see* a different action than the real one. | Such characters are shown as `\uXXXX` escapes with a `warnings` entry (`_display_safe`). The approval stays bound to the real `action_hash`. | `8140c3e` |
| 3 | **Medium-High** | **Parser differential.** `{"tool":"delete_file","tool":"read_file"}` was evaluated as `read_file` (Python keeps the last key); a first-wins parser in the agent runtime would run `delete_file`. | New `DuplicateKeyCheck` middleware (after the size limit) refuses repeated keys at any depth with 422. | `551abee` |
| 4 | **Medium** | **Writable policy accepted.** `warden serve` started with a mode-666 policy; any local user could rewrite every rule. | `settings.unsafe_permissions`: refuse group/world-writable policies, or ones in a world-writable folder without the sticky bit. `warden init` writes 644. | `b0e3c9a`, `e7cb92c` |
| 5 | **Medium** | **Silent rule typos.** A deny rule value like `"@evil.com "` or one containing `U+200B` never matched anything, protecting nothing, with no warning. | `models._check_policy_text`: such values (invisible/look-alike characters; edge spaces on exact matches and path/URL/email values) fail to load. | `005e312` |
| 6 | Low | **Startup crash.** A corrupted or unwritable audit database crashed `serve` with a raw traceback. | `StartupError`, clean message, exit 2. | `a093453` |
| 7 | Low | **Example agent TOCTOU.** `examples/agent.py` checked the caller's dict and later ran the tool with the same mutable object. | Snapshot once; the same frozen copy is checked and executed. | `1196294` |
| 8 | Test gaps | Second mutation run: strictness tests used values loose mode also rejects; mixed-type `in` lists; plain text vs path checks; URLs with spaces; rate-limit window edge. | New tests. Mutation score 86% → 94% (rest are equivalent mutants). | `d8ff184` |

Also fixed earlier the same day on `main` (already pushed): `host_in` IDNA2003/2008
mismatch, settings number parsing crash, symlinked audit DB, approval burned on audit
failure, model strictness/boundary tests.

## Verified as holding up

- Engine invariants (no rule → deny, deny wins, order-independent, allow only from allow
  rules): 60,000 generated cases, 0 failures.
- Bypass fuzzer: 0 bypasses for path rules, email rules and `host_in` rules; allow-lists
  can't be escaped with `%2e%2e`.
- Approvals under concurrency: 1,755 concurrent requests, no approval ever produced more
  than one `allow`, audit log matches what agents saw, no 5xx.
- HTTP fuzzing: 5,000 malformed requests, no 5xx, every error carries `deny`.
- Real process: starts, serves, refuses a foreign Host, shuts down cleanly on Ctrl-C;
  audit DB mode 600; the admin key never printed when set via `WARDEN_ADMIN_KEY`.

## Remaining weaknesses (not fixed: architectural, or a product decision)

| Severity | Issue | Why not fixed tonight |
|---|---|---|
| **Critical (by design)** | **No enforcement.** Warden advises; an agent can skip it or execute different arguments. | Needs the planned SDK / MCP proxy. |
| High | **No agent authentication.** `agent_id` is self-declared; any local process can call `/v1/evaluate` and consume an approval if it knows the id and exact action. | Needs per-agent credentials. |
| Medium | **No request rate limiting.** A local process can fill the approval queue (1,000 pending, global) or grow the audit DB without bound within the retention window. | Meaningful limits need agent identity (per-agent quotas). |
| Medium | **One shared admin key**, printed to the terminal when not set; no record of which person approved. | Needs user accounts. |
| Medium | **Text URL deny rules** still miss `http://` vs `https://` and explicit ports. | Inherent to text matching; `host_in` + warning W012 is the answer. |
| Low | Conditions only see top-level arguments; nested values aren't checked. | Feature work (paths into JSON). |
| Low | Audit log not tamper-evident. | Planned (hash chain). |
| Low | Approvals are in memory: lost on restart, per process. | Planned (persistent approvals). |
| Info | Dependencies weren't scanned for known CVEs (no outside network access in this session). `uv.lock` pins versions; Dependabot is on. | Run `pip-audit` / GitHub alerts. |
| Info | `/docs` loads Swagger UI from a CDN (documented). | |
| Info | Equivalent surviving mutants (e.g. log propagation, daemon flag) need no tests. | |

## Final results

- Tests: **703 passed** (baseline 652), coverage **99.00%** (gate 98%).
- ruff, ruff format, mypy --strict (62 files): clean.
- `warden check --strict` on both shipped policies: clean. Demo: all steps as expected.
- Benchmark: ~10 µs per decision, ~1.06 ms per HTTP request including the audit write.
