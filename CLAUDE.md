# WARDEN — Project Instructions

## Product

Warden (PyPI `agent-warden`, import `warden`, repo `wi-abas/agent-warden`) is a
developer-first, deterministic, local-first policy layer for AI agent tool calls. Before
a tool runs, Warden answers:

- `allow`
- `deny`
- `require_approval` (a human must approve that exact action first)

It is an early MVP and **not production-secure**. Never claim otherwise.

## What exists

- **Engine** (`engine.py`): rules with `when` conditions (incl. nested paths like
  `["headers", "to"]`), tool argument lists, path/URL/email/Unicode trick checks, default deny,
  most restrictive wins, fail closed.
- **HTTP API** (`api.py`, FastAPI, `127.0.0.1` only): `/v1/evaluate`, admin approval
  endpoints (`X-Warden-Admin-Key`), host check, body size limit, duplicate-key refusal.
- **Agent tokens** (`agents.py`): optional `--agents` file of SHA-256 token hashes;
  with it, `agent_id` comes from `Authorization: Bearer`.
- **Rate limits and quotas** (`limits.py`): per-agent requests/minute and pending
  approvals, from the policy's `limits` section.
- **Approvals** (`approvals.py`): single use, TTL, revocation, bound to `action_hash` and
  agent; state persisted in SQLite, arguments never on disk.
- **Audit log** (`audit.py`): SQLite, hash-chained, retention, `warden audit verify`.
  Tool arguments are never stored or logged.
- **Clients**: `client.py` (stdlib HTTP client, local URLs only, fails closed),
  `sdk.py` (`@guard`: freeze arguments, check, run exactly what was checked),
  `mcp_proxy.py` (`warden proxy`: stdio MCP proxy checking every `tools/call`).
- **CLI** (`cli.py`): `serve`, `check`, `init`, `schema`, `agent`, `audit verify|head`, `proxy`.

## Technology

Python 3.12+, FastAPI, Pydantic, SQLite (stdlib `sqlite3`), Pytest, Hypothesis, Ruff,
strict mypy, uv. Runtime dependencies: fastapi, pydantic, uvicorn. Nothing else without a
strong reason.

## Architecture

- Policy evaluation is deterministic. **Never** use an LLM for a security decision.
- Policy logic stays separate from API routes; storage separate from policy logic.
- Typed Python, simple readable code.

## Security model (never break these)

- Default to DENY when a policy is missing, evaluation fails, or anything is unexpected.
  Never turn a deny into an allow to make something easier.
- Never execute an agent's tool call inside Warden.
- Treat agent inputs and tool arguments as untrusted; validate all input.
- Never log or store tool arguments or secrets; error responses never echo input.
- Approvals are explicit, single-use, bound to the exact action and agent, can't be
  replayed or modified after approval, and are never approved blind.
- Every security behaviour gets a test. Never weaken or delete existing tests.
- Coverage gate: 98% (CI fails below it).
- New design for a major feature: short note in `docs/design/<feature>.md` first
  (problem, approach, threat model, what it doesn't cover).
- Known remaining weaknesses live in `SECURITY.md` and the latest
  `docs/security-audit-*.md`. Keep them honest and current.

## Development rules

- Explain the purpose of files before creating complicated code (the owner is learning).
- Keep changes small; commit each finished step separately.
- Run the full gate after every meaningful change; don't silently skip failing tests.
- Don't add dependencies without explaining why (prefer optional extras).
- Don't implement unrelated features. Ask before a major architectural change.

## Commands

Use **uv** for everything. Never call `pip` directly and never edit `uv.lock` by hand.

| Task | Command |
|---|---|
| Install / sync deps | `uv sync` |
| Add a runtime / dev dep | `uv add <pkg>` / `uv add --dev <pkg>` |
| Run tests (+ coverage) | `uv run pytest --cov` |
| Run a single test | `uv run pytest tests/test_x.py::test_name` |
| Lint / format / types | `uv run ruff check .` / `uv run ruff format .` / `uv run mypy` |
| Start the server | `uv run warden serve [--policy F] [--agents F]` |
| Validate a policy | `uv run warden check FILE --strict` |
| Regenerate the schema | `uv run warden schema > schemas/policy-v1.json` |
| Verify the audit chain | `uv run warden audit verify [--expect FILE]` |
| Save an audit checkpoint | `uv run warden audit head` |
| Run policy tests | `uv run warden test examples/policy-tests.json` |
| Fuzz (deep, local) | `HYPOTHESIS_PROFILE=deep uv run pytest tests/test_fuzz_targets.py` |
| Show / change rate limits | `uv run warden limits [set\|reset]` |
| Mutation tests (slow) | `uv run python scripts/mutation.py --target engine` |
| Benchmark | `uv run python scripts/benchmark.py` |

Before calling a change done, run (no pipes that hide exit codes):
`uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest --cov`

If imports suddenly fail (`No module named 'warden'`), the project is on the iCloud
Desktop and the `.pth` file got hidden: `chflags nohidden .venv/lib/python*/site-packages/*.pth`.

## Layout

- `src/warden/`: the package (src layout, built with `uv_build`). All application code.
- `tests/`: pytest. API tests use `fastapi.testclient.TestClient`; `tests/helpers.py`
  has `BASIC_POLICY` and `live_server()` for real-HTTP tests.
- `docs/`: user docs (`policies.md`, `api.md`, `mcp-proxy.md`), `design/` notes,
  security audits. `schemas/policy-v1.json` must match `warden schema` (tested).
- `examples/`: demo, example agent, proxy config (all exercised by tests).
- `scripts/`: benchmark, demo SVG, mutation tester.
- CI (`.github/workflows/`): `ci.yml` (lint, types, tests, policies, demo),
  `security.yml` (pip-audit), `mutation.yml` (weekly). Actions pinned to commit SHAs.

## Git

- Don't commit `.venv/`, `.DS_Store`, `__pycache__/`, `.env` files, databases or
  `warden-agents.json`.
- Commit or push only when asked. Never push to `main` directly; work on a branch.
- Don't add `Co-Authored-By` or any Claude attribution lines to commit messages or PR
  descriptions.
