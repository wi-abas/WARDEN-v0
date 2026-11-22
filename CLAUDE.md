# WARDEN — Project Instructions

## Product

Warden is a developer-first security and policy enforcement layer for AI agents.

Its purpose is to evaluate agent tool calls and decide whether actions should be:

- ALLOWED
- DENIED
- REQUIRE HUMAN APPROVAL

## Current Goal

Build a minimal, working, local-first MVP.

Do not build unnecessary features.

## Technology

- Python 3.12+
- FastAPI
- Pydantic
- SQLite
- Pytest
- Ruff
- uv for package management

## Architecture

- Keep policy evaluation deterministic.
- The policy engine must never rely on an LLM to make security decisions.
- Keep policy logic separate from API routes.
- Keep storage separate from policy logic.
- Use typed Python.
- Prefer simple, readable code.

## Security Requirements

- Default to DENY if a policy is missing or evaluation fails.
- Never execute an agent's tool call inside the policy evaluation engine.
- Validate all input.
- Never expose secrets in logs.
- Treat agent inputs and tool arguments as untrusted.
- Approval must be explicit.
- An approval must be tied to the exact action being approved.
- Prevent approval replay and action modification after approval.
- Do not claim the system is production-secure.

## Development Rules

- Explain the purpose of files before creating complicated code.
- Keep changes small.
- Write tests for every security-sensitive behavior.
- Run tests after every meaningful change.
- Do not silently skip failing tests.
- Do not add dependencies without explaining why.
- Do not implement unrelated features.
- Ask before introducing a major architectural change.

## First Milestone

Build a local policy evaluation API that accepts an action request and returns:

- allow
- deny
- require_approval

Include a policy engine, unit tests, and a basic FastAPI API.

Do not implement the dashboard yet.

## Commands

Use **uv** for everything. Never call `pip` directly and never edit `uv.lock` by hand.

| Task | Command |
|---|---|
| Install / sync deps | `uv sync` |
| Add a runtime dep | `uv add <pkg>` |
| Add a dev dep | `uv add --dev <pkg>` |
| Run tests | `uv run pytest` |
| Run a single test | `uv run pytest tests/test_x.py::test_name` |
| Lint | `uv run ruff check .` |
| Format | `uv run ruff format .` |
| Type check | `uv run mypy` |

Before you call a change done, run `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest` and make sure it passes.

## Layout

- `src/warden/`: the package (src layout, built with `uv_build`). Put all application code here.
- `tests/`: pytest tests. Test the API with `fastapi.testclient.TestClient`.
- SQLite is accessed through the standard library's `sqlite3`, so it needs no extra dependency.

## Git

- Don't commit `.venv/`, `.DS_Store`, `__pycache__/` or `.env` files.
- Commit or push only when asked.
- Don't add `Co-Authored-By` or any Claude attribution lines to commit messages or PR descriptions.
