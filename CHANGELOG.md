# Changelog

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
