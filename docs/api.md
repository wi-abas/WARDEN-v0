# API and operations

## Example

```sh
curl -s -X POST http://127.0.0.1:8000/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{"agent_id": "agent-1", "tool": "write_file", "arguments": {"path": "/workspace/a.txt", "content": "hi"}}'
```

```json
{
  "decision": "require_approval",
  "reason": "Writing files needs a human to approve",
  "matched_rule": "write-workspace",
  "action_hash": "…64 hex characters…",
  "approval_id": "…32 characters…"
}
```

| Endpoint | Purpose |
|---|---|
| `GET /health` | `{"status": "ok", "rules_loaded": 4}`, or HTTP 503 `"degraded"` when no rules loaded (broken or empty policy file: everything is denied). |
| `POST /v1/evaluate` | Send an action, get a decision. With agent tokens, needs `Authorization: Bearer <token>` (401/403 otherwise). Over the agent's rate limit: 429 with `Retry-After`. |
| `GET /v1/approvals` | Admin: list pending approvals, with their arguments. |
| `POST /v1/approvals/{id}/approve` | Admin: approve one (once). |
| `POST /v1/approvals/{id}/deny` | Admin: deny one (once). |

## Approvals

1. The agent asks. A rule says `require_approval`, and the response includes an `approval_id`.
2. You look at what's waiting and approve it. Admin calls need the key Warden prints in
   the terminal at startup (a new one every start):
   ```sh
   curl -s http://127.0.0.1:8000/v1/approvals -H 'X-Warden-Admin-Key: <key>'
   curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/approve -H 'X-Warden-Admin-Key: <key>'
   ```
3. The agent sends the **exact same action** again, plus `"approval_id": "<approval_id>"`.
   While the human hasn't decided, the answer stays `require_approval` ("waiting for a human
   to approve"), so the agent can poll. Once approved it gets `allow`, once. A human "no"
   gives `deny` ("denied by a human").

An approval works **once**, only for the **exact action** that was approved (same agent,
tool and arguments, checked via `action_hash`), and **expires after 15 minutes**. It can
never turn a `deny` into `allow`. Each approval can be decided only once, with one
exception: an approved approval the agent hasn't used yet can still be **revoked** with
`/deny`.

In `GET /v1/approvals`, hidden or look-alike characters in arguments (zero-width spaces,
right-to-left overrides, full-width letters) are shown as visible `\uXXXX` escapes and
the item gets a `warnings` entry, so an agent can't make you approve something that
*looks* different from what it is. The approval is still bound to the real action.

**Restarts:** approval state (id, agent, tool, `action_hash`, status, expiry) is kept in
the audit database, so pending and approved approvals survive a restart; `used` is saved
before an allow is returned, so a restart can't replay one. Arguments never touch disk:
after a restart a pending approval is listed with `"arguments": null` and a warning, and
**can't be approved** (409) until the agent asks again with the same action, which brings
the arguments back (its `action_hash` must match). Denying always works.

## Agent tokens

Without tokens, `agent_id` is whatever the caller says. With tokens, it comes from a
secret only that agent has:

```sh
uv run warden agent add billing-agent      # prints the token ONCE (only its hash is stored)
uv run warden serve --agents warden-agents.json
```

The agent sends `Authorization: Bearer <token>` with every `/v1/evaluate` call
(`agent_id` in the body becomes optional; if present it must match the token, else 403).
No token or a wrong one: 401 with `"decision": "deny"`. The SDK and the MCP proxy read the
token from `WARDEN_AGENT_TOKEN`. Approvals can only be used by the agent that asked.

`warden agent list` and `warden agent remove <id>` manage the file (`--agents FILE`,
default `warden-agents.json`, mode 600). To rotate a token: remove, add, restart Warden.
Changes take effect on restart. Design: [design/agent-tokens.md](design/agent-tokens.md).

**Migrating:** nothing changes until you pass `--agents`. Add every agent, hand out the
tokens, then restart with `--agents`.

## Audit log

Every decision is saved to `warden-audit.db` (SQLite, in the folder you start Warden from):
time, agent, tool, decision, reason, matched rule and `action_hash`.
**Tool arguments are never stored.** If the log can't be written, Warden answers
`deny` (HTTP 503), so nothing is allowed without a record.

A second table, `events`, records everything else: a human approving or denying (if that
record can't be written, the approval doesn't happen), failed approve/deny attempts, and
rejected requests (wrong admin key, bad input, oversized body, errors), with method and URL
path but never the body or query string. Failed approval retries keep the `approval_id`
that was tried, so misuse is visible.

**Retention:** entries older than 90 days are deleted at startup and then once a day.
Each deletion is itself recorded as an `audit_purged` event ("deleted 120 decisions and
4 events older than 90 days"), so gaps in the history are explained. Retention can be
turned off with `--retention-days 0`.

**Tamper evidence:** each table is a hash chain (every row includes the hash of the one
before it). `uv run warden audit verify` recomputes it and reports the first row that was
edited, deleted or inserted, and prints the newest hashes. Keep a copy of those somewhere
else: someone who rewrites the whole file (or cuts off the newest rows) can only be
caught by comparing with a copy. Retention keeps the chain verifiable. Design:
[design/audit-chain.md](design/audit-chain.md).

```sh
sqlite3 warden-audit.db "SELECT timestamp, tool, decision FROM decisions ORDER BY id DESC LIMIT 10"
sqlite3 warden-audit.db "SELECT timestamp, kind, http_status, reason FROM events ORDER BY id DESC LIMIT 10"
```

## Settings

```sh
WARDEN_ADMIN_KEY="$(openssl rand -base64 32)" \
  uv run warden serve --policy my-rules.json --port 9000 --audit-db logs/audit.db --retention-days 365
```

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| Policy file | `--policy` | `WARDEN_POLICY` | `policies/default.json` |
| Port | `--port` | `WARDEN_PORT` | `8000` |
| Audit database | `--audit-db` | `WARDEN_AUDIT_DB` | `warden-audit.db` |
| Audit retention | `--retention-days` (`0` = forever) | `WARDEN_RETENTION_DAYS` | `90` |
| Admin key | *(no flag)* | `WARDEN_ADMIN_KEY` (32+ characters) | random, printed at startup |
| Agent tokens | `--agents` | `WARDEN_AGENTS` | none (agent_id self-declared) |

Flags beat environment variables. The admin key has no flag on purpose: command lines are
visible to every user on the machine (`ps`). Environment variables are hidden from other
users, but programs running as the **same** user, including an agent, can usually read
them (for example `/proc/<pid>/environ` on Linux). **Run agents as a different OS user than
Warden** if they shouldn't be able to approve their own actions.

An invalid setting, or a policy file that is invalid or has no rules, stops Warden with a
clear message instead of starting a server that would deny everything. The host is always `127.0.0.1`.
