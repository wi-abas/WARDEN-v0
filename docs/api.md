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
| `POST /v1/evaluate` | Send an action, get a decision. |
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
`/deny`. Approvals are kept
in memory only (arguments never touch disk), so restarting Warden clears them.

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

Flags beat environment variables. The admin key has no flag on purpose: command lines are
visible to every user on the machine (`ps`). Environment variables are hidden from other
users, but programs running as the **same** user, including an agent, can usually read
them (for example `/proc/<pid>/environ` on Linux). **Run agents as a different OS user than
Warden** if they shouldn't be able to approve their own actions.

An invalid setting, or a policy file that is invalid or has no rules, stops Warden with a
clear message instead of starting a server that would deny everything. The host is always `127.0.0.1`.
