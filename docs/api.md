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
| `GET /v1/approvals` | Admin: pending, unexpired approvals, with their arguments and age, as a JSON list. |
| `POST /v1/approvals/{id}/approve` | Admin: approve one (once). Body `{"action_hash": ...}` required. |
| `POST /v1/approvals/{id}/deny` | Admin: deny one (once). Body `{"action_hash": ...}` required for a pending approval; revoking an approved one needs no body. |
| `GET /v1/approvals?group=true` | Admin: the same, grouped by agent and tool: `{"groups": [...]}`. |
| `GET /v1/approvals?ids=A,B&agent_id=X&tool=Y` | Admin: only those approvals (any filter can be left out; up to 100 ids). Narrows what is shown, never what is decided. |
| `GET /v1/approvals?max_age_seconds=N` | Admin: only approvals asked for at most N seconds ago (1 to 604800). Pending only. |
| `POST /v1/approvals/decide` | Admin: approve or reject several by id, all or nothing. |
| `GET /v1/approvals?status=rejected` | Admin: rejections that still stand (no arguments). Takes the same `ids`/`agent_id`/`tool` filters; not `group`. |
| `POST /v1/approvals/{id}/lift` | Admin: lift a rejection, so the agent may ask for that action again. |

## Approvals

1. The agent asks. A rule says `require_approval`, and the response includes an `approval_id`.
2. You look at what's waiting and approve it. Admin calls need the key Warden prints in
   the terminal at startup (a new one every start):
   ```sh
   curl -s http://127.0.0.1:8000/v1/approvals -H 'X-Warden-Admin-Key: <key>'
   curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/approve -H 'X-Warden-Admin-Key: <key>' \
     -H 'content-type: application/json' -d '{"action_hash": "<action_hash from the list>"}'
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

Plain `GET /v1/approvals` answers with a **list**, one item per pending approval. It
only ever shows **pending, unexpired** approvals: approved, rejected, used and expired
ones never appear (`?status=rejected` is the only other view), so an old decision can't
be swept into a new one. `age_seconds` is how long ago the agent asked:

```json
[{"approval_id": "JSr4DnD0vXhHMGkgs8llrFvinrli1d1a", "agent_id": "agent-1", "tool": "write_file",
  "arguments": {"path": "/workspace/a.txt", "content": "hi"}, "warnings": [],
  "action_hash": "dc3a4297...", "expires_in_seconds": 899, "age_seconds": 1}]
```

With `?group=true` the same items come wrapped in an **object**, `{"groups": [...]}`, one
group per agent and tool (see [Several at once](#several-at-once-group-approvals)).
Nothing pending: `[]` or `{"groups": []}`.

The body `{"action_hash": "..."}` is **required** (since v0.4) on `/approve`, and on
`/deny` of a pending approval: it must be the approval's `action_hash` from the list
(409 "action_hash doesn't match this approval" otherwise), which proves you listed it
first. Without it: 422 `{"error": "action_hash required: list the approvals and send the
action_hash you were shown"}` and nothing changes. **Revoking** an approved, unused
approval with `/deny` works with no body (or `{}`): revoking can only make things
stricter, so it stays quick; a sent `action_hash` is still checked. After a restart the
hash is still known (it is stored), so a restarted approval can still be rejected.

In `GET /v1/approvals`, hidden or look-alike characters in arguments (zero-width spaces,
right-to-left overrides, full-width letters) are shown as visible `\uXXXX` escapes and
the item gets a `warnings` entry, so an agent can't make you approve something that
*looks* different from what it is. The approval is still bound to the real action.

### Several at once (group approvals)

When an agent queues several similar actions, you can decide them together. This is
built so that you can't approve something you didn't see:

```sh
export WARDEN_ADMIN_KEY=<key>
uv run warden approvals list --group          # every pending action, in full
uv run warden approvals approve ID1 ID2 ID3   # shows them again, then asks [y/N]
uv run warden approvals reject ID1 ID2        # same, for "no"
```

The CLI fetches the named approvals again, prints every action in full (non-ASCII and
control characters escaped) and asks `Approve these 3 actions? [y/N]`; `--yes` skips
the question for scripts. Exit codes: 0 done, 1 refused or answered no, 2 usage error,
missing `WARDEN_ADMIN_KEY` (never accepted as a flag) or Warden unreachable.

If an agent floods the queue, `list --agent A --tool T` shows only that agent and tool,
and `approve`/`reject` keep working: they fetch only the ids you name. `list --max-age
MINUTES` shows only approvals asked for in the last MINUTES. Each item shows "asked
8 min ago" next to "expires in".

**Separate runs.** If the ids you approve were asked for more than 2 minutes apart
(sorted by age, a gap between neighbours), they probably come from separate agent runs,
maybe an abandoned one. The CLI prints each run (count, time range) and asks `Approve all
10 actions from 2 separate runs? [y/N]`. With `--yes` it **refuses** (exit 1, nothing
changed) unless you also pass `--across-runs`. Rejecting is never blocked. This is a
timing hint, not a fact: the server doesn't refuse anything based on it.

Over HTTP:

```sh
curl -s 'http://127.0.0.1:8000/v1/approvals?group=true' -H 'X-Warden-Admin-Key: <key>'
```
```json
{"groups": [{"agent_id": "mail-bot", "tool": "send_email", "count": 2, "approvals": [
  {"approval_id": "Qd3...", "agent_id": "mail-bot", "tool": "send_email",
   "arguments": {"to": "ann@example.com"}, "warnings": [], "action_hash": "9f2...",
   "expires_in_seconds": 812, "age_seconds": 88},
  {"approval_id": "Zk8...", "...": "..."}]}]}
```

```sh
curl -s -X POST http://127.0.0.1:8000/v1/approvals/decide -H 'X-Warden-Admin-Key: <key>' \
  -H 'content-type: application/json' \
  -d '{"ids": ["Qd3...", "Zk8..."], "action_hashes": ["9f2...", "41c..."], "approve": true}'
```
```json
{"status": "approved", "count": 2, "results": [
  {"approval_id": "Qd3...", "status": "approved"}, {"approval_id": "Zk8...", "status": "approved"}]}
```

Rules:
- **Approve what you saw**: approving needs `action_hashes`, the `action_hash` the list
  showed for each id, in the same order (422 without them). A hash that doesn't match its
  id refuses the whole group (409, "list the approvals again"), so ids copied from an
  agent's message or an old list can't be approved without listing. Since v0.4
  rejecting needs them too (422 "action_hashes required: ..." without them): with
  sticky rejections a "no" lasts, so it should be a "no" to something seen. The CLI
  sends them for you.
- **Exact ids only**, 1 to 100, no repeats (else 422). There is no "approve everything
  from agent X": an approval that arrives after you looked is never included.
- **One agent and one tool** per decision. A group never mixes them.
- **All or nothing.** If any id is unknown or expired, already decided (approved, used,
  denied or revoked), from another agent or tool, or has no arguments yet after a
  restart, nothing changes and you get 409:
  ```json
  {"error": "nothing changed: some approvals can't be decided",
   "failed": [{"id": "Zk8...", "reason": "already decided"}]}
  ```
- **Each approval stays separate**: single use, bound to its own action and agent, a
  fresh 15-minute window from the moment of approval. Revoking one approved approval
  is still done one at a time with `/deny`.
- **Audit**: one `approval_approved`/`approval_denied` event per approval plus one
  `approval_group_decided` event (count and ids), all written in one transaction before
  anything changes. If that write fails: 503, nothing changed.

## Sticky rejections

When a human rejects a pending approval (or revokes an approved one, singly or in a
group), "no" sticks: for the agent's `rejection_window_seconds` (policy `limits`,
default 900, `0` = off, see [policies.md](policies.md)), the same agent asking for the
same action (same `action_hash`) gets

```json
{"decision": "deny", "reason": "rejected by a human; this exact action is refused until 2026-11-23 14:32:05 UTC (approval Qd3...)",
 "matched_rule": "email-needs-approval", "action_hash": "9f2...", "approval_id": null}
```

instead of a new pending approval. A different action (one character changed in the
arguments) is a new approval as usual. Rejections don't count toward the pending quota.

```sh
uv run warden approvals list --rejected       # rejections that still stand
uv run warden approvals lift ID               # shows it, asks [y/N]; --yes for scripts
```
```sh
curl -s 'http://127.0.0.1:8000/v1/approvals?status=rejected' -H 'X-Warden-Admin-Key: <key>'
```
```json
[{"approval_id": "Qd3...", "agent_id": "mail-bot", "tool": "send_email", "action_hash": "9f2...",
  "rejected_at": "2026-11-23T14:17:05Z", "expires_in_seconds": 812}]
```
```sh
curl -s -X POST http://127.0.0.1:8000/v1/approvals/<approval_id>/lift -H 'X-Warden-Admin-Key: <key>'
```
```json
{"approval_id": "Qd3...", "status": "lifted"}
```

Lifting deletes the rejection; it doesn't approve anything. The agent's next request is
an ordinary pending approval that a human must approve after seeing it. Unknown or
expired: 404; not a rejection (pending, approved, used): 409. The lift is audited
(`approval_rejection_lifted`) **before** it takes effect: if that write fails, 503 and
the rejection stands. Rejections are kept in the approvals table (no arguments), so they
survive a restart.

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

**Tokens are identity; per-agent rules are permissions.** A rule with
`"agents": ["billing-agent"]` applies only to that agent (see
[Per-agent rules](policies.md#per-agent-rules)). Such rules need `--agents`: without it,
`warden serve` refuses to start.

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

### How clients find Warden

The settings above are for the **server** (`warden serve`). Clients don't read them: if
you start Warden on another port (`--port 8790` or `WARDEN_PORT`), tell each client the
new URL too. `warden approvals` doesn't see `WARDEN_PORT` and keeps trying `:8000`.

| Client | Where it gets the URL (first one set wins) | Default |
|---|---|---|
| `warden approvals` | `--warden-url URL`, then `WARDEN_URL` | `http://127.0.0.1:8000` |
| SDK `@guard` / `run_guarded` **without** `client=` | `WARDEN_URL` (also `WARDEN_AGENT_ID`, `WARDEN_AGENT_TOKEN`), read at call time | `http://127.0.0.1:8000`, agent `agent` |
| SDK `WardenClient(...)` you create yourself | its `url=` argument only (**not** `WARDEN_URL`) | `http://127.0.0.1:8000` |
| `warden proxy` | `--warden-url URL`, then `warden_url` in the `--config` file, then `WARDEN_URL` | `http://127.0.0.1:8000` |
| Your own HTTP code | whatever URL you wrote | |

`warden limits`, `warden check`, `warden test` and `warden audit` don't talk to the server
at all; they read files.

So, for Warden on port 8790:

```sh
uv run warden serve --port 8790
export WARDEN_URL=http://127.0.0.1:8790        # warden approvals, warden proxy, default SDK clients
uv run warden approvals list --group           # or: --warden-url http://127.0.0.1:8790
uv run warden proxy -- COMMAND [ARGS...]       # a warden_url in its config file still wins
```
```python
warden = WardenClient(url="http://127.0.0.1:8790", agent_id="billing-agent")
```

A client URL must be `http://` with host `127.0.0.1`, `localhost` or `::1` and an explicit
port, and nothing else (no path, user, query or fragment). Anything else is refused:
`warden approvals` and `warden proxy` exit with code 2, and the SDK raises
`ClientConfigError` instead of calling Warden. Clients also ignore `HTTP_PROXY` settings,
so tool arguments and the admin key never go to a proxy.
