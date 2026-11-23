# Design: approval hygiene (stale approvals, required `action_hash`)

## Problem

1. **Stale approvals get swept in.** An agent run queues five actions, is abandoned,
   and a new run queues five more. A reviewer runs `warden approvals list --agent X`,
   copies all ten ids and approves them. The five old ones are now approved for 15
   minutes, and the next time any run makes one of those exact calls, it runs without
   anyone having thought about it in the new context.
2. **Single decisions can still be made by id alone.** `POST
   /v1/approvals/{id}/approve` checks `action_hash` only when it's sent (see
   group-approvals.md), so an id pasted from an agent's message can be approved
   without listing what it is. The MCP proxy's hint even suggests exactly that `curl`.

## Approach: stale approvals

- **Default views stay narrow, and that becomes a tested promise**: `GET
  /v1/approvals` and `warden approvals list` show only pending, unexpired approvals.
  Decided and expired ones never appear unless asked for (`?status=rejected` from
  sticky-rejections.md is the only other view).
- **Show age**: each item gets `age_seconds` (from `created_at`, already stored). The
  CLI prints "asked 8 min ago" next to "expires in".
- **`list --max-age MINUTES`**: only approvals younger than that (narrows the view only,
  like `--agent` / `--tool`).
- **Warn when a selection spans runs.** Sort the chosen ids by `created_at`; a gap of
  more than 2 minutes between neighbours splits them into "runs". If there is more than
  one, the CLI prints each run (time range, count) and asks "Approve all 10 actions
  from 2 separate runs? [y/N]". With `--yes` it **refuses** instead, unless
  `--across-runs` is also given: a script shouldn't sweep old runs in silently.
  Rejecting is never blocked (saying no is safe).
- The server stays neutral: "run" is a hint from timing, not a fact, so the API doesn't
  refuse anything based on it.

## Approach: `action_hash` required (breaking, v0.4)

- `POST /v1/approvals/{id}/approve`: body `{"action_hash": ...}` **required**.
- `POST /v1/approvals/{id}/deny` on a **pending** approval: required too. With
  sticky rejections a "no" now lasts, so it should also be a "no" to something seen.
- **Revoke stays bodiless**: `/deny` on an *approved, unused* approval works without a
  body (checked if sent). Revoking must be quick and can only make things stricter.
- `POST /v1/approvals/decide`: `action_hashes` now required for reject too. The CLI
  already sends them, so `warden approvals` is unaffected.
- Missing hash: HTTP 400, "action_hash required: list the approvals and send the
  action_hash you were shown"; nothing changes, nothing echoed. The hash is known even
  after a restart (it's stored), so rejecting a restarted approval still works.

## Migration notes

- Scripts calling `/approve` or `/deny` without a body: list first (`GET
  /v1/approvals`), then send the `action_hash` from that list. Or use `warden approvals
  approve ID`, which does both.
- **MCP proxy hint** becomes "1. `warden approvals list --agent <id>` 2. `warden
  approvals approve <approval id>`" (curl variant with `-d '{"action_hash":
  "<from the list>"}'` in docs/mcp-proxy.md). The hint never prints the hash itself,
  even though the proxy knows it: the point is that the human copies it from the list.
- `examples/agent.py` and `examples/demo.py` print/use bodiless approves: update them.
  `docs/api.md`, CHANGELOG ("Breaking") and SECURITY.md (remove "approving by id alone
  is still possible") updated in the same change.

## Threat model

Protects against: approving actions from an abandoned run by accident; approving an id
without having seen its action; a confused-deputy reviewer pasting an id an agent
chose to show them.

## What it doesn't cover

- A reviewer who lists, doesn't read, and approves anyway (the hash proves the list was
  fetched, not read).
- The 2-minute gap is a heuristic: one slow run can look like two, two quick runs
  like one.
- **Open question for Wissam:** 2 minutes as the run gap, and `--across-runs` as the
  escape hatch, or simply refuse `--yes` whenever any chosen approval is older than N
  minutes?
