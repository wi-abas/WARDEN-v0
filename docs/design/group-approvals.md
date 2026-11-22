# Group approvals

## Problem

When an agent queues several similar actions (ten emails to the same team, five file
writes), approving them one by one is tedious. But "approve all" is a classic way to
sneak a bad action past a tired reviewer: one odd action in a list of ten looks like
the other nine. Group approvals let a human decide several approvals in one step
without making it easier to approve something they didn't see.

## Approach

- **Grouping** (`GET /v1/approvals?group=true`): pending approvals grouped by
  `(agent_id, tool)`, groups sorted by agent then tool, items by creation time then id.
  Every item is shown in full, the same shape as the plain list (escaped arguments,
  `warnings`, `action_hash`). There is no summary-only view.
- **Exact ids only** (`POST /v1/approvals/decide`, `{"ids": [...], "approve": bool}`):
  the human names each approval. There is no filter ("everything from agent X"), so an
  approval created after the human looked can't be swept in.
- **All or nothing** (`ApprovalStore.decide_group`): under the store's lock, every id
  is checked first. If any is unknown/expired, not pending, has unknown arguments
  (after a restart), is repeated, or belongs to another agent or tool than the first
  valid id, nothing changes and the answer lists each failing id with a reason (ids
  are pattern-checked, so they are safe to echo; arguments never are).
- **Same per-action binding**: approving N ids is N ordinary approvals: each still
  bound to its own `action_hash` and agent, single use, with a fresh TTL from the
  moment of approval, persisted like single decisions.
- **Audit first, in one transaction**: one `approval_approved`/`approval_denied` event
  per approval (as for single decisions) plus one `approval_group_decided` event
  (count, ids, approve/reject, "by admin") are written in a single SQLite transaction
  before anything changes. If that write fails, nothing is approved (503).
- **State in one transaction**: the new statuses are saved with one database
  transaction (`ApprovalDB.save_many`), then applied in memory. A failed save changes
  nothing.
- **Cap**: 1 to 100 ids (`MAX_GROUP`), else 422.
- **CLI** (`warden approvals list|approve|reject`): talks to the running server
  (local URLs only, like `warden.client`), admin key from `WARDEN_ADMIN_KEY` only.
  It prints every action (JSON with `ensure_ascii`, so no raw control or look-alike
  characters reach the terminal) before asking `Approve these N actions? [y/N]`.

## Decisions (where the brief left room)

- **Only pending approvals** can be decided in a group. A single `/deny` can still
  revoke an approved-but-unused approval; a group reject that includes one fails with
  "already decided". Revoking is a deliberate, one-at-a-time act.
- **Duplicates**: the API model refuses a list with repeated ids (422, like any other
  malformed body, without echoing it). The store refuses them too ("duplicate"), for
  callers that skip the API model.
- **Unknown and expired look the same** ("not found or expired"): expired approvals are
  forgotten, exactly like the single endpoint's 404.
- **Creation time** is new approval state (`created_at`), saved in the approvals table
  (added to old databases with `ALTER TABLE`; old rows get their expiry minus the TTL,
  which is when they were created for pending ones). It only sorts the list.
- **Group failures are audited** as one `approval_decide_failed` event with the count
  of failing ids, through the same per-minute limit as rejected requests, so a flood
  of bad group calls can't fill the disk.
- **Non-SQLite audit logs** (test doubles) get the events one by one; only
  `SQLiteAuditLog` can write them atomically, and that is what `warden serve` uses.
- **The CLI re-reads the list** right before deciding and shows exactly the ids it
  sends. Ids it can't find among the pending approvals are refused locally (exit 1).
- **Exit codes**: 0 done; 1 refused (409/404/401, or the human answered no); 2 usage,
  missing `WARDEN_ADMIN_KEY`, or the server can't be reached.

## Threat model

Protects against:
- An action slipped into a "bulk approve": nothing is approved that wasn't named by id,
  and every named action was shown in full first (CLI) or is in the grouped list.
- Mixing: a group never spans agents or tools, so a dangerous tool can't hide among
  harmless ones.
- Races: a concurrent evaluate, single decision or second group decision either sees
  the group fully applied or not at all.
- Replay: approvals from a group are ordinary single-use approvals.
- Unrecorded decisions: audit first; a failed audit write changes nothing.

Does NOT protect against:
- A human who doesn't read. Showing everything makes a careful review possible, not
  certain.
- A script calling the API directly with ids it never displayed (the admin key holder
  is trusted). `--yes` exists for scripts and skips the prompt.
- Similar-looking actions within one group (same agent and tool, slightly different
  arguments): the human must compare them.
- One shared admin key: the audit log can say "by admin", not which person.
- Audit written but state save failed (disk error between the two): the audit log then
  records a decision that didn't take effect. Same as single decisions; nothing is
  approved in that case, so it fails closed.

## Re-audit findings

(Filled in after the re-audit.)
