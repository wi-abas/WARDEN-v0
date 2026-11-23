# Design: sticky rejections

## Problem

When a human rejects an approval, the agent can ask for the exact same action again
and immediately gets a **new** pending approval (`ApprovalStore.request` only reuses
pending or approved ones). A looping agent nags the reviewer with the same action until
someone approves it by mistake or out of fatigue: "no" doesn't stick.

## Approach

- When a human rejects a pending approval (or revokes an approved one), the approval
  row stays as a **rejection** for a window: `expires_at = now + rejection window`
  (today it keeps the rest of its original 15 minutes).
- In `request()`, before reusing or creating anything: if a `denied` approval with the
  same `action_hash` exists and hasn't expired, raise `Rejected`. `apply_approval`
  turns that into `deny`, reason "rejected by a human; this exact action is refused
  until 14:32 (approval <id>)". No arguments in the reason, as always. The
  `action_hash` already contains the agent id, so this only affects the same agent
  asking for the same tool with the same arguments.
- **Window**: `rejection_window_seconds` in the policy's `limits` (default and per
  agent, like the other limits; reviewed with the rules and checked by `warden check`
  and the schema). Default 900 s (the approval TTL), 0 = off (today's behaviour), max
  7 days.
- **Persisted like approval state**: it *is* the existing `approvals` row (id, agent,
  tool, `action_hash`, status `denied`, expiry). No new table, no arguments on disk.
  With a database a rejection survives a restart; without one it's lost on restart,
  like every approval.
- **Lifting a rejection** (a human rejected by mistake): `POST
  /v1/approvals/{id}/lift` (admin key) / `warden approvals lift ID`. It deletes the
  rejection, audited **before** it takes effect (`approval_rejection_lifted`), like
  every human decision. No `action_hash` needed: lifting only lets the agent *ask*
  again; the new request is an ordinary pending approval that a human must approve
  after seeing it. `GET /v1/approvals?status=rejected` lists active rejections (id,
  agent, tool, `action_hash`, rejected time, time left).

## Interactions

- **Group decisions**: a group reject makes each approval sticky, exactly as N single
  rejects. Each stays bound to its own `action_hash`.
- **Quotas**: rejections don't count toward the pending quota (only pending ones do).
  They can only be created by a human with the admin key, so an agent can't flood
  them; the store keeps them in memory until they expire.
- **Rate limits** apply first, as for every request. A refused re-ask is a normal
  audited `deny` (with `matched_rule`).
- **Retrying with the old `approval_id`** already answers "denied by a human"; now
  that lasts for the whole window instead of the rest of the original TTL.
- **Restart**: expiry uses the wall clock when persisted (same caveats as
  persistent approvals).

## Threat model

Protects against: approval fatigue from an agent re-asking a rejected action; a
rejected action being approved later by a different, less careful reviewer within the
window.

## What it doesn't cover

- **Exact action only.** Changing one character in the arguments (or, without tokens,
  the agent id) gives a new `action_hash` and a new approval. Warden can't tell
  "similar" actions apart without judging meaning, which it never does. Per-agent
  quotas and rate limits bound how often this can happen.
- No "reject this kind of action forever": change the policy for that.
- **Decided:** a revoke (deny of an already approved approval) is sticky too ("no" is
  "no").
