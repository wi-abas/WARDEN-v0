# Design: per-agent rate limits and quotas

## Problem

Any agent (or any local process, without tokens) can flood Warden: fill the global
approval queue (1,000 pending) so other agents' approvals are refused, or grow the audit
database without bound inside the retention window.

## Approach

- An optional `limits` section in the policy file (trusted config, reviewed with the
  rules, checked by `warden check` and the schema):
  ```json
  "limits": {
    "default": { "requests_per_minute": 1200, "max_pending_approvals": 100 },
    "agents": { "billing-agent": { "requests_per_minute": 30, "max_pending_approvals": 5 } }
  }
  ```
  Per-agent values win, then `default`, then built-in defaults (1,200 per minute,
  100 pending; raised from 600 / 50, which a busy agent could hit).
  `warden limits` shows and changes them. Without a `limits` section the built-in defaults apply.
- **Requests per minute**: a token bucket per agent (capacity = the per-minute limit,
  refilled continuously). Deterministic: a monotonic clock, injectable in tests; no
  randomness. Every `/v1/evaluate` call counts, approval polls included. Over the limit:
  HTTP 429, `"decision": "deny"`, `Retry-After` header, recorded as a rejected request
  (whose recording is itself capped, so a flood can't fill the disk).
- **Refused requests** (422 or 400 invalid, 403 wrong `agent_id`) count only when a valid agent
  token proves whose they are. A self-declared `agent_id` is never charged for them, so a
  caller can't burn another agent's budget with junk. Bodies refused by size or framing
  (411, 413) are not charged: they are refused before anything is read.
- **Pending approvals per agent**: checked inside the approval store's lock, so racing
  requests can't overshoot. Over the quota: `deny`, "too many pending approvals for this
  agent". The global cap (1,000) still applies.
- Memory: at most 10,000 agents are tracked; idle (full) buckets are dropped first; if
  that isn't enough, unknown agents are denied (fail closed).

## Threat model

Protects against one agent starving others of approvals, approval-queue flooding, and
unbounded audit growth from one agent.

## What it doesn't cover

- **Without agent tokens, limits can be dodged** by inventing new `agent_id`s (each gets
  its own bucket, up to the 10,000-agent cap). Use `--agents`.
- Limits are per Warden process and reset on restart.
- Rejected requests are still parsed before the limit is checked (bodies are capped at
  64 KB). This is not protection against a network-level flood.
