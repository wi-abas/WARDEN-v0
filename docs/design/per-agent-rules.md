# Design: per-agent rules

## Problem

Every rule applies to every agent. To give two agents different permissions (the
billing agent may pay, the research agent may only read) you must run one Warden per
agent, each with its own policy. Agent tokens already prove *which* agent asks; rules
can't use that yet.

## Approach

- A rule may list the agents it applies to:
  ```json
  {"id": "billing-pays", "tool": "pay", "effect": "allow",
   "agents": ["billing-agent"], "when": [{"arg": "amount", "op": "lte", "value": 500}]}
  ```
  No `agents` key = every agent (today's behaviour, so old policies keep their meaning).
- **Exact, case-sensitive matching.** Each entry must match `AGENT_ID_PATTERN`; 1 to
  100 entries, no duplicates, an empty list is refused (it would be a rule that never
  applies). No wildcards or prefixes: `billing-*` would silently hand a newly added
  `billing-evil` the same permissions. Case-sensitive because agent ids are
  case-sensitive everywhere else (tokens, limits, approvals).
- **Engine**: `_rule_matches` checks `request.agent_id in rule.agents` next to the tool
  check, before any condition. A per-agent rule is just a rule that matches fewer
  requests, so **most restrictive still wins** across all matching rules: a per-agent
  allow can never override a global deny or require_approval. To give one agent more
  than the others, the stricter rule must itself be limited to the other agents.
- **Identity must be proven.** Without `--agents`, `agent_id` is self-declared, so a
  per-agent allow is free for any local process that types the right name, and a
  per-agent deny is dodged by typing another. Decision: **`warden serve` refuses to
  start** when the policy has any rule with `agents` but no agents file is given
  ("rule 'billing-pays' is per-agent: start with --agents so agent ids are proven").
  Refusing is fail closed and impossible to miss; a warning would be ignored.
- **Names must exist.** With an agents file, `warden serve` also refuses to start if a
  rule names an agent that isn't in it. A typo in a deny rule's `agents`
  (`biling-agent`) would otherwise protect nothing, silently. The same check covers
  `limits.agents`.
- **`warden check`**: optional `--agents FILE`. W014: a rule (or `limits.agents`) names
  an agent not in the file. W015: two agent names differ only in upper/lower case
  (probably one agent written two ways). Without `--agents`, check notes that
  per-agent rules need it at serve time. W003/W004 (dead and duplicate rules) take
  `agents` into account: a global unconditional deny still makes a per-agent allow
  dead; a per-agent deny doesn't kill a global allow.
- **`warden test`**: cases already take `agent_id` (default `policy-test`). Nothing
  new, but per-agent rules need cases with an explicit `agent_id`, for the agent that
  should get the allow and for one that shouldn't. `warden test` trusts the case's id
  (it's offline: no tokens).
- **Schema**: `agents` added to the rule as an optional array, still `policy-v1` (a
  superset). The `action_hash` already contains the agent id; the audit log already
  records `matched_rule`, so a decision by a per-agent rule is traceable.

## Threat model

Protects against: one agent using another agent's permissions; one shared policy being
looser than the least trusted agent needs; spoofing an agent id to reach a per-agent
allow (refused without tokens); a misspelt agent name silently disabling a deny rule.

## What it doesn't cover

- A stolen token is that agent, with all its per-agent permissions.
- No "every agent except X" (`except_agents`): it would make new agents inherit
  permissions without anyone choosing that. List the agents instead.
- No groups or roles of agents; long lists repeat. Can be added later as named sets.
- **Open question for Wissam:** refuse to start (this note) vs a softer engine rule
  "without tokens, per-agent deny rules apply to everyone and per-agent allow rules to
  no one" (fail closed, but surprising). Refusing is simpler to explain.
