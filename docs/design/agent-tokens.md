# Design: per-agent tokens

(The file also holds `server_key`, with which Warden proves itself to the agent. It can
imitate Warden, not an agent: [server-identity.md](server-identity.md).)

## Problem

`agent_id` is self-declared: any local process can claim to be any agent, so per-agent
rules, rate limits and the audit trail can't be trusted, and one agent can use another
agent's approval if it knows the id and the exact action.

## Approach

- An **agents file** (JSON, `--agents FILE` / `WARDEN_AGENTS`) lists each agent's id and
  the **SHA-256 hash** of its token. Warden never stores tokens.
  ```json
  {"agents": [{"id": "billing-agent", "token_sha256": "9f86d0…", "server_key": "4d0306…"}]}
  ```
- `warden agent add <id>` creates a random token (`wdn_` + 256 random bits), stores
  only its hash (file mode 600, written atomically) and prints the token **once**.
  `warden agent list` / `warden agent remove <id>` manage the file.
- Agents send `Authorization: Bearer <token>`. Warden hashes it and compares it with
  **every** stored hash using `secrets.compare_digest` (constant time, no early exit).
- With an agents file, **the agent id comes from the token**. A body `agent_id` is
  optional; if present it must match (else 403). No token or an unknown token: 401 deny.
- Approvals: the approval records the (now authenticated) agent, and using one requires
  the same agent as well as the same `action_hash` (which also contains the agent id).
- SHA-256 rather than a slow password hash: tokens are 256-bit random values, not
  human passwords, so brute force is infeasible and a fast hash is the standard choice.

## Migration path

1. Nothing changes until you pass `--agents`: without it Warden works as before
   (self-declared `agent_id`, with a startup warning).
2. `warden agent add my-agent` for each agent; give each its token
   (`WARDEN_AGENT_TOKEN` for the SDK and the MCP proxy).
3. Restart with `--agents warden-agents.json`. From then on every `/v1/evaluate`
   needs a valid token. Old clients that still send `agent_id` keep working as long as
   it matches their token.

## Threat model

Protects against: a local process impersonating another agent; using another agent's
approval; spoofed agent ids in the audit log; timing attacks on token comparison;
token theft from the agents file (only token hashes on disk; its `server_key`s can imitate
Warden to the agents, not an agent to Warden).

## What it doesn't cover

- A stolen token (from the agent's environment or memory) is that agent.
- Tokens are loaded at startup; changes need a restart. No expiry or rotation schedule.
- Programs running as the same OS user as an agent can usually read its environment.
- The admin key is still one shared secret.
