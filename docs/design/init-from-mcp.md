# Design: `warden init --from-mcp` (proposal, not built)

## Problem

Writing the policy is where people give up: nobody hand-writes rules and argument lists
for an MCP server with 40 tools. The server already describes every tool (`tools/list`:
name, description, `inputSchema` with `properties` and `required`).

## Approach

`warden init --from-mcp [--tool-prefix fs.] [--out policy.json] -- <server command>`:

1. Start the server the way `warden proxy` does (same environment rules: without
   `WARDEN_ADMIN_KEY` / `WARDEN_AGENT_TOKEN`), send `initialize`,
   `notifications/initialized`, then `tools/list` (following `nextCursor`), and stop it.
   Overall timeout (30 s) and caps (500 tools, 1 MiB of answers); any problem: exit 2,
   nothing written.
2. For each tool, write:
   - an argument list in `tools`: `properties` keys as `arguments`, `required` as
     `required`. Unknown arguments are then denied (closes W001 for every tool).
   - **one `require_approval` rule** (`"id": "<prefix><name>"`). Never `allow`: what is
     safe to allow is the operator's decision, and a server's description is not a
     reason to trust it. The operator then turns the reviewed ones into allow rules.
3. Write `policy-tests.json` with one case per tool expecting `require_approval`, with
   placeholder values for required arguments by their schema type (text `"example"`,
   number `0`, boolean `false`), so `warden test` passes out of the box and grows with
   the policy.
4. Print a summary: tools written, tools skipped (and why), arguments that look like
   paths (`path`, `file`, `dir`, ...) or URLs (`url`, `uri`) with a hint
   (`startswith "/project/"` + trailing `/`, or `host_in`).
5. Refuse to overwrite existing files. `warden check --strict` must pass on the result.

## Threat model (the server's answers are untrusted input)

- Tool names that Warden's tool-name pattern refuses are skipped and listed (they'd be
  denied anyway); same for argument names the argument-name pattern refuses (that tool
  gets no argument list, and the summary says so).
- Descriptions are never written into the policy or the tests. Names are only written
  JSON-encoded, after the pattern check. Sizes are capped.
- Generating a policy runs the server once: that's the same trust as running it behind
  the proxy, so the same pin warnings apply ([mcp-proxy.md](../mcp-proxy.md)).

## What it doesn't cover

- It can't know which calls are safe: every rule starts as `require_approval`.
- Argument types (string, number, enum) aren't enforced yet: tool argument lists only
  hold names. The schema's types are a good input for that later roadmap item.
- **Tool changes after generation** ("rug pull": a server that changes a tool's schema
  later): a follow-up could store the `tools/list` hash next to the policy and have the
  proxy warn or refuse when it changes.
