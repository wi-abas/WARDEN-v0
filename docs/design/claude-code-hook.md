# Design: `warden hook` for Claude Code (proposal, not built)

## Problem

The MCP proxy only sees MCP tools. Claude Code's own tools (`Bash`, `Write`, `Edit`,
`Read`, `WebFetch`, ...) never pass through Warden. Claude Code can run a command before
every tool call (a `PreToolUse` hook) and block the call by the hook's exit code, so
Warden can check those too, without changing Claude Code.

## Approach

Three commands:

- `warden hook run`: the hook itself. Reads Claude Code's JSON from stdin (`tool_name`,
  `tool_input`), asks Warden through the normal client (agent token from
  `WARDEN_AGENT_TOKEN`, so the server identity proof is used), and:
  - `allow` → exit 0 **with no output**, so Claude Code's own permission prompts still
    apply (two locks, not one). It never prints a `permissionDecision: "allow"`, which
    would skip them.
  - everything else → exit **2** with the reason on stderr (Claude Code shows it to the
    model and blocks the call): `deny`, `require_approval`, Warden unreachable or not
    proven, invalid stdin, any exception. The whole `main` is wrapped so every failure
    path exits 2: an uncaught Python error exits 1, and **1 doesn't block**.
  - `require_approval`: default "error" mode, like the proxy: block, print the approval
    id and the `warden approvals approve ...` command; the model retries after a human
    approves. Optional "wait" mode polls within the hook's timeout. It never maps to
    Claude Code's own "ask" prompt: that approval wouldn't be bound to the action in
    Warden or recorded in its audit log.
- `warden hook install [--scope user|project|local]`: adds
  `{"matcher": "*", "hooks": [{"type": "command", "command": "warden hook run"}]}` to
  `hooks.PreToolUse` in the matching settings file. Refuses a file that isn't valid JSON,
  writes atomically (temp file + rename) with a backup, finds its own entry by the exact
  command so running it twice adds nothing.
- `warden hook status` / `uninstall`: report or remove that entry.

Tool names arrive as Claude Code spells them (`Bash`, `Write`, `mcp__github__create_issue`),
which Warden's tool-name pattern accepts, case-sensitively. The arguments are `tool_input`
as given. A preset (see [presets.md](presets.md)) would ship rules for the built-in tools.

## Threat model

- The model proposes a tool call Warden's policy doesn't allow → blocked before it runs.
- Warden down, an impostor on the port, broken input → blocked (exit 2).
- **The model turning the hook off:** a project's `.claude/settings.json` is a file the
  agent can edit. Install in the user scope (`~/.claude/settings.json`, merged with the
  project's), and have the policy deny `Write`/`Edit` to `.claude/` folders and to
  Warden's own files. `Bash` can still edit anything unless `Bash` is limited too.

## What it doesn't cover

- **If the hook command itself can't start** (`warden` not on `PATH`, a broken
  environment), the shell exits 127, which Claude Code doesn't treat as a block: the
  tool runs. Hooks fail open at that level, and only Claude Code can change that.
  Mitigation: `warden hook status --check` in CI or a shell profile, and Claude Code's own
  `permissions.deny` for the most dangerous tools.
- Hooks are a Claude Code feature: other agents need the SDK, the proxy, or their own
  equivalent.
- What a `Bash` command does is only as checkable as the policy makes it (see
  [no-shell-syntax.md](no-shell-syntax.md)).
