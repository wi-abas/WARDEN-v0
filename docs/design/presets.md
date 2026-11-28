# Design: policy presets, `warden init --preset` (proposal, not built)

## Problem

`warden init` writes one generic starter policy. Most people use Warden in front of a
few well-known kinds of tools (a filesystem MCP server, GitHub, email, Claude Code's own
tools), and each needs the same careful rules: trailing slashes, `host_in` instead of
text, `no_shell_syntax`, argument lists. Small, tested starting points remove the
"blank page" and the classic mistakes.

## Approach

`warden init --preset NAME [--root /abs/project/] [policy.json]`, and `--list`.

- Presets are JSON files in the package (`src/warden/presets/NAME.json`), each with a
  `warden test` file next to it. CI runs `warden check --strict` and `warden test` on
  every preset, so a preset can't ship broken or with warnings.
- `--root` fills a `{root}` placeholder: must be an absolute, clean path (Warden's path
  checks), a trailing `/` is added. Without it, `init` refuses presets that need it.
- After writing, `init` prints what the preset allows, what needs approval, and that
  everything else is denied, so nobody adopts it blind.

First presets (everything not listed is denied):

| Preset | Allow | Require approval |
|---|---|---|
| `filesystem-mcp` (`fs.` prefix) | read/list/search under `{root}` | write/edit/move under `{root}` |
| `github-mcp` (`github.` prefix) | read issues, PRs, files | create/comment; merge, push, delete |
| `email` | — | send, with `to` checked as one plain address; a domain allow list to fill in |
| `claude-code` (needs [the hook](claude-code-hook.md)) | `Read`/`Glob`/`Grep` under `{root}`; `Bash` for `git status`/`git diff`/`git log` with `no_shell_syntax` | `Write`/`Edit` under `{root}`; other `Bash` |

`claude-code` also denies writes to `.claude/`, `.git/hooks/`, `~/.ssh`, `.env` and
Warden's own files, so the agent can't turn its checks off.

## Threat model

Presets protect against common policy mistakes, not against a determined agent with a
too-wide preset: they're starting points, deliberately narrow, and print what they allow.

## What it doesn't cover

- Tool names and arguments differ between server versions; a preset can fall out of
  date (its argument lists then deny new arguments, which fails closed).
- A preset is only as narrow as `{root}`: `--root /` (or a home folder) is refused, the
  same paths `warden check` W023 warns about.
