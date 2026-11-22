# Design: conditions on nested arguments

## Problem

Conditions only saw top-level arguments. Tools that take objects
(`{"headers": {"to": ...}}`) couldn't be governed by argument rules at all.

## Approach

- `arg` accepts a list of keys (`["headers", "to"]`). Up to 8 levels; every part must
  match the argument-name pattern. A plain string is always one top-level name.
- Lookup (`engine._lookup`) follows the path: a missing key anywhere is "missing" (deny
  rules apply, allow rules don't); a non-object on the path (text, number, list) makes
  the argument uncheckable and **denies the whole request**. Lists are never searched.
- All value checks (types, path/URL/email tricks, Unicode) are the same code as for
  top-level arguments.
- Schema stays `policy-v1`: `arg` is now "string or list of strings", a superset.

## Compatibility

Argument names could already contain dots, so `"file.name"` means the top-level
argument called `file.name`, and keeps meaning that. A dotted string as a path was
considered and rejected: it would change what old rules mean, and reading a dot both
ways would let an agent send a literal `a.b` key and a nested `a` → `b` side by side,
so Warden and the tool could look at different values. Only the list form looks inside
objects, so every rule has exactly one meaning.

## What it doesn't cover

- Argument lists (`tools`) still only cover top-level names, so unexpected keys inside an
  object aren't refused. `warden check` W013 flags deny rules on nested values.
- No wildcards or list indexing (`recipients[*]`).
