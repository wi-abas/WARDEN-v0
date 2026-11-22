# Design: conditions on nested arguments

## Problem

Conditions only saw top-level arguments. Tools that take objects
(`{"headers": {"to": ...}}`) couldn't be governed by argument rules at all.

## Approach

- `arg` accepts a dotted path (`"headers.to"`) or a list of keys (`["headers", "to"]`).
  Up to 8 levels; every part must match the argument-name pattern.
- Lookup (`engine._lookup`) follows the path: a missing key anywhere is "missing" (deny
  rules apply, allow rules don't); a non-object on the path (text, number, list) makes
  the argument uncheckable and **denies the whole request**. Lists are never searched.
- All value checks (types, path/URL/email tricks, Unicode) are the same code as for
  top-level arguments.
- Schema stays `policy-v1`: `arg` is now "string or list of strings", a superset.

## Compatibility

Argument names could already contain dots, so `"file.name"` used to mean a top-level key.
It now means `file` → `name`. For such old rules the path is missing in requests that
use the literal key, which can only make the answer stricter (tested). The list form
`["file.name"]` reaches the literal key.

## What it doesn't cover

- Argument lists (`tools`) still only cover top-level names, so unexpected keys inside an
  object aren't refused. `warden check` W013 flags deny rules on nested values.
- No wildcards or list indexing (`recipients[*]`).
