# Design: a keyed action_hash

## Problem

The `action_hash` was a plain SHA-256 of `{agent_id, tool, arguments}`. It is stored in
every audit row and in the approvals table, and the audit log promised it identifies an
action "without revealing it". That only holds when the arguments are hard to guess.
Amounts, recipients and file paths usually aren't: anyone with a copy of the database can
hash every likely value and compare. A review recovered `amount=48213` from a stored hash
in 0.3 seconds. So arguments that are "never stored" could be read back from a backup.

## Approach

- The server's `action_hash` is now `HMAC-SHA256(key, "warden-action-v1\n" + canonical
  JSON)`. Without the key, guessing a value means guessing the 256-bit key too.
- The key is 32 random bytes, stored as hex in its own file next to the database:
  `<audit-db>.hash-key` (for example `warden-audit.db.hash-key`). Created on first start
  with mode 0600 (`O_EXCL`, never through a symlink); later starts read it. It must stay
  the same across restarts, or stored approvals stop matching (they fail closed: deny).
- On POSIX, `serve` refuses to start if the key file is readable or writable by other
  users, is a symlink, or doesn't hold exactly 64 hex characters. It never silently
  makes a new key over a broken one: that would quietly orphan every pending approval.
- Several servers sharing one database derive the same key path, so they share the key.
- `create_app()` without a key (tests, embedding) uses a random key for that process.
- `fingerprint(request)` without a key still returns the plain SHA-256. It is used only
  where nothing is stored: `warden test`, and library users calling `engine.evaluate`
  directly. The server always passes its key.

## Threat model

Protects against: recovering tool arguments from a copy of the audit/approvals database
(a backup, a synced folder, a support bundle) that doesn't include the key file.

## What it doesn't cover

- Someone with both the database AND the key file can still guess arguments the old way.
  A backup of the whole folder includes both: back up the database alone, or exclude
  `*.hash-key`.
- Anyone who can read files as the Warden user can read the key (same as the database).
- The agent still gets the hash of its own action in the answer. It already knows the
  arguments, and without the key it can't compute hashes for other actions.
- Old databases: rows written before this change keep their plain hashes, and approvals
  pending from before it no longer match (deny; ask again).
