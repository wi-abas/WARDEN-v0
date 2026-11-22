# Design: tamper-evident audit log

## Problem

The audit log is a plain SQLite file. Anyone who can edit it can change or delete
history (e.g. turn a `deny` into an `allow`, or remove the record of an action) and
nothing would show it.

## Approach

- Each table (`decisions`, `events`) is a **hash chain**. Every row stores `prev_hash`
  (the previous row's hash) and `row_hash` = SHA-256 over a version label, the table
  name, the row id, `prev_hash` and every value in the row. The first row points to a
  genesis value (64 zeros).
- Writers take SQLite's write lock (`BEGIN IMMEDIATE`) before reading the chain head, so
  concurrent writers (threads, the background event worker) can't fork the chain.
- **Retention** deletes only a *prefix* of each table (rows before the first row that is
  still within the retention window), so what remains is an unbroken chain. The hash of
  the last deleted row becomes that table's **anchor** (`audit_anchors` table) and is
  also written into the `audit_purged` event (`chain_anchor`), which is itself chained.
- `warden audit verify` recomputes everything (read-only) and reports the **first
  broken row** of each table, anchors that don't match the last purge, and prints each
  table's newest hash.
- Databases from before the chain: new columns are added at startup; old rows have no
  hashes and are reported as "from before the hash chain". An unchained row *after*
  chained ones is reported as broken.

## Threat model

Detects: editing any field of a row, deleting or inserting rows in the middle,
reordering, editing anchors to hide extra deletions, unchained rows added later.

## What it doesn't cover

- **A full rewrite.** Without a secret key, someone with write access can recompute
  every hash after their edit. Detecting that needs the newest hash kept somewhere
  they can't reach: `verify` prints it; copy it elsewhere (a ticket, another machine).
- **Cutting the tail** (deleting the newest rows) leaves a valid, shorter chain. Again
  only a saved copy of the newest hash shows it.
- Rows deleted by retention are gone; the chain only proves the rest is intact.
- It's evidence, not prevention: Warden doesn't stop anyone from editing the file.
