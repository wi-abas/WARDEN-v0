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
  they can't reach. `warden audit head` prints a checkpoint (newest id + hash per
  table) as one JSON line; append it to a file kept elsewhere, and
  `warden audit verify --expect FILE` checks the log still contains every checkpoint
  (see "Checkpoints" below).
- **Cutting the tail** (deleting the newest rows) leaves a valid, shorter chain. Again
  only a saved checkpoint shows it.
- Rows deleted by retention are gone; the chain only proves the rest is intact.
- It's evidence, not prevention: Warden doesn't stop anyone from editing the file.

## Checkpoints (`warden audit head` / `verify --expect`)

```sh
uv run warden audit head >> checkpoints.jsonl        # e.g. hourly from cron
scp checkpoints.jsonl backup-host:warden/             # or commit it to another repo
uv run warden audit verify --expect checkpoints.jsonl
```

- `head` refuses to print a checkpoint for a log whose chain is already broken
  (saving it would bless the tampering).
- `verify --expect` first checks the chain, then that each checkpointed row still has
  its saved hash. The intact chain from that row to today proves nothing in between
  changed. It fails on: a different hash (history rewritten), a log that ends before
  the checkpoint (tail cut, or another file), and a checkpointed row that retention
  has since deleted. The last one fails closed on purpose: a rewrite could also be
  disguised as a purge. Use a checkpoint newer than the retention period.
- A checkpoint exactly at a retention anchor stays checkable (the anchor keeps its hash).
- The file is strict: one invalid line refuses the whole file, so a garbled file can't
  pass as "nothing to check". Max 10 MB / 100,000 checkpoints.
- **The checkpoint only helps if the attacker can't change the copy.** Keep it on
  another machine or account, not next to the database.
- Hashes depend only on row contents, not on which database file they're in: two logs
  with identical rows have identical hashes. Fine for detecting edits; it doesn't prove
  which machine a log came from.
