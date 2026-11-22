# Design: persistent approvals

## Problem

Approvals lived in memory only: restarting Warden (crash, upgrade, laptop reboot) dropped
every pending and approved-but-unused approval, so humans had to approve again.

## Approach

- Approval **state** is written to an `approvals` table in the audit database (already
  mode 600 and symlink-protected): id, agent, tool, `action_hash`, status, expiry,
  creation time. Every change is written **before** it takes effect in memory, so a
  failed write changes nothing (fail closed). Loaded at startup; expired rows deleted.
- **Arguments are still never written to disk** (they may contain secrets). After a
  restart an approval's arguments are unknown. They come back when the agent asks again
  with the same action: its `action_hash` must match exactly, so the arguments shown are
  provably the ones the approval is bound to.
- **No blind approvals**: approving an approval whose arguments are unknown is refused
  (409, "arguments not available yet"); denying is always allowed. An approval that was
  already approved before the restart stays approved and can be used once.
- Expiry uses the wall clock (`time.time`) when persistence is on, because the monotonic
  clock restarts with the process. Single-use, TTL, revocation, agent binding and
  `action_hash` binding are unchanged; the check-and-mark-used step persists `used`
  before the allow is returned.

## Threat model

Protects against: losing approvals on restart; replaying an approval across a restart
(the `used` state is on disk first); approving something the human can't see.

## What it doesn't cover

- One Warden process per database. Two processes sharing it would each trust their own
  memory (no cross-process locking of approvals).
- Someone who can edit the database can mark an approval approved (the database file is
  trusted, like the policy file; see the tamper-evident audit log for detection).
- A wall-clock jump forward expires approvals early; backward extends them.
