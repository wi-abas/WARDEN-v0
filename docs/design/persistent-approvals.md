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

## Several servers on one database

Each server used to trust its own memory, so two servers could each use the same
approval. Now the database is the truth:

- Every operation reads the rows again first, so a decision made through one server
  holds on all of them. Arguments stay in the memory of the server that was asked;
  elsewhere the approval can be denied but not approved (no blind approvals).
- Every row has a `revision`. A change (use, restore, approve, reject, revoke) is one
  `UPDATE ... WHERE approval_id = ? AND revision = ?`: of two racing changes exactly one
  is written, the other changes nothing. A lost `use` is never an allow. A lost human
  decision is a 503 "nothing changed", and the audit log says it was not applied. A group
  decision is one transaction: all of it or nothing.
- A new approval is inserted only if no pending or approved row for the same action
  exists, so two servers asked at once hand out the same approval.
- A locked or failing database raises, which the API turns into a deny.

Chosen over an exclusive lock because it is small, needs no lock file that could stay
behind after a crash, and leaves `warden audit verify` and other readers alone.

## Threat model

Protects against: losing approvals on restart; replaying an approval across a restart
(the `used` state is on disk first); approving something the human can't see.

## What it doesn't cover

- Servers sharing a database (above): pending quotas can be overshot by a few when both
  create approvals for different actions at the same moment; rate limits and arguments
  are per server.
- Someone who can edit the database can mark an approval approved (the database file is
  trusted, like the policy file; see the tamper-evident audit log for detection).
- A wall-clock jump forward expires approvals early; backward extends them.
