"""Human approvals for actions that a rule marked `require_approval`.

The flow:
1. Agent asks; a rule says require_approval. Warden creates a PENDING approval,
   bound to the action's fingerprint (action_hash), and returns its approval_id.
2. A human lists pending approvals (with the arguments, so they can see what they
   are approving) and approves or denies one. Each can be decided only once.
3. Agent retries the SAME action with the approval_id. Warden allows it only if:
   the approval is APPROVED, the fingerprint matches exactly, it was never used
   before, and it hasn't expired. The check-and-mark-used step is a single locked
   operation, so two simultaneous retries can't both succeed.

Arguments may contain secrets, and they must be shown to the human, so they are
never written to disk. With an ApprovalDB, approval STATE (id, agent, tool,
action_hash, status, expiry) survives a restart; arguments come back when the agent
asks again with the same action, and until then the approval can't be approved
(see docs/design/persistent-approvals.md). Without one, a restart drops everything.

Sticky rejections (docs/design/sticky-rejections.md): when a human rejects (or revokes)
an approval, the row stays as a REJECTION for the agent's rejection window. While it
lasts, the same agent asking for the same action (same action_hash) is denied instead
of getting a new pending approval, so "no" sticks. An admin can lift it.
"""

import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from pydantic import JsonValue

from warden.limits import DEFAULT_REJECTION_WINDOW_SECONDS
from warden.models import ActionRequest, Decision, EvaluationResult

APPROVAL_TTL_SECONDS = 15 * 60
MAX_PENDING = 1000
MAX_GROUP = 100  # most approvals one group decision may name


class Status(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    USED = "used"


@dataclass
class Approval:
    approval_id: str
    agent_id: str
    tool: str
    # None = unknown: loaded after a restart, before the agent asked again.
    arguments: dict[str, JsonValue] | None
    action_hash: str
    expires_at: float  # seconds on the store's clock
    status: Status = Status.PENDING
    created_at: float = 0.0  # store's clock; only used to sort lists
    decided_at: float | None = None  # store's clock; when a human last decided it
    revision: int = 0  # goes up with every saved change; 0 = not saved yet
    # Memory only: the revision this server's own use() gave it. restore() may only undo
    # exactly that use; any newer change (or a human's "no") wins.
    used_revision: int | None = None


class DecideError(Exception):
    """Approve/deny failed. `not_found` = unknown or expired; `no_arguments` = can't
    approve what the human can't see yet; `hash_mismatch` = the human looked at a
    different action than this id's; `hash_required` = no action_hash was sent where
    one is required; else already decided."""

    def __init__(
        self,
        not_found: bool,
        no_arguments: bool = False,
        hash_mismatch: bool = False,
        hash_required: bool = False,
    ) -> None:
        super().__init__(
            "not found"
            if not_found
            else "arguments unknown"
            if no_arguments
            else "action_hash mismatch"
            if hash_mismatch
            else "action_hash required"
            if hash_required
            else "decided"
        )
        self.not_found = not_found
        self.no_arguments = no_arguments
        self.hash_mismatch = hash_mismatch
        self.hash_required = hash_required


class StaleApproval(Exception):
    """Another Warden server changed the approval between our check and our write.
    Nothing was written (fail closed)."""


class GroupReason(StrEnum):
    """Why one id in a group decision was refused."""

    NOT_FOUND = "not found or expired"
    DECIDED = "already decided"
    NO_ARGUMENTS = "arguments not available yet (Warden restarted)"
    DUPLICATE = "listed more than once"
    MIXED = "different agent or tool than the rest of the group"
    HASH_MISMATCH = "action_hash doesn't match this approval (list the approvals again)"


class GroupDecideError(Exception):
    """A group decision was refused as a whole: nothing changed. `failed` lists each
    refused id with its reason (ids only, never arguments)."""

    def __init__(self, failed: list[tuple[str, GroupReason]]) -> None:
        super().__init__(f"{len(failed)} approvals refused")
        self.failed = failed


_APPROVALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id  TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    tool         TEXT NOT NULL,
    action_hash  TEXT NOT NULL,
    status       TEXT NOT NULL,
    expires_at   REAL NOT NULL,
    created_at   REAL,
    decided_at   REAL,
    revision     INTEGER NOT NULL DEFAULT 1
)
"""


class ApprovalDB:
    """Approval state in SQLite (no arguments, ever). Usually the audit database file,
    which is already private (600) and never a symlink.

    Several servers may share it: a change is written only if the row still has the
    revision the server last saw, so exactly one of two racing changes wins."""

    def __init__(self, path: Path) -> None:
        if path.is_symlink():
            raise ValueError(f"approvals database {path} is a symlink; refusing to use it")
        if not path.exists():
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        self.path = path
        with closing(self._connect()) as conn, conn:
            conn.execute(_APPROVALS_SCHEMA)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(approvals)")}
            if "created_at" not in columns:  # a database from before group approvals
                conn.execute("ALTER TABLE approvals ADD COLUMN created_at REAL")
            if "decided_at" not in columns:  # a database from before sticky rejections
                conn.execute("ALTER TABLE approvals ADD COLUMN decided_at REAL")
            if "revision" not in columns:  # a database from before shared databases
                conn.execute("ALTER TABLE approvals ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def delete_expired(self, now: float) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM approvals WHERE expires_at <= ?", (now,))

    def read(self, ttl: float) -> list[Approval]:
        """Every approval, oldest expiry first. Arguments unknown (None). Rows from
        before `created_at` existed count as created `ttl` before expiry."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT approval_id, agent_id, tool, action_hash, status, expires_at, "
                "created_at, decided_at, revision FROM approvals ORDER BY expires_at"
            ).fetchall()
        return [
            Approval(
                approval_id=r[0],
                agent_id=r[1],
                tool=r[2],
                arguments=None,
                action_hash=r[3],
                expires_at=r[5],
                status=Status(r[4]),
                created_at=r[6] if r[6] is not None else r[5] - ttl,
                decided_at=r[7],
                revision=r[8],
            )
            for r in rows
        ]

    def save(self, approval: Approval) -> None:
        self.save_many([approval])

    def save_many(self, approvals: Sequence[Approval]) -> None:
        """Save all of them in ONE transaction: all are written, or none.

        Each must still have the revision it was read with (0: it is new, and no other
        pending or approved row is for the same action). If not: StaleApproval."""
        with closing(self._connect()) as conn, conn:
            for a in approvals:
                if a.revision == 0:
                    cursor = conn.execute(
                        "INSERT INTO approvals (approval_id, agent_id, tool, action_hash, "
                        "status, expires_at, created_at, decided_at, revision) "
                        "SELECT ?, ?, ?, ?, ?, ?, ?, ?, 1 WHERE NOT EXISTS ("
                        "SELECT 1 FROM approvals WHERE action_hash = ? "
                        "AND status IN ('pending', 'approved') AND expires_at > ?)",
                        (
                            a.approval_id,
                            a.agent_id,
                            a.tool,
                            a.action_hash,
                            a.status.value,
                            a.expires_at,
                            a.created_at,
                            a.decided_at,
                            a.action_hash,
                            a.created_at,
                        ),
                    )
                else:
                    cursor = conn.execute(
                        "UPDATE approvals SET status = ?, expires_at = ?, decided_at = ?, "
                        "revision = revision + 1 WHERE approval_id = ? AND revision = ?",
                        (a.status.value, a.expires_at, a.decided_at, a.approval_id, a.revision),
                    )
                if cursor.rowcount != 1:
                    raise StaleApproval  # rolls back every row of this call

    def delete(self, approval_ids: list[str]) -> None:
        with closing(self._connect()) as conn, conn:
            conn.executemany(
                "DELETE FROM approvals WHERE approval_id = ?", [(i,) for i in approval_ids]
            )


class PendingQuotaExceeded(Exception):
    """This agent already has as many pending approvals as it may have."""


class Rejected(Exception):
    """A human rejected this exact action recently: the rejection still stands."""

    def __init__(self, approval_id: str, seconds_left: float) -> None:
        super().__init__("rejected by a human")
        self.approval_id = approval_id
        self.seconds_left = seconds_left


def _new_approval_id() -> str:
    """Unguessable, 32 characters. Never starts with "-", so it can't be mistaken for
    an option on a command line (`warden approvals approve ID`)."""
    while True:
        approval_id = secrets.token_urlsafe(24)
        if not approval_id.startswith("-"):
            return approval_id


class ApprovalStore:
    """Thread-safe approvals. Every method takes the lock.

    With `db`, the database is the truth: every method first reads it again (another
    server may share it), and every change is written to it BEFORE it takes effect in
    memory, only if nobody else changed that approval meanwhile. If reading or writing
    fails, the method raises and nothing changes (fail closed).
    """

    def __init__(
        self,
        ttl_seconds: float = APPROVAL_TTL_SECONDS,
        max_pending: int = MAX_PENDING,
        clock: Callable[[], float] | None = None,
        db: ApprovalDB | None = None,
        rejection_window: Callable[[str], float] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        # agent_id -> seconds a rejection sticks (0 = off). The server sets it from the
        # policy's limits; without one, every agent gets the default.
        self.rejection_window: Callable[[str], float] = rejection_window or (
            lambda agent_id: DEFAULT_REJECTION_WINDOW_SECONDS
        )
        self._max_pending = max_pending
        # Monotonic (immune to clock changes) in memory; the wall clock when persisted,
        # because the monotonic clock starts over with every process.
        self._clock = clock or (time.time if db is not None else time.monotonic)
        self._db = db
        self.db_path = db.path if db is not None else None
        self._lock = threading.Lock()
        self._items: dict[str, Approval] = {}
        if db is not None:
            self._refresh(self._clock())

    def _save(self, *updated: Approval) -> None:
        """Make these changes: in the database first (all or none), then in memory."""
        if self._db is not None:
            if len(updated) == 1:
                self._db.save(updated[0])
            else:
                self._db.save_many(updated)
        for new in updated:
            known = self._items.setdefault(new.approval_id, new)
            known.status, known.expires_at = new.status, new.expires_at
            known.decided_at, known.revision = new.decided_at, new.revision + 1

    def _refresh(self, now: float) -> None:
        """Take over what other servers changed, and forget expired approvals (safe: an
        unknown id is always refused). Arguments are kept: they are only in memory."""
        if self._db is not None:
            rows = self._db.read(self._ttl)
            if any(row.expires_at <= now for row in rows):
                try:
                    self._db.delete_expired(now)
                except sqlite3.Error:
                    pass  # harmless: expired rows are ignored
            for row in rows:
                known = self._items.get(row.approval_id)
                if known is not None:
                    known.status, known.expires_at = row.status, row.expires_at
                    known.decided_at, known.revision = row.decided_at, row.revision
            self._items = {r.approval_id: self._items.get(r.approval_id, r) for r in rows}
        self._items = {k: a for k, a in self._items.items() if a.expires_at > now}

    @staticmethod
    def _recall(approval: Approval, arguments: dict[str, JsonValue] | None) -> None:
        """After a restart: the agent sent the action again and its hash matched, so
        these are exactly the arguments the approval is bound to."""
        if approval.arguments is None and arguments is not None:
            approval.arguments = arguments

    def _sticky(self, approval: Approval) -> bool:
        """True if this is a rejection that still refuses the action (not lifted, not
        expired: expired ones are purged first)."""
        return approval.status is Status.DENIED and self.rejection_window(approval.agent_id) > 0

    def _denied_until(self, approval: Approval, now: float) -> float:
        """Expiry for a rejection decided now: the whole rejection window (0 = off: the
        rest of its current window, as before sticky rejections)."""
        window = self.rejection_window(approval.agent_id)
        return now + window if window > 0 else approval.expires_at

    def request(
        self, action: ActionRequest, action_hash: str, agent_limit: int | None = None
    ) -> str | None:
        """Create (or reuse) a pending approval. None = too many pending overall.

        Raises PendingQuotaExceeded if the agent already has `agent_limit` pending
        (checked under the lock, so racing requests can't overshoot). Raises Rejected if
        a human rejected this exact action and the rejection still stands (checked
        first: a rejection beats everything)."""
        with self._lock:
            try:
                return self._request(action, action_hash, agent_limit)
            except StaleApproval:
                # Another server just created one for the same action: use that one.
                return self._request(action, action_hash, agent_limit)

    def _request(
        self, action: ActionRequest, action_hash: str, agent_limit: int | None
    ) -> str | None:
        now = self._clock()
        self._refresh(now)
        for a in self._items.values():
            # The hash covers the agent id: only the same agent, same action.
            if self._sticky(a) and secrets.compare_digest(a.action_hash, action_hash):
                raise Rejected(a.approval_id, a.expires_at - now)
        for a in self._items.values():
            if a.status in {Status.PENDING, Status.APPROVED} and a.action_hash == action_hash:
                # Same action asked again (maybe the agent lost the id): hand back
                # the existing approval instead of piling up a new one.
                self._recall(a, action.arguments)
                return a.approval_id
        pending = sum(a.status is Status.PENDING for a in self._items.values())
        if pending >= self._max_pending:
            return None
        if agent_limit is not None:
            mine = sum(
                a.status is Status.PENDING and a.agent_id == action.agent_id
                for a in self._items.values()
            )
            if mine >= agent_limit:
                raise PendingQuotaExceeded
        approval_id = _new_approval_id()
        approval = Approval(
            approval_id=approval_id,
            agent_id=action.agent_id,
            tool=action.tool,
            arguments=action.arguments,
            action_hash=action_hash,
            expires_at=now + self._ttl,
            created_at=now,
        )
        self._save(approval)
        return approval_id

    def pending(self) -> list[tuple[Approval, float]]:
        """Pending approvals with seconds left, oldest first."""
        with self._lock:
            now = self._clock()
            self._refresh(now)
            items = [a for a in self._items.values() if a.status is Status.PENDING]
            return [(a, a.expires_at - now) for a in sorted(items, key=lambda a: a.expires_at)]

    def decide(
        self,
        approval_id: str,
        approve: bool,
        before_commit: Callable[[Approval, Status], None] = lambda a, s: None,
        expected_hash: str | None = None,
        require_hash: bool = False,
    ) -> Status:
        """Approve or deny a pending approval, exactly once.

        An APPROVED approval that hasn't been used yet can still be denied: that
        revokes it (a human changed their mind or clicked by mistake).
        `before_commit` runs (under the lock) before the status changes. If it raises,
        nothing changes: used to make sure every human decision is audited first.
        With `expected_hash` (the action_hash the human was shown), it must match.
        With `require_hash` (the HTTP API), approving or rejecting a PENDING approval
        needs `expected_hash`; only revoking an approved one works without it (revoking
        can only make things stricter, so it must stay quick).
        """
        with self._lock:
            now = self._clock()
            self._refresh(now)
            approval = self._items.get(approval_id)
            if approval is None:
                raise DecideError(not_found=True)
            revoking = approval.status is Status.APPROVED and not approve
            if approval.status is not Status.PENDING and not revoking:
                if approval.status is Status.USED and not approve:
                    self._cancel_restore(approval)
                raise DecideError(not_found=False)
            if require_hash and expected_hash is None and not revoking:
                raise DecideError(not_found=False, hash_required=True)
            if approve and approval.arguments is None:
                # Restarted: nobody can see what this would approve. Deny still works.
                raise DecideError(not_found=False, no_arguments=True)
            # Bytes: compare_digest refuses non-ASCII text (TypeError) instead of saying no.
            if expected_hash is not None and not secrets.compare_digest(
                approval.action_hash.encode(), expected_hash.encode()
            ):
                raise DecideError(not_found=False, hash_mismatch=True)
            new_status = Status.APPROVED if approve else Status.DENIED
            before_commit(approval, new_status)
            # The agent gets a full window from the moment of approval, not
            # whatever was left of the window from when it first asked. A rejection
            # (or revoke) sticks for the agent's rejection window.
            expires_at = now + self._ttl if approve else self._denied_until(approval, now)
            self._save(replace(approval, status=new_status, expires_at=expires_at, decided_at=now))
            return new_status

    def _cancel_restore(self, approval: Approval) -> None:
        """A human said no to an approval that is being used right now. Too late to
        revoke it, but if that use is undone (restore) it must stay spent: no server may
        restore it after this."""
        approval.used_revision = None
        self._save(replace(approval))  # a new revision: other servers' restores lose

    def _superseded(self, approval: Approval) -> bool:
        """True if a human rejected this exact action after this approval was approved
        (through another approval, created while this one counted as used)."""
        return any(
            a.status is Status.DENIED
            and secrets.compare_digest(a.action_hash, approval.action_hash)
            and (
                a.decided_at is None
                or approval.decided_at is None
                or a.decided_at >= approval.decided_at
            )
            for a in self._items.values()
        )

    def rejections(self) -> list[tuple[Approval, float, float]]:
        """Rejections that still stand: (approval, seconds left, seconds since the
        rejection), soonest to expire first."""
        with self._lock:
            now = self._clock()
            self._refresh(now)
            items = sorted(
                (a for a in self._items.values() if self._sticky(a)), key=lambda a: a.expires_at
            )
            return [
                (a, a.expires_at - now, now - (a.decided_at if a.decided_at is not None else now))
                for a in items
            ]

    def lift(
        self,
        approval_id: str,
        before_commit: Callable[[Approval], None] = lambda a: None,
    ) -> None:
        """Lift a rejection (a human rejected by mistake): the agent may ASK again, and
        gets an ordinary pending approval that a human must approve after seeing it.

        Raises DecideError(not_found=True) if unknown or expired, DecideError otherwise
        if it isn't a rejection. `before_commit` (the audit) runs under the lock first;
        if it raises, nothing changes. Deleted from the database before from memory."""
        with self._lock:
            self._refresh(self._clock())
            approval = self._items.get(approval_id)
            if approval is None:
                raise DecideError(not_found=True)
            if approval.status is not Status.DENIED:
                raise DecideError(not_found=False)
            before_commit(approval)
            # With it goes any older approval of the same action it beat: otherwise
            # lifting would bring that approval back, and nobody would be asked again.
            gone = [approval_id] + [
                a.approval_id
                for a in self._items.values()
                if a.status is Status.APPROVED
                and a.action_hash == approval.action_hash
                and self._superseded(a)
            ]
            if self._db is not None:
                self._db.delete(gone)
            for key in gone:
                del self._items[key]

    def pending_groups(self) -> list[tuple[tuple[str, str], list[tuple[Approval, float]]]]:
        """Pending approvals grouped by (agent_id, tool), groups sorted by that key,
        items by creation time, then id. A group never mixes agents or tools."""
        groups: dict[tuple[str, str], list[tuple[Approval, float]]] = {}
        for approval, seconds_left in self.pending():
            groups.setdefault((approval.agent_id, approval.tool), []).append(
                (approval, seconds_left)
            )
        for items in groups.values():
            items.sort(key=lambda item: (item[0].created_at, item[0].approval_id))
        return sorted(groups.items())

    def decide_group(
        self,
        approval_ids: Sequence[str],
        approve: bool,
        before_commit: Callable[[list[Approval], Status], None] = lambda a, s: None,
        expected_hashes: Sequence[str] | None = None,
    ) -> list[Approval]:
        """Approve or deny several PENDING approvals of one agent and tool, all or nothing.

        Every id is checked first, under the lock; if any fails, GroupDecideError lists
        them and nothing changes. `before_commit` (the audit) runs before anything
        changes; if it raises, nothing changes. Each approval stays an ordinary
        single-use approval bound to its own action. Returns them, in the given order.
        `expected_hashes` (same order as the ids): the action_hash the human was shown
        for each; every one must match.
        """
        if not 1 <= len(approval_ids) <= MAX_GROUP:
            raise ValueError(f"a group decision takes 1 to {MAX_GROUP} ids")
        if expected_hashes is not None and len(expected_hashes) != len(approval_ids):
            raise ValueError("one action_hash per id")
        with self._lock:
            now = self._clock()
            self._refresh(now)
            failed: list[tuple[str, GroupReason]] = []
            found: list[Approval] = []
            seen: set[str] = set()
            group: tuple[str, str] | None = None
            for index, approval_id in enumerate(approval_ids):
                approval = self._items.get(approval_id)
                if approval_id in seen:
                    failed.append((approval_id, GroupReason.DUPLICATE))
                    continue
                seen.add(approval_id)
                if approval is None:
                    failed.append((approval_id, GroupReason.NOT_FOUND))
                    continue
                key = (approval.agent_id, approval.tool)
                group = group or key
                if key != group:
                    failed.append((approval_id, GroupReason.MIXED))
                elif approval.status is not Status.PENDING:
                    if approval.status is Status.USED and not approve:
                        self._cancel_restore(approval)
                    failed.append((approval_id, GroupReason.DECIDED))
                elif approve and approval.arguments is None:
                    failed.append((approval_id, GroupReason.NO_ARGUMENTS))
                elif expected_hashes is not None and not secrets.compare_digest(
                    approval.action_hash.encode(), expected_hashes[index].encode()
                ):
                    failed.append((approval_id, GroupReason.HASH_MISMATCH))
                else:
                    found.append(approval)
            if failed:
                raise GroupDecideError(failed)
            new_status = Status.APPROVED if approve else Status.DENIED
            before_commit(found, new_status)
            # Approved: a full window from now; rejected: each sticks for its agent's
            # rejection window. As for single decisions.
            updated = [
                replace(
                    a,
                    status=new_status,
                    expires_at=now + self._ttl if approve else self._denied_until(a, now),
                    decided_at=now,
                )
                for a in found
            ]
            self._save(*updated)
            return found

    def use(
        self,
        approval_id: str,
        action_hash: str,
        agent_id: str | None = None,
        arguments: dict[str, JsonValue] | None = None,
    ) -> Status | None:
        """Try to use an approval for this exact action, in one locked step.

        Returns the status it had: APPROVED means it was granted now (and is
        marked USED, so it can't be granted again). PENDING, DENIED or USED mean
        no. None means unknown, expired, or approved for a DIFFERENT action
        (a mismatch reveals nothing and does NOT burn the approval). With `agent_id`,
        the approval must also belong to that agent (the hash covers it too; this is a
        second, explicit lock).
        """
        with self._lock:
            self._refresh(self._clock())
            approval = self._items.get(approval_id)
            if approval is None:
                return None
            if not secrets.compare_digest(approval.action_hash, action_hash):
                return None
            if agent_id is not None and approval.agent_id != agent_id:
                return None
            self._recall(approval, arguments)
            status = approval.status
            if status is Status.APPROVED:
                if self._superseded(approval):
                    return Status.DENIED
                # Persist "used" BEFORE granting: a crash right after can't replay it.
                # Conditional: of several servers sharing the database, only one can.
                try:
                    self._save(replace(approval, status=Status.USED))
                except StaleApproval:
                    self._refresh(self._clock())
                    current = self._items.get(approval_id)
                    # Never an allow after losing the race, whatever it is now.
                    if current is None or current.status is Status.APPROVED:
                        return None
                    return current.status
                approval.used_revision = approval.revision
            return status

    def restore(self, approval_id: str) -> None:
        """Undo a use: the allow it produced was never delivered (e.g. the audit write
        failed and the agent got deny instead), so the approval isn't spent.

        Only the use this server made, unchanged since. A newer "no" from a human wins,
        for this approval or for the same action under another id. On any doubt it
        stays used: the agent asks for a new approval (fail closed)."""
        with self._lock:
            try:
                self._refresh(self._clock())
                approval = self._items.get(approval_id)
                if (
                    approval is None
                    or approval.status is not Status.USED
                    or approval.used_revision != approval.revision
                    or self._superseded(approval)
                ):
                    return
                self._save(replace(approval, status=Status.APPROVED))
            except (sqlite3.Error, StaleApproval):
                return

    def consume(self, approval_id: str, action_hash: str) -> bool:
        """Use an approval. True only once, only for the exact approved action."""
        return self.use(approval_id, action_hash) is Status.APPROVED


def apply_approval(
    action: ActionRequest,
    result: EvaluationResult,
    store: ApprovalStore,
    agent_limit: int | None = None,
) -> EvaluationResult:
    """Turn the engine's decision into the final answer, using approvals.

    Only require_approval is affected. An approval can never turn a DENY into ALLOW.
    """
    if result.decision is not Decision.REQUIRE_APPROVAL or result.action_hash is None:
        return result

    if action.approval_id is None:
        try:
            approval_id = store.request(action, result.action_hash, agent_limit)
        except Rejected as exc:
            # No arguments in the reason, as always: only when, and which approval.
            until = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(time.time() + exc.seconds_left)
            )
            return EvaluationResult(
                decision=Decision.DENY,
                reason=f"rejected by a human; this exact action is refused until {until} "
                f"(approval {exc.approval_id})",
                matched_rule=result.matched_rule,
                action_hash=result.action_hash,
            )
        except PendingQuotaExceeded:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="too many pending approvals for this agent",
                matched_rule=result.matched_rule,
                action_hash=result.action_hash,
            )
        if approval_id is None:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="too many pending approvals",
                matched_rule=result.matched_rule,
                action_hash=result.action_hash,
            )
        return EvaluationResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason=result.reason,
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            approval_id=approval_id,
        )

    status = store.use(
        action.approval_id, result.action_hash, agent_id=action.agent_id, arguments=action.arguments
    )
    if status is Status.APPROVED:
        return EvaluationResult(
            decision=Decision.ALLOW,
            reason=f"approved by a human ({result.reason})",
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            approval_id=action.approval_id,
        )
    if status is Status.PENDING:
        # Not a "no" yet: tell the agent to keep waiting (still NOT allowed).
        return EvaluationResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason="waiting for a human to approve",
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            approval_id=action.approval_id,
        )
    reasons = {Status.DENIED: "denied by a human", Status.USED: "approval already used"}
    return EvaluationResult(
        decision=Decision.DENY,
        reason=reasons.get(status, "approval not valid") if status else "approval not valid",
        matched_rule=result.matched_rule,
        action_hash=result.action_hash,
    )
