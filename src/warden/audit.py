"""The audit log: a permanent record of every decision Warden makes.

Two tables:
- decisions: every answer to an agent (time, agent, tool, decision, reason,
  matched rule, action_hash, approval_id).
- events: everything else worth knowing: a human approving or denying, and
  rejected requests (bad input, wrong admin key, oversized body, errors).

What is NEVER stored: tool arguments (they may contain secrets). The action_hash
still identifies the exact action without revealing it.

Tamper evidence: every row carries `prev_hash` (the previous row's hash in the
same table) and `row_hash` = SHA-256 over the table name, row id, prev_hash and
the row's values. Editing, deleting or reordering a row breaks the chain from that
row on; `warden audit verify` finds the first broken row. Retention deletes a
prefix of each chain and saves an "anchor" (the hash of the last deleted row), in
the anchors table AND in the chained audit_purged event. A plain hash chain can't
stop someone who rewrites every later hash too: compare the head hash that
`verify` prints with a copy kept elsewhere. See docs/design/audit-chain.md.

Storage is kept behind the small `AuditLog` interface, so the SQLite file used
here can later be swapped (e.g. for Postgres or a hosted service) without
touching the engine or the API.
"""

import hashlib
import json
import logging
import os
import sqlite3
import stat
import threading
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from warden.models import ActionRequest, Decision, EvaluationResult

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_PATH = Path("warden-audit.db")
DEFAULT_RETENTION_DAYS = 90  # None = keep everything forever
MAX_RETENTION_DAYS = 36_500  # 100 years: far more overflows the calendar, so purges fail
PURGE_INTERVAL = timedelta(days=1)


class AuditEntry(BaseModel):
    """One decision, as stored. Deliberately has no `arguments` field."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    timestamp: str  # ISO 8601, UTC
    agent_id: str
    tool: str
    decision: Decision
    reason: str
    matched_rule: str | None
    action_hash: str | None
    approval_id: str | None = None

    @classmethod
    def from_decision(cls, request: ActionRequest, result: EvaluationResult) -> "AuditEntry":
        return cls(
            timestamp=datetime.now(UTC).isoformat(),
            agent_id=request.agent_id,
            tool=request.tool,
            decision=result.decision,
            reason=result.reason,
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            # On a failed retry the result has no approval_id; keep the one that was
            # tried, so misuse attempts are visible.
            approval_id=result.approval_id or request.approval_id,
        )


class EventKind(StrEnum):
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_DECIDE_FAILED = "approval_decide_failed"  # unknown, expired or already decided
    # One human decision on several approvals (each also gets its own event).
    APPROVAL_GROUP_DECIDED = "approval_group_decided"
    # A human lifted a sticky rejection: the agent may ask for that action again.
    APPROVAL_REJECTION_LIFTED = "approval_rejection_lifted"
    REQUEST_REJECTED = "request_rejected"  # 401, 411, 413, 422, 500
    AUDIT_PURGED = "audit_purged"  # old entries deleted by retention
    # Written once, when an old database gets the hash columns: rows up to these ids
    # (chain_anchor, JSON) predate the chain. No other row may be without hashes.
    AUDIT_CHAIN_STARTED = "audit_chain_started"


MAX_PATH_CHARS = 200


class AuditEvent(BaseModel):
    """Something that isn't an agent decision. Never contains tool arguments."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    timestamp: str
    kind: EventKind
    reason: str
    http_status: int | None = None
    method: str | None = None
    path: str | None = None  # URL path only, no query string, cut to MAX_PATH_CHARS
    approval_id: str | None = None
    agent_id: str | None = None
    tool: str | None = None
    action_hash: str | None = None
    # Only on audit_purged: where each table's hash chain now starts (JSON).
    chain_anchor: str | None = None

    @classmethod
    def now(
        cls,
        kind: EventKind,
        reason: str,
        *,
        http_status: int | None = None,
        method: str | None = None,
        path: str | None = None,
        approval_id: str | None = None,
        agent_id: str | None = None,
        tool: str | None = None,
        action_hash: str | None = None,
    ) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(UTC).isoformat(),
            kind=kind,
            reason=reason,
            http_status=http_status,
            method=method,
            path=path[:MAX_PATH_CHARS] if path is not None else None,
            approval_id=approval_id,
            agent_id=agent_id,
            tool=tool,
            action_hash=action_hash,
        )


class AuditLog(Protocol):
    """Anything that can store and list audit entries."""

    def record(self, entry: AuditEntry) -> None: ...

    def recent(self, limit: int = 100) -> list[AuditEntry]: ...  # mutation-ok: stub

    def record_event(self, event: AuditEvent) -> None: ...

    def recent_events(self, limit: int = 100) -> list[AuditEvent]: ...  # mutation-ok: stub


_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    tool         TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    matched_rule TEXT,
    action_hash  TEXT,
    approval_id  TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    reason       TEXT NOT NULL,
    http_status  INTEGER,
    method       TEXT,
    path         TEXT,
    approval_id  TEXT,
    agent_id     TEXT,
    tool         TEXT,
    action_hash  TEXT
);
CREATE TABLE IF NOT EXISTS audit_anchors (
    table_name   TEXT PRIMARY KEY,
    last_deleted_id   INTEGER NOT NULL,
    last_deleted_hash TEXT NOT NULL
);
"""

# Columns added after the first version. Older databases get them on startup
# (a tiny "migration"), so upgrading Warden never loses audit history. Rows written
# before the hash chain existed have no hashes: `verify` reports them as unchained.
_ADDED_COLUMNS = {
    "decisions": {"approval_id": "TEXT", "prev_hash": "TEXT", "row_hash": "TEXT"},
    "events": {"chain_anchor": "TEXT", "prev_hash": "TEXT", "row_hash": "TEXT"},
}

GENESIS_HASH = "0" * 64
_CHAIN_VERSION = "warden-audit-chain-v1"
_TABLES = ("decisions", "events")

_EVENT_FIELDS = (
    "timestamp",
    "kind",
    "reason",
    "http_status",
    "method",
    "path",
    "approval_id",
    "agent_id",
    "tool",
    "action_hash",
    "chain_anchor",
)
_EVENT_COLUMNS = ", ".join(_EVENT_FIELDS)

_COLUMNS = "timestamp, agent_id, tool, decision, reason, matched_rule, action_hash, approval_id"
_TABLE_COLUMNS = {"decisions": _COLUMNS, "events": _EVENT_COLUMNS}


def row_hash(table: str, row_id: int, prev_hash: str, values: tuple[object, ...]) -> str:
    """The chain hash of one row: covers its table, id, predecessor and every value."""
    payload = json.dumps(
        [table, row_id, prev_hash, list(values)], separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(f"{_CHAIN_VERSION}\n{payload}".encode()).hexdigest()


def _chain_head(conn: sqlite3.Connection, table: str) -> str:
    """The hash the next row must point back to."""
    row = conn.execute(
        f"SELECT row_hash FROM {table} ORDER BY id DESC LIMIT 1"  # noqa: S608 (constant)
    ).fetchone()
    if row is not None:
        return str(row[0]) if row[0] else GENESIS_HASH  # unchained (old) rows: start over
    anchor = conn.execute(
        "SELECT last_deleted_hash FROM audit_anchors WHERE table_name = ?", (table,)
    ).fetchone()
    return str(anchor[0]) if anchor else GENESIS_HASH


def _append(conn: sqlite3.Connection, table: str, values: tuple[object, ...]) -> None:
    """Insert one chained row. The caller holds a write lock (BEGIN IMMEDIATE), so no
    other writer can append between reading the head and writing the row."""
    columns = _TABLE_COLUMNS[table]
    prev = _chain_head(conn, table)
    placeholders = ", ".join("?" * (len(values) + 1))
    cursor = conn.execute(
        f"INSERT INTO {table} ({columns}, prev_hash) VALUES ({placeholders})",  # noqa: S608
        (*values, prev),
    )
    row_id = cursor.lastrowid
    assert row_id is not None  # noqa: S101 (sqlite always sets it after an INSERT)
    conn.execute(
        f"UPDATE {table} SET row_hash = ? WHERE id = ?",  # noqa: S608 (constant table)
        (row_hash(table, row_id, prev, values), row_id),
    )


def _make_private(path: Path) -> None:
    """Create the database file readable by this user only (0600), or tighten it.

    It holds agent ids, tools, decisions and pending approval ids: not for other
    users on the machine. (SQLite gives its journal files the same permissions.)
    """
    if path.is_symlink():
        # In a shared folder (e.g. /tmp) someone else could plant a link and make
        # Warden write its log wherever they like. Never follow one.
        raise ValueError(f"audit log path {path} is a symlink; refusing to use it")
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        path.chmod(0o600)
        logger.warning("audit log %s was readable by others; restricted it to you (600)", path)


def _check_days(days: int) -> None:
    if type(days) is not int or not 1 <= days <= MAX_RETENTION_DAYS:
        raise ValueError(
            f"retention must be a whole number of days >= 1 and <= {MAX_RETENTION_DAYS}, "
            "or None (forever)"
        )


class SQLiteAuditLog:
    """Audit log stored in a local SQLite file (standard library, no extra dependency).

    Opens a fresh connection per call: simple, and safe when the API handles
    requests on several threads at once.
    """

    def __init__(
        self,
        path: Path = DEFAULT_AUDIT_PATH,
        retention_days: int | None = DEFAULT_RETENTION_DAYS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if retention_days is not None:
            _check_days(retention_days)
        self.path = path
        self.retention_days = retention_days
        self._clock = clock
        self._purge_lock = threading.Lock()
        self._last_purge: datetime | None = None
        self._purge_running = False
        self._purge_thread: threading.Thread | None = None
        _make_private(path)
        unchained: dict[str, int] = {}  # tables that get the hash columns now: last old id
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)
            for table, added in _ADDED_COLUMNS.items():
                existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                if "row_hash" not in existing:
                    last = conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0]  # noqa: S608
                    unchained[table] = int(last or 0)
                for name, sql_type in added.items():
                    if name not in existing:
                        # Names come from the constant above, never from user input.
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
        if any(unchained.values()):
            self._record_chain_start(unchained)
        self._maybe_purge(background=False)  # first purge at startup, before serving

    def _record_chain_start(self, unchained: dict[str, int]) -> None:
        """Only at the moment the hash columns are added: these rows really are older
        than the chain. Recorded IN the chain, so it can't be quietly changed; without
        it, `verify` accepts no row without hashes (nulling hashes can't hide an edit)."""
        limits = {table: unchained.get(table, 0) for table in _TABLES}
        with closing(self._write()) as conn, conn:
            self._insert_event(
                conn,
                AuditEvent(
                    timestamp=self._clock().isoformat(),
                    kind=EventKind.AUDIT_CHAIN_STARTED,
                    reason="hash chain started; older rows have no hashes",
                    chain_anchor=json.dumps(limits, sort_keys=True),
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)  # mutation-ok: timeout

    def _write(self) -> sqlite3.Connection:
        """A connection holding the write lock (released by commit / rollback)."""
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        return conn

    def _maybe_purge(self, background: bool = True) -> None:
        """Purge at most once per PURGE_INTERVAL. Never makes a write fail or wait.

        During normal writes the purge runs in a background thread, so the request
        that happens to trigger it isn't slowed down by a big DELETE.
        """
        if self.retention_days is None:
            return
        now = self._clock()
        with self._purge_lock:
            if self._purge_running:
                return
            if self._last_purge is not None and now - self._last_purge < PURGE_INTERVAL:
                return
            self._last_purge = now
            self._purge_running = True  # mutation-ok: the interval check above also stops a 2nd run
        if background:
            self._purge_thread = threading.Thread(
                target=self._run_purge,
                name="warden-audit-purge",
                daemon=True,  # mutation-ok: only affects exit while a purge runs
            )
            self._purge_thread.start()
        else:
            self._run_purge()

    def _run_purge(self) -> None:
        days = self.retention_days
        try:
            if days is not None:
                self.purge_older_than(days)
        except Exception as exc:
            logger.error("audit retention purge failed, will retry: %s", type(exc).__name__)
            with self._purge_lock:
                self._last_purge = None  # retry on the next write, not in 24 hours
        finally:
            with self._purge_lock:
                self._purge_running = False

    def wait_for_purge(self, timeout: float = 10) -> None:  # mutation-ok: timeout
        """Wait for a background purge to finish (used by tests and at shutdown)."""
        thread = self._purge_thread
        if thread is not None:
            thread.join(timeout)

    def purge_older_than(self, days: int) -> int:
        """Delete entries older than `days` from both tables. Returns how many.

        The deletion and an AUDIT_PURGED event explaining it are written in one
        transaction: history never disappears without a record saying why.
        """
        _check_days(days)
        now = self._clock()
        cutoff = (now - timedelta(days=days)).isoformat()
        with closing(self._write()) as conn, conn:
            decisions = _delete_prefix(conn, "decisions", cutoff)
            events = _delete_prefix(conn, "events", cutoff)
            if decisions + events:
                anchors = dict(
                    conn.execute(
                        "SELECT table_name, last_deleted_hash FROM audit_anchors "
                        "ORDER BY table_name"
                    ).fetchall()
                )
                self._insert_event(
                    conn,
                    AuditEvent(
                        timestamp=now.isoformat(),
                        kind=EventKind.AUDIT_PURGED,
                        reason=f"deleted {decisions} decisions and {events} events "
                        f"older than {days} days",
                        # In the chain too, so the anchors table can't be quietly edited.
                        chain_anchor=json.dumps(anchors, sort_keys=True)  # mutation-ok: sorted
                        if anchors
                        else None,
                    ),
                )
        return decisions + events

    def record(self, entry: AuditEntry) -> None:
        self._maybe_purge()
        # "?" placeholders: values are never pasted into the SQL text (no SQL injection).
        with closing(self._write()) as conn, conn:
            _append(
                conn,
                "decisions",
                (
                    entry.timestamp,
                    entry.agent_id,
                    entry.tool,
                    entry.decision.value,
                    entry.reason,
                    entry.matched_rule,
                    entry.action_hash,
                    entry.approval_id,
                ),
            )

    def recent(self, limit: int = 100) -> list[AuditEntry]:
        """Newest first."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM decisions ORDER BY id DESC LIMIT ?",  # noqa: S608
                (limit,),
            ).fetchall()
        return [
            AuditEntry(
                timestamp=r[0],
                agent_id=r[1],
                tool=r[2],
                decision=Decision(r[3]),
                reason=r[4],
                matched_rule=r[5],
                action_hash=r[6],
                approval_id=r[7],
            )
            for r in rows
        ]

    def record_event(self, event: AuditEvent) -> None:
        self.record_events([event])

    def record_events(self, events: list[AuditEvent]) -> None:
        """Write several events in ONE transaction: all are recorded, or none."""
        self._maybe_purge()
        with closing(self._write()) as conn, conn:
            for event in events:
                self._insert_event(conn, event)

    @staticmethod
    def _insert_event(conn: sqlite3.Connection, event: AuditEvent) -> None:
        values = [getattr(event, name) for name in _EVENT_FIELDS]
        values[1] = event.kind.value
        _append(conn, "events", tuple(values))

    def recent_events(self, limit: int = 100) -> list[AuditEvent]:
        """Newest first."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM events ORDER BY id DESC LIMIT ?",  # noqa: S608
                (limit,),
            ).fetchall()
        events = []
        for row in rows:
            data = dict(zip(_EVENT_FIELDS, row, strict=True))  # mutation-ok: same lengths
            data["kind"] = EventKind(data["kind"])
            events.append(AuditEvent(**data))
        return events


def record_events(log: AuditLog, events: list[AuditEvent]) -> None:
    """All or nothing with SQLiteAuditLog (what `warden serve` uses). Other logs (test
    doubles) get the events one by one."""
    if isinstance(log, SQLiteAuditLog):
        log.record_events(events)
        return
    for event in events:
        log.record_event(event)


def _delete_prefix(conn: sqlite3.Connection, table: str, cutoff: str) -> int:
    """Delete the oldest rows, up to (not including) the first row at or after `cutoff`.

    Only a PREFIX is deleted, so the chain of what's left stays whole. A row whose
    timestamp is out of order (e.g. the clock moved) is kept a little longer rather
    than cut out of the middle. The last deleted row's hash becomes the anchor.
    ISO timestamps in UTC sort correctly as text, so "<" means "older".
    """
    first_kept = conn.execute(
        f"SELECT MIN(id) FROM {table} WHERE timestamp >= ?",  # noqa: S608 (constant)
        (cutoff,),
    ).fetchone()[0]
    where, args = ("id < ?", (first_kept,)) if first_kept is not None else ("1", ())
    last = conn.execute(
        f"SELECT id, row_hash FROM {table} WHERE {where} ORDER BY id DESC LIMIT 1",  # noqa: S608
        args,
    ).fetchone()
    if last is None:
        return 0
    deleted = conn.execute(
        f"DELETE FROM {table} WHERE id <= ?",  # noqa: S608 (constant table name)
        (last[0],),
    ).rowcount
    if last[1]:
        conn.execute(
            "INSERT INTO audit_anchors (table_name, last_deleted_id, last_deleted_hash) "
            "VALUES (?, ?, ?) ON CONFLICT(table_name) DO UPDATE SET "
            "last_deleted_id = excluded.last_deleted_id, "
            "last_deleted_hash = excluded.last_deleted_hash",
            (table, last[0], last[1]),
        )
    return int(deleted)


# --- Verification ----------------------------------------------------------------------


class ChainReport(BaseModel):
    """What `warden audit verify` found. `problems` is empty when the log is intact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checked: dict[str, int]  # chained rows verified per table
    unchained: dict[str, int]  # rows written before the chain existed
    heads: dict[str, str]  # the newest hash per table: keep a copy elsewhere
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_chain(path: Path) -> ChainReport:
    """Recompute every hash. Reports the FIRST broken row of each table. Read-only."""
    # as_uri() percent-encodes "?", "#" and "%": pasting the raw path into the URI
    # would make SQLite open a DIFFERENT file (e.g. "audit#1.db" -> "audit").
    uri = f"{path.resolve().as_uri()}?mode=ro"
    checked: dict[str, int] = {}
    unchained: dict[str, int] = {}
    heads: dict[str, str] = {}
    problems: list[str] = []
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:  # mutation-ok: timeout
        anchors, anchors_ok = _read_anchors(conn)
        if not anchors_ok:
            problems.append("audit_anchors: contains values Warden never writes (edited?)")
        old_rows = _unchained_limits(conn)
        for table in _TABLES:
            count, legacy, head, problem = _verify_table(
                conn, table, anchors.get(table), old_rows.get(table, 0)
            )
            checked[table], unchained[table], heads[table] = count, legacy, head
            if problem:
                problems.append(problem)
        problems += _verify_anchors(conn, anchors)
    return ChainReport(checked=checked, unchained=unchained, heads=heads, problems=problems)


def _read_anchors(conn: sqlite3.Connection) -> tuple[dict[str, str], bool]:
    """Last deleted hash per table, and whether every anchor has the right types (SQLite
    columns accept any type, so an edited database can hold anything here)."""
    rows = conn.execute(
        "SELECT table_name, last_deleted_id, last_deleted_hash FROM audit_anchors"
    ).fetchall()
    good = {t: h for t, i, h in rows if type(t) is str and type(i) is int and type(h) is str}
    return good, len(good) == len(rows)


def _unchained_limits(conn: sqlite3.Connection) -> dict[str, int]:
    """Per table, the last id that may lack hashes: from the first CHAINED
    audit_chain_started event. None recorded: no row may lack hashes."""
    row = conn.execute(
        "SELECT chain_anchor FROM events WHERE kind = ? AND row_hash IS NOT NULL "
        "ORDER BY id LIMIT 1",
        (EventKind.AUDIT_CHAIN_STARTED.value,),
    ).fetchone()
    try:
        data = json.loads(row[0]) if row is not None and row[0] else {}
    except (ValueError, RecursionError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {t: v for t, v in data.items() if t in _TABLES and type(v) is int and v >= 0}


def _verify_table(
    conn: sqlite3.Connection, table: str, anchor: str | None, old_rows: int = 0
) -> tuple[int, int, str, str | None]:
    columns = _TABLE_COLUMNS[table]
    rows = conn.execute(
        f"SELECT id, {columns}, prev_hash, row_hash FROM {table} ORDER BY id"  # noqa: S608
    )
    expected = anchor or GENESIS_HASH
    checked = legacy = 0
    chained = False
    for row in rows:
        row_id, values, prev, stored = row[0], tuple(row[1:-2]), row[-2], row[-1]
        if stored is None and prev is None and not chained and row_id <= old_rows:
            legacy += 1  # written before the chain existed (recorded when it started)
            continue
        where = f"{table} row id {row_id}"
        if stored is None or prev is None:
            return checked, legacy, expected, f"{where}: hash missing (row added or edited)"
        if prev != expected:
            return checked, legacy, expected, f"{where}: doesn't follow the previous row "
            "(a row before it was deleted, inserted or edited)"
        try:
            actual = row_hash(table, row_id, prev, values)
        except (TypeError, ValueError):  # e.g. a BLOB: a value Warden never writes
            actual = None
        if actual != stored:
            return checked, legacy, expected, f"{where}: contents changed after writing"
        chained = True
        checked += 1
        expected = stored
    return checked, legacy, expected, None


def _verify_anchors(conn: sqlite3.Connection, anchors: dict[str, str]) -> list[str]:
    """The anchors table must match what the newest audit_purged event recorded."""
    if not anchors:
        return []
    row = conn.execute(
        "SELECT chain_anchor FROM events WHERE kind = ? AND chain_anchor IS NOT NULL "
        "ORDER BY id DESC LIMIT 1",
        (EventKind.AUDIT_PURGED.value,),
    ).fetchone()
    try:
        recorded = json.loads(row[0]) if row is not None else None
    except (ValueError, RecursionError):
        recorded = None
    if recorded != anchors:
        return ["audit_anchors: doesn't match the last recorded purge (anchors edited?)"]
    return []
