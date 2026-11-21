"""The audit log: a permanent record of every decision Warden makes.

Two tables:
- decisions: every answer to an agent (time, agent, tool, decision, reason,
  matched rule, action_hash, approval_id).
- events: everything else worth knowing: a human approving or denying, and
  rejected requests (bad input, wrong admin key, oversized body, errors).

What is NEVER stored: tool arguments (they may contain secrets). The action_hash
still identifies the exact action without revealing it.

Storage is kept behind the small `AuditLog` interface, so the SQLite file used
here can later be swapped (e.g. for Postgres or a hosted service) without
touching the engine or the API.
"""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from warden.models import ActionRequest, Decision, EvaluationResult

DEFAULT_AUDIT_PATH = Path("warden-audit.db")


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
    REQUEST_REJECTED = "request_rejected"  # 401, 411, 413, 422, 500


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

    @classmethod
    def now(cls, kind: EventKind, reason: str, **fields: object) -> "AuditEvent":
        if isinstance(fields.get("path"), str):
            fields["path"] = fields["path"][:MAX_PATH_CHARS]
        return cls(timestamp=datetime.now(UTC).isoformat(), kind=kind, reason=reason, **fields)


class AuditLog(Protocol):
    """Anything that can store and list audit entries."""

    def record(self, entry: AuditEntry) -> None: ...

    def recent(self, limit: int = 100) -> list[AuditEntry]: ...

    def record_event(self, event: AuditEvent) -> None: ...

    def recent_events(self, limit: int = 100) -> list[AuditEvent]: ...


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
"""

# Columns added after the first version. Older databases get them on startup
# (a tiny "migration"), so upgrading Warden never loses audit history.
_ADDED_COLUMNS = {"approval_id": "TEXT"}

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
)
_EVENT_COLUMNS = ", ".join(_EVENT_FIELDS)

_COLUMNS = "timestamp, agent_id, tool, decision, reason, matched_rule, action_hash, approval_id"


class SQLiteAuditLog:
    """Audit log stored in a local SQLite file (standard library, no extra dependency).

    Opens a fresh connection per call: simple, and safe when the API handles
    requests on several threads at once.
    """

    def __init__(self, path: Path = DEFAULT_AUDIT_PATH) -> None:
        self.path = path
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(decisions)")}
            for name, sql_type in _ADDED_COLUMNS.items():
                if name not in existing:
                    # Names come from the constant above, never from user input.
                    conn.execute(f"ALTER TABLE decisions ADD COLUMN {name} {sql_type}")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def record(self, entry: AuditEntry) -> None:
        # "?" placeholders: values are never pasted into the SQL text (no SQL injection).
        with closing(self._connect()) as conn, conn:
            conn.execute(
                f"INSERT INTO decisions ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
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
        values = [getattr(event, name) for name in _EVENT_FIELDS]
        values[1] = event.kind.value
        with closing(self._connect()) as conn, conn:
            conn.execute(
                f"INSERT INTO events ({_EVENT_COLUMNS}) VALUES ({', '.join('?' * len(values))})",  # noqa: S608
                values,
            )

    def recent_events(self, limit: int = 100) -> list[AuditEvent]:
        """Newest first."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM events ORDER BY id DESC LIMIT ?",  # noqa: S608
                (limit,),
            ).fetchall()
        events = []
        for row in rows:
            data = dict(zip(_EVENT_FIELDS, row, strict=True))
            data["kind"] = EventKind(data["kind"])
            events.append(AuditEvent(**data))
        return events
