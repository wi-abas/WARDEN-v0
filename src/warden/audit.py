"""The audit log: a permanent record of every decision Warden makes.

What is stored: time, agent, tool, decision, reason, matched rule, action_hash.
What is NEVER stored: tool arguments (they may contain secrets). The action_hash
still identifies the exact action without revealing it.

Storage is kept behind the small `AuditLog` interface, so the SQLite file used
here can later be swapped (e.g. for Postgres or a hosted service) without
touching the engine or the API.
"""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
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
            approval_id=result.approval_id,
        )


class AuditLog(Protocol):
    """Anything that can store and list audit entries."""

    def record(self, entry: AuditEntry) -> None: ...

    def recent(self, limit: int = 100) -> list[AuditEntry]: ...


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
)
"""

# Columns added after the first version. Older databases get them on startup
# (a tiny "migration"), so upgrading Warden never loses audit history.
_ADDED_COLUMNS = {"approval_id": "TEXT"}

_COLUMNS = "timestamp, agent_id, tool, decision, reason, matched_rule, action_hash, approval_id"


class SQLiteAuditLog:
    """Audit log stored in a local SQLite file (standard library, no extra dependency).

    Opens a fresh connection per call: simple, and safe when the API handles
    requests on several threads at once.
    """

    def __init__(self, path: Path = DEFAULT_AUDIT_PATH) -> None:
        self.path = path
        with closing(self._connect()) as conn, conn:
            conn.execute(_SCHEMA)
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
