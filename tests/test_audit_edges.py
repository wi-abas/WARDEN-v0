"""Exact limits and formats of the audit log (gaps found by mutation tests)."""

import dataclasses
import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditEvent,
    EventKind,
    SQLiteAuditLog,
    row_hash,
    verify_chain,
)
from warden.models import Decision

START = datetime(2026, 6, 1, tzinfo=UTC)


def entry(when: datetime = START) -> AuditEntry:
    return AuditEntry(
        timestamp=when.isoformat(),
        agent_id="a",
        tool="t",
        decision=Decision.ALLOW,
        reason="r",
        matched_rule=None,
        action_hash=None,
    )


def test_chain_hash_format_is_pinned() -> None:
    """A fixed reference: if the hash format changes (e.g. non-ASCII escaped), every
    existing log and saved checkpoint would stop verifying."""
    values = ("2026-06-01T00:00:00+00:00", "agent-é", "t", "allow", "ünïcode → ok", None)
    payload = '["decisions",1,"' + "0" * 64 + '",["2026-06-01T00:00:00+00:00","agent-é",'
    payload += '"t","allow","ünïcode → ok",null]]'
    expected = hashlib.sha256(f"warden-audit-chain-v1\n{payload}".encode()).hexdigest()
    assert row_hash("decisions", 1, GENESIS_HASH, values) == expected


def test_genesis_hash_is_64_zeros(tmp_path: Path) -> None:
    assert GENESIS_HASH == "0" * 64
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=None)
    log.record(entry())
    with sqlite3.connect(tmp_path / "a.db") as conn:
        assert conn.execute("SELECT prev_hash FROM decisions WHERE id = 1").fetchone()[0] == (
            "0" * 64
        )


def test_models_are_strict_and_frozen() -> None:
    with pytest.raises(ValidationError):
        AuditEntry.model_validate({**entry().model_dump(), "decision": "allow"})  # str, not enum
    with pytest.raises(ValidationError):
        entry().reason = "changed"  # type: ignore[misc]
    event = AuditEvent(timestamp=START.isoformat(), kind=EventKind.REQUEST_REJECTED, reason="x")
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({**event.model_dump(), "kind": "request_rejected"})
    with pytest.raises(ValidationError):
        event.reason = "changed"  # type: ignore[misc]


def test_chain_report_is_frozen(tmp_path: Path) -> None:
    SQLiteAuditLog(tmp_path / "a.db", retention_days=None)
    report = verify_chain(tmp_path / "a.db")
    with pytest.raises(ValidationError):
        report.problems = ["hidden"]  # type: ignore[misc]
    assert not dataclasses.is_dataclass(report)


def test_retention_of_one_day_is_allowed(tmp_path: Path) -> None:
    assert SQLiteAuditLog(tmp_path / "a.db", retention_days=1).retention_days == 1
    with pytest.raises(ValueError, match=">= 1"):
        SQLiteAuditLog(tmp_path / "b.db", retention_days=0)


def test_purge_runs_again_after_exactly_one_day(tmp_path: Path) -> None:
    now = [START]
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=30, clock=lambda: now[0])
    assert log._last_purge == START  # purged once at startup
    now[0] = START + timedelta(days=1) - timedelta(seconds=1)
    log.record(entry(now[0]))
    log.wait_for_purge()
    assert log._last_purge == START  # not yet
    now[0] = START + timedelta(days=1)
    log.record(entry(now[0]))
    log.wait_for_purge()
    assert log._last_purge == START + timedelta(days=1)


def test_recent_returns_the_newest_100_by_default(tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=None)
    for _ in range(101):
        log.record(entry())
        log.record_event(
            AuditEvent(timestamp=START.isoformat(), kind=EventKind.REQUEST_REJECTED, reason="x")
        )
    assert len(log.recent()) == 100
    assert len(log.recent_events()) == 100


def test_purge_stores_the_last_deleted_row_as_anchor(tmp_path: Path) -> None:
    now = START + timedelta(days=100)
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=None, clock=lambda: now)
    for when in (START, START, now):
        log.record(entry(when))
    with sqlite3.connect(tmp_path / "a.db") as conn:
        second = conn.execute("SELECT row_hash FROM decisions WHERE id = 2").fetchone()[0]
    assert log.purge_older_than(30) == 2
    with sqlite3.connect(tmp_path / "a.db") as conn:
        anchor = conn.execute(
            "SELECT last_deleted_id, last_deleted_hash FROM audit_anchors "
            "WHERE table_name = 'decisions'"
        ).fetchone()
    assert anchor == (2, second)
    assert verify_chain(tmp_path / "a.db").ok
