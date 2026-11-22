"""Audit retention: old entries are deleted, the deletion is recorded, and it can be off."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.audit import (
    AuditEntry,
    AuditEvent,
    EventKind,
    SQLiteAuditLog,
)
from warden.models import Decision

START = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now


def entry(when: datetime, agent: str = "a") -> AuditEntry:
    return AuditEntry(
        timestamp=when.isoformat(),
        agent_id=agent,
        tool="t",
        decision=Decision.ALLOW,
        reason="r",
        matched_rule=None,
        action_hash=None,
    )


def event(when: datetime) -> AuditEvent:
    return AuditEvent(timestamp=when.isoformat(), kind=EventKind.REQUEST_REJECTED, reason="x")


def seed(path: Path) -> None:
    """Old and new rows, written with retention off so nothing is purged yet."""
    log = SQLiteAuditLog(path, retention_days=None)
    for days_ago, agent in [(200, "ancient"), (91, "old"), (89, "recent"), (0, "today")]:
        log.record(entry(START - timedelta(days=days_ago), agent))
    log.record_event(event(START - timedelta(days=100)))
    log.record_event(event(START - timedelta(days=1)))


def test_startup_purges_entries_older_than_retention(tmp_path: Path) -> None:
    seed(tmp_path / "a.db")
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=90, clock=Clock())
    assert [e.agent_id for e in log.recent()] == ["today", "recent"]
    kinds = [e.kind for e in log.recent_events()]
    assert kinds == [EventKind.AUDIT_PURGED, EventKind.REQUEST_REJECTED]


def test_purge_is_recorded_with_counts(tmp_path: Path) -> None:
    seed(tmp_path / "a.db")
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=90, clock=Clock())
    purged = log.recent_events()[0]
    assert purged.reason == "deleted 2 decisions and 1 events older than 90 days"
    assert purged.timestamp == START.isoformat()


def test_nothing_to_purge_records_nothing(tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=90, clock=Clock())
    log.record(entry(START))
    assert log.recent_events() == []


def test_retention_off_keeps_everything(tmp_path: Path) -> None:
    seed(tmp_path / "a.db")
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=None, clock=Clock())
    assert len(log.recent()) == 4
    assert len(log.recent_events()) == 2


def test_purges_again_after_a_day_while_running(tmp_path: Path) -> None:
    clock = Clock()
    log = SQLiteAuditLog(tmp_path / "a.db", retention_days=90, clock=clock)
    log.record(entry(START - timedelta(days=89), "ages-out"))

    clock.now = START + timedelta(hours=23)  # less than a day: no purge yet
    log.record(entry(clock.now, "x"))
    assert "ages-out" in [e.agent_id for e in log.recent()]

    clock.now = START + timedelta(days=2)  # a day later and the entry is now 91 days old
    log.record(entry(clock.now, "y"))
    log.wait_for_purge()
    assert "ages-out" not in [e.agent_id for e in log.recent()]


def test_purge_failure_never_blocks_a_write(tmp_path: Path) -> None:
    class PurgeFails(SQLiteAuditLog):
        def purge_older_than(self, days: int) -> int:
            raise RuntimeError("boom")

    log = PurgeFails(tmp_path / "a.db", retention_days=90, clock=Clock())
    log.record(entry(START))
    assert len(log.recent()) == 1


@pytest.mark.parametrize("bad", [0, -5, True, 1.5, "90"])
def test_bad_retention_is_rejected(tmp_path: Path, bad: object) -> None:
    with pytest.raises(ValueError):
        SQLiteAuditLog(tmp_path / "a.db", retention_days=bad)  # type: ignore[arg-type]


def test_default_retention_is_90_days(tmp_path: Path) -> None:
    assert SQLiteAuditLog(tmp_path / "a.db").retention_days == 90


def test_failed_purge_is_retried_on_the_next_write(tmp_path: Path) -> None:
    attempts: list[int] = []

    class FailsOnce(SQLiteAuditLog):
        def purge_older_than(self, days: int) -> int:
            attempts.append(days)
            if len(attempts) == 1:
                raise RuntimeError("database busy")
            return super().purge_older_than(days)

    log = FailsOnce(tmp_path / "a.db", retention_days=90, clock=Clock())  # attempt 1 fails
    log.record(entry(START))  # attempt 2 right away, not a day later
    log.wait_for_purge()
    assert len(attempts) == 2
    log.record(entry(START))  # succeeded: no more attempts today
    log.wait_for_purge()
    assert len(attempts) == 2


def test_write_does_not_wait_for_a_slow_purge(tmp_path: Path) -> None:
    import threading
    import time

    release = threading.Event()

    class SlowPurge(SQLiteAuditLog):
        def purge_older_than(self, days: int) -> int:
            if self._last_purge is not None and self._last_purge > START:
                release.wait(5)  # the background purge blocks until we let it go
            return 0

    clock = Clock()
    log = SlowPurge(tmp_path / "a.db", retention_days=90, clock=clock)
    clock.now = START + timedelta(days=2)
    started = time.monotonic()
    log.record(entry(clock.now))  # triggers the (slow) purge in the background
    assert time.monotonic() - started < 1
    assert len(log.recent()) == 1
    release.set()
    log.wait_for_purge()


def test_only_one_purge_runs_at_a_time(tmp_path: Path) -> None:
    import threading

    started = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    class SlowPurge(SQLiteAuditLog):
        def purge_older_than(self, days: int) -> int:
            calls.append(days)
            if len(calls) > 1:  # the first (startup) purge is quick
                started.set()
                release.wait(5)
            return 0

    clock = Clock()
    log = SlowPurge(tmp_path / "a.db", retention_days=90, clock=clock)
    clock.now = START + timedelta(days=2)
    log.record(entry(clock.now))  # starts a background purge that blocks
    assert started.wait(5)
    clock.now = START + timedelta(days=4)  # a purge would be due again...
    log.record(entry(clock.now))  # ...but one is still running: don't start another
    release.set()
    log.wait_for_purge()
    assert len(calls) == 2
