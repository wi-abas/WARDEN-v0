"""Tamper-evident audit log: a hash chain over decisions and events, and `audit verify`."""

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden import cli
from warden.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditEvent,
    EventKind,
    SQLiteAuditLog,
    verify_chain,
)
from warden.models import Decision

START = datetime(2026, 6, 1, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now


def entry(when: datetime = START, agent: str = "a") -> AuditEntry:
    return AuditEntry(
        timestamp=when.isoformat(),
        agent_id=agent,
        tool="t",
        decision=Decision.ALLOW,
        reason="r",
        matched_rule=None,
        action_hash=None,
    )


def event(when: datetime = START) -> AuditEvent:
    return AuditEvent(timestamp=when.isoformat(), kind=EventKind.REQUEST_REJECTED, reason="x")


def filled(path: Path, n: int = 5) -> SQLiteAuditLog:
    log = SQLiteAuditLog(path, retention_days=None)
    for i in range(n):
        log.record(entry(agent=f"agent-{i}"))
        log.record_event(event())
    return log


def sql(path: Path, statement: str, *args: object) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(statement, args)


def test_intact_log_verifies(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    filled(path)
    report = verify_chain(path)
    assert report.ok and report.checked == {"decisions": 5, "events": 5}
    with sqlite3.connect(path) as conn:
        first_prev = conn.execute("SELECT prev_hash FROM decisions ORDER BY id LIMIT 1").fetchone()
        last = conn.execute("SELECT row_hash FROM decisions ORDER BY id DESC LIMIT 1").fetchone()
    assert first_prev == (GENESIS_HASH,)
    assert report.heads["decisions"] == last[0]


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        ("UPDATE decisions SET decision = 'deny' WHERE id = 3", "decisions row id 3: contents"),
        ("UPDATE events SET reason = 'nothing to see' WHERE id = 2", "events row id 2: contents"),
        ("DELETE FROM decisions WHERE id = 2", "decisions row id 3: doesn't follow"),
        ("DELETE FROM decisions WHERE id = 1", "decisions row id 2: doesn't follow"),
        ("UPDATE decisions SET row_hash = NULL WHERE id = 4", "decisions row id 4: hash missing"),
        (
            "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason) "
            "VALUES ('x', 'a', 't', 'allow', 'forged')",
            "decisions row id 6: hash missing",
        ),
        ("UPDATE decisions SET id = 99 WHERE id = 2", "decisions row id 3: doesn't follow"),
    ],
)
def test_tampering_is_found_at_the_first_broken_row(
    tmp_path: Path, tamper: str, problem: str
) -> None:
    path = tmp_path / "a.db"
    filled(path)
    sql(path, tamper)
    report = verify_chain(path)
    assert not report.ok
    assert report.problems[0].startswith(problem)


def test_rehashing_one_row_breaks_the_next(tmp_path: Path) -> None:
    from warden.audit import row_hash

    path = tmp_path / "a.db"
    filled(path)
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT id, timestamp, agent_id, tool, decision, reason, matched_rule, action_hash, "
            "approval_id, prev_hash FROM decisions WHERE id = 2"
        ).fetchone()
        values = (row[1], row[2], row[3], "deny", *row[5:9])
        conn.execute(
            "UPDATE decisions SET decision = 'deny', row_hash = ? WHERE id = 2",
            (row_hash("decisions", 2, row[9], values),),
        )
    assert verify_chain(path).problems[0].startswith("decisions row id 3: doesn't follow")


def test_cutting_the_tail_changes_the_head(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    filled(path)
    before = verify_chain(path).heads["decisions"]
    sql(path, "DELETE FROM decisions WHERE id = 5")
    after = verify_chain(path)
    assert after.ok and after.heads["decisions"] != before  # only an outside copy shows it


# --- Retention ------------------------------------------------------------------------


def test_chain_survives_retention_purges(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    clock = Clock()
    log = SQLiteAuditLog(path, retention_days=None, clock=clock)
    for days_ago in (200, 150, 100, 10, 0):
        log.record(entry(START - timedelta(days=days_ago)))
        log.record_event(event(START - timedelta(days=days_ago)))
    log.purge_older_than(90)
    report = verify_chain(path)
    assert report.ok, report.problems
    assert report.checked == {"decisions": 2, "events": 3}  # 2 kept + the purge event
    log.record(entry())
    assert verify_chain(path).ok
    # A second purge moves the anchors and records them again.
    clock.now = START + timedelta(days=95)
    log.purge_older_than(90)
    log.record(entry(clock.now))
    assert verify_chain(path).ok


def test_purging_everything_then_writing_more(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = SQLiteAuditLog(path, retention_days=None, clock=Clock())
    log.record(entry(START - timedelta(days=100)))
    log.record(entry(START - timedelta(days=99)))
    log.purge_older_than(90)
    log.record(entry())
    report = verify_chain(path)
    assert report.ok and report.checked["decisions"] == 1


def test_editing_the_anchor_is_found(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = SQLiteAuditLog(path, retention_days=None, clock=Clock())
    for days_ago in (100, 99, 0):
        log.record(entry(START - timedelta(days=days_ago)))
    log.purge_older_than(90)
    # Someone deletes one more old row and moves the anchor to hide it.
    with sqlite3.connect(path) as conn:
        first = conn.execute("SELECT id, row_hash FROM decisions ORDER BY id LIMIT 1").fetchone()
        conn.execute("DELETE FROM decisions WHERE id = ?", (first[0],))
        conn.execute(
            "UPDATE audit_anchors SET last_deleted_hash = ? WHERE table_name = 'decisions'",
            (first[1],),
        )
    assert verify_chain(path).problems == [
        "audit_anchors: doesn't match the last recorded purge (anchors edited?)"
    ]
    sql(path, "UPDATE events SET chain_anchor = 'not json' WHERE kind = 'audit_purged'")
    assert not verify_chain(path).ok


def test_out_of_order_timestamps_never_cut_the_middle(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = SQLiteAuditLog(path, retention_days=None, clock=Clock())
    log.record(entry(START - timedelta(days=100), agent="old"))
    log.record(entry(START, agent="new"))
    log.record(entry(START - timedelta(days=100), agent="old-but-late"))  # clock moved
    log.purge_older_than(90)
    assert [e.agent_id for e in log.recent()] == ["old-but-late", "new"]
    assert verify_chain(path).ok


# --- Old databases, concurrency -------------------------------------------------------


def test_old_database_is_upgraded_and_old_rows_reported(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, "
            "agent_id TEXT, tool TEXT, decision TEXT, reason TEXT, matched_rule TEXT, "
            "action_hash TEXT)"
        )
        conn.execute(
            "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason) "
            "VALUES ('2026-01-01T00:00:00+00:00', 'a', 't', 'allow', 'r')"
        )
    path.chmod(0o600)
    log = SQLiteAuditLog(path, retention_days=None)
    log.record(entry())
    report = verify_chain(path)
    assert report.ok and report.unchained["decisions"] == 1 and report.checked["decisions"] == 1
    # An unchained row AFTER chained ones is an insertion, not history.
    sql(
        path,
        "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason) "
        "VALUES ('x', 'a', 't', 'allow', 'r')",
    )
    assert not verify_chain(path).ok


def test_concurrent_writers_keep_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = SQLiteAuditLog(path, retention_days=None)

    def worker(n: int) -> None:
        for i in range(25):
            log.record(entry(agent=f"w{n}-{i}"))
            log.record_event(event())

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    report = verify_chain(path)
    assert report.ok and report.checked == {"decisions": 200, "events": 200}


# --- CLI ------------------------------------------------------------------------------


def test_cli_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "a.db"
    filled(path, 3)
    assert cli.main(["audit", "verify", "--audit-db", str(path)]) == 0
    out = capsys.readouterr().out
    assert "decisions: 3 rows verified" in out and "OK" in out
    sql(path, "UPDATE decisions SET reason = 'x' WHERE id = 2")
    assert cli.main(["audit", "verify", "--audit-db", str(path)]) == 1
    assert "BROKEN: decisions row id 2" in capsys.readouterr().out


def test_cli_verify_uses_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "env.db"
    filled(path, 1)
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(path))
    assert cli.main(["audit", "verify"]) == 0
    sql(path, "DELETE FROM decisions")
    sql(
        path,
        "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason) "
        "VALUES ('x', 'a', 't', 'allow', 'r')",
    )
    assert cli.main(["audit", "verify"]) == 0  # an unchained-only table: nothing to check
    assert "1 older rows" in capsys.readouterr().out


def test_cli_verify_missing_or_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["audit", "verify", "--audit-db", str(tmp_path / "none.db")]) == 2
    bad = tmp_path / "bad.db"
    bad.write_text("not a database at all, just text " * 100)
    assert cli.main(["audit", "verify", "--audit-db", str(bad)]) == 2
    assert "can't read" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["audit#1.db", "audit?mode=rw.db", "audit%20x.db", "a b.db"])
def test_verify_opens_exactly_the_given_file(tmp_path: Path, name: str) -> None:
    # A decoy with the name a naive URI would open instead ("audit" for "audit#1.db").
    decoy = tmp_path / name.split("#")[0].split("?")[0]
    if decoy.name != name:
        filled(decoy, 1)
    path = tmp_path / name
    filled(path, 2)
    sql(path, "UPDATE decisions SET reason = 'edited' WHERE id = 1")
    report = verify_chain(path)
    assert not report.ok and report.problems[0].startswith("decisions row id 1")
