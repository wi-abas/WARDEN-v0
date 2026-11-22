"""Audit checkpoints: `warden audit head` and `warden audit verify --expect`."""

import json
import sqlite3
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
    row_hash,
)
from warden.audit_checkpoint import (
    CheckpointError,
    check_checkpoints,
    make_checkpoint,
    read_checkpoints,
    to_line,
)
from warden.models import Decision

START = datetime(2026, 6, 1, tzinfo=UTC)


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


def fill(log: SQLiteAuditLog, n: int, when: datetime = START) -> None:
    for i in range(n):
        log.record(entry(when, agent=f"agent-{i}"))
        log.record_event(event(when))


def save(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "checkpoints.jsonl"
    path.write_text("".join(line + "\n" for line in lines))
    return path


def head(db: Path) -> str:
    return to_line(make_checkpoint(db))


def expect(db: Path, checkpoints: Path) -> list[str]:
    return check_checkpoints(db, read_checkpoints(checkpoints))


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "a.db"
    fill(SQLiteAuditLog(path, retention_days=None), 5)
    return path


def test_checkpoint_names_the_newest_rows(db: Path) -> None:
    checkpoint = make_checkpoint(db, now=START)
    assert checkpoint.created == "2026-06-01T00:00:00+00:00"
    assert {t: h.id for t, h in checkpoint.heads.items()} == {"decisions": 5, "events": 5}
    with sqlite3.connect(db) as conn:
        newest = conn.execute("SELECT row_hash FROM decisions WHERE id = 5").fetchone()[0]
    assert checkpoint.heads["decisions"].hash == newest


def test_log_that_grew_still_matches(db: Path, tmp_path: Path) -> None:
    saved = save(tmp_path, head(db))
    fill(SQLiteAuditLog(db, retention_days=None), 3)
    saved.write_text(saved.read_text() + head(db) + "\n")
    assert expect(db, saved) == []


def test_empty_log(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    SQLiteAuditLog(db, retention_days=None)
    checkpoint = make_checkpoint(db)
    assert all(h.id == 0 and h.hash == GENESIS_HASH for h in checkpoint.heads.values())
    fill(SQLiteAuditLog(db, retention_days=None), 2)
    assert expect(db, save(tmp_path, to_line(checkpoint))) == []


def rewrite_everything(db: Path, new_reason: str) -> None:
    """The attack a plain hash chain can't see: edit a row, then recompute every hash."""
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE decisions SET reason = ? WHERE id = 2", (new_reason,))
        prev = GENESIS_HASH
        columns = (
            "timestamp, agent_id, tool, decision, reason, matched_rule, action_hash, approval_id"
        )
        for row in conn.execute(f"SELECT id, {columns} FROM decisions ORDER BY id").fetchall():  # noqa: S608
            new = row_hash("decisions", row[0], prev, tuple(row[1:]))
            conn.execute(
                "UPDATE decisions SET prev_hash = ?, row_hash = ? WHERE id = ?", (prev, new, row[0])
            )
            prev = new


def test_full_rewrite_is_found(db: Path, tmp_path: Path) -> None:
    saved = save(tmp_path, head(db))
    rewrite_everything(db, "nothing happened here")
    # The chain alone looks fine: that's the point of keeping a checkpoint elsewhere.
    assert cli.verify_audit(db) == 0
    problems = expect(db, saved)
    assert problems == [
        f"checkpoint 1 ({read_checkpoints(saved)[0].created}), decisions row id 5: hash "
        "differs (history was rewritten)"
    ]
    assert cli.verify_audit(db, saved) == 1


def test_cutting_the_end_is_found(db: Path, tmp_path: Path) -> None:
    saved = save(tmp_path, head(db))
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM events WHERE id >= 4")
    problems = expect(db, saved)
    assert len(problems) == 1
    assert "events: the log ends at row id 3, before checkpointed row id 5" in problems[0]


def test_another_database_is_found(db: Path, tmp_path: Path) -> None:
    saved = save(tmp_path, head(db))
    other = tmp_path / "other.db"
    later = START + timedelta(seconds=1)
    fill(SQLiteAuditLog(other, retention_days=None), 5, when=later)  # same ids, other rows
    assert len(expect(other, saved)) == 2


def test_retention_keeps_checkpoints_checkable(tmp_path: Path) -> None:
    db = tmp_path / "r.db"
    now = START + timedelta(days=100)
    log = SQLiteAuditLog(db, retention_days=None, clock=lambda: now)
    fill(log, 3, when=START)  # old
    saved = save(tmp_path, head(db))  # checkpoint at the last old row
    fill(log, 2, when=now)
    log.purge_older_than(30)
    # The checkpointed row was purged, but it's exactly the anchor: still checkable.
    assert expect(db, saved) == []
    saved_new = save(tmp_path, head(db))
    assert expect(db, saved_new) == []


def test_everything_purged_then_checkpoint(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    log = SQLiteAuditLog(db, retention_days=None)
    fill(log, 2)
    log.purge_older_than(1)
    checkpoint = make_checkpoint(db)
    assert checkpoint.heads["decisions"].id == 2  # the anchor stands in for the head
    assert expect(db, save(tmp_path, to_line(checkpoint))) == []


def test_checkpoint_older_than_retention_fails_closed(tmp_path: Path) -> None:
    db = tmp_path / "o.db"
    log = SQLiteAuditLog(db, retention_days=None, clock=lambda: START + timedelta(days=100))
    fill(log, 1, when=START)
    old = save(tmp_path, head(db))
    fill(log, 2, when=START)
    fill(log, 1, when=START + timedelta(days=100))
    log.purge_older_than(30)
    problems = expect(db, old)
    assert problems and all("deleted by retention, can't be checked" in p for p in problems)


def test_head_refuses_a_broken_chain(db: Path) -> None:
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE decisions SET reason = 'x' WHERE id = 2")
    with pytest.raises(CheckpointError, match="chain is broken"):
        make_checkpoint(db)


def test_invalid_genesis_checkpoint(db: Path, tmp_path: Path) -> None:
    line = json.loads(head(db))
    line["heads"]["events"] = {"id": 0, "hash": "1" * 64}
    assert expect(db, save(tmp_path, json.dumps(line))) == [
        f"checkpoint 1 ({line['created']}), events: invalid empty-table hash"
    ]


def test_anchor_mismatch_is_a_rewrite(tmp_path: Path) -> None:
    db = tmp_path / "m.db"
    log = SQLiteAuditLog(db, retention_days=None)
    fill(log, 2)
    line = json.loads(head(db))
    line["heads"]["decisions"]["hash"] = "a" * 64
    log.purge_older_than(1)
    assert "hash differs" in expect(db, save(tmp_path, json.dumps(line)))[0]


@pytest.mark.parametrize(
    "content",
    [
        "",
        "\n\n",
        "not json",
        '{"version": "warden-audit-checkpoint-v1"}',
        '{"version": "v0", "created": "x", "heads": {}}',
        # only one table: a checkpoint must cover both
        '{"version": "warden-audit-checkpoint-v1", "created": "x", "heads": {"decisions": '
        '{"id": 1, "hash": "' + "a" * 64 + '"}}}',
        # duplicate key
        '{"version": "warden-audit-checkpoint-v1", "version": "warden-audit-checkpoint-v1"}',
        # bad hash / negative id / extra field
        '{"version": "warden-audit-checkpoint-v1", "created": "x", "heads": {"decisions": '
        '{"id": 1, "hash": "XYZ"}, "events": {"id": 1, "hash": "' + "a" * 64 + '"}}}',
        '{"version": "warden-audit-checkpoint-v1", "created": "x", "heads": {"decisions": '
        '{"id": -1, "hash": "' + "a" * 64 + '"}, "events": {"id": 1, "hash": "' + "a" * 64 + '"}}}',
        '{"version": "warden-audit-checkpoint-v1", "created": "x", "extra": 1, "heads": {}}',
    ],
)
def test_bad_checkpoint_files_are_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "c.jsonl"
    path.write_text(content)
    with pytest.raises(CheckpointError):
        read_checkpoints(path)


def test_one_bad_line_refuses_the_whole_file(db: Path, tmp_path: Path) -> None:
    with pytest.raises(CheckpointError, match="line 2"):
        read_checkpoints(save(tmp_path, head(db), "garbage", head(db)))


def test_unreadable_or_huge_checkpoint_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(CheckpointError, match="can't read"):
        read_checkpoints(tmp_path / "missing.jsonl")
    binary = tmp_path / "bin.jsonl"
    binary.write_bytes(b"\xff\xfe")
    with pytest.raises(CheckpointError, match="can't read"):
        read_checkpoints(binary)
    import warden.audit_checkpoint as module

    monkeypatch.setattr(module, "MAX_CHECKPOINT_FILE_BYTES", 10)
    big = tmp_path / "big.jsonl"
    big.write_text("x" * 11)
    with pytest.raises(CheckpointError, match="larger than"):
        read_checkpoints(big)


def test_too_many_checkpoints(db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import warden.audit_checkpoint as module

    monkeypatch.setattr(module, "MAX_CHECKPOINTS", 2)
    with pytest.raises(CheckpointError, match="more than 2"):
        read_checkpoints(save(tmp_path, head(db), head(db), head(db)))


# --- CLI ---------------------------------------------------------------------------------


def test_cli_head_and_verify(db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["audit", "head", "--audit-db", str(db)]) == 0
    line = capsys.readouterr().out.strip()
    assert json.loads(line)["heads"]["decisions"]["id"] == 5
    saved = save(tmp_path, line)
    assert cli.main(["audit", "verify", "--audit-db", str(db), "--expect", str(saved)]) == 0
    assert "contains all 1 checkpoints" in capsys.readouterr().out
    rewrite_everything(db, "edited")
    assert cli.main(["audit", "verify", "--audit-db", str(db), "--expect", str(saved)]) == 1
    assert "BROKEN: checkpoint 1" in capsys.readouterr().out


def test_cli_head_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["audit", "head", "--audit-db", str(tmp_path / "none.db")]) == 2
    assert "no audit database" in capsys.readouterr().err
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 100)
    assert cli.main(["audit", "head", "--audit-db", str(junk)]) == 2
    assert "can't read" in capsys.readouterr().err
    db = tmp_path / "b.db"
    fill(SQLiteAuditLog(db, retention_days=None), 2)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE events SET reason = 'edited' WHERE id = 1")
    assert cli.main(["audit", "head", "--audit-db", str(db)]) == 1
    assert "chain is broken" in capsys.readouterr().err


def test_cli_verify_expect_errors(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("nope")
    assert cli.main(["audit", "verify", "--audit-db", str(db), "--expect", str(bad)]) == 2
    assert "isn't a valid checkpoint" in capsys.readouterr().err

    import warden.audit_checkpoint as module

    def locked(*_: object) -> list[str]:
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(module, "check_checkpoints", locked)
    saved = save(tmp_path, head(db))
    assert cli.main(["audit", "verify", "--audit-db", str(db), "--expect", str(saved)]) == 2
    assert "can't read" in capsys.readouterr().err


def test_cli_broken_chain_wins_over_expect(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = save(tmp_path, head(db))
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE decisions SET reason = 'x' WHERE id = 3")
    assert cli.main(["audit", "verify", "--audit-db", str(db), "--expect", str(saved)]) == 1
    assert "BROKEN: decisions row id 3" in capsys.readouterr().out
