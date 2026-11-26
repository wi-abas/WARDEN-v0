"""After a crash in the middle of a write, SQLite leaves a journal next to the database.
The audit tools read only, so they can't undo that write: they say what to do instead."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_audit_chain import filled

from warden import cli
from warden.audit import verify_chain
from warden.audit_checkpoint import run_expect

# Writes more than fits in its cache, so the database itself is changed, then dies.
CRASH = """
import os, sqlite3, sys
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("PRAGMA cache_size = 1")
conn.execute("BEGIN IMMEDIATE")
for _ in range(300):
    conn.execute(
        "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason) "
        "VALUES ('t', 'a', 't', 'allow', ?)", ("x" * 2000,))
os._exit(1)
"""


@pytest.fixture
def crashed(tmp_path: Path) -> Path:
    path = tmp_path / "a.db"
    filled(path, 2)
    subprocess.run([sys.executable, "-c", CRASH, str(path)], check=False)  # noqa: S603
    assert (tmp_path / "a.db-journal").stat().st_size > 0
    return path


def files(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}


def test_verify_and_head_explain_a_leftover_journal(
    crashed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    link = tmp_path / "link.db"
    os.symlink(crashed, link)
    before = files(tmp_path)
    for command in ("verify", "head"):
        for path in (crashed, link):
            assert cli.main(["audit", command, "--audit-db", str(path)]) == 2
            captured = capsys.readouterr()
            assert captured.out == ""
            assert "a.db-journal" in captured.err
            assert "opy both files" in captured.err
            assert "starting Warden" in captured.err
    assert files(tmp_path) == before  # read-only: the evidence is untouched


def test_expect_explains_it_too(
    crashed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A crash between verifying the chain and comparing the checkpoints."""
    checkpoints = tmp_path / "c.jsonl"
    head = '{"id":0,"hash":"' + "0" * 64 + '"}'
    checkpoints.write_text(
        '{"version":"warden-audit-checkpoint-v1","created":"now","heads":{"decisions":'
        + head
        + ',"events":'
        + head
        + "}}\n"
    )
    assert run_expect(crashed, checkpoints) == 2
    assert "a.db-journal" in capsys.readouterr().err


def test_the_advice_works(crashed: Path, tmp_path: Path) -> None:
    """Copy both files, let SQLite undo the write in the copy, verify the copy."""
    original = files(tmp_path)
    folder = tmp_path / "copy"
    folder.mkdir()
    for name, content in original.items():
        (folder / name).write_bytes(content)
    conn = sqlite3.connect(folder / "a.db")
    conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    conn.close()
    report = verify_chain(folder / "a.db")
    assert report.ok
    assert report.checked == {"decisions": 2, "events": 2}
    assert files(tmp_path) == original


def test_a_locked_database_is_not_called_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.db"
    filled(path, 1)
    connect = sqlite3.connect

    def impatient(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn: sqlite3.Connection = connect(*args, **{**kwargs, "timeout": 0})
        return conn

    lock = connect(path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    monkeypatch.setattr(sqlite3, "connect", impatient)
    assert cli.main(["audit", "verify", "--audit-db", str(path)]) == 2
    lock.close()
    assert capsys.readouterr().err == f"warden: can't read {path}: OperationalError\n"
