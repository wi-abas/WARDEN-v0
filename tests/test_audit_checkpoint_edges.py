"""Exact limits, counts and messages of audit checkpoints (gaps found by mutation tests)."""

import dataclasses
import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_audit_checkpoint import START, fill, head, save

import warden.audit_checkpoint as module
from warden.audit import GENESIS_HASH, SQLiteAuditLog
from warden.audit_checkpoint import (
    Checkpoint,
    CheckpointError,
    CheckResult,
    Head,
    check_checkpoints,
    make_checkpoint,
    read_checkpoints,
    to_line,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "a.db"
    fill(SQLiteAuditLog(path, retention_days=None), 3)
    return path


def padded(tmp_path: Path, line: str, size: int) -> Path:
    """A checkpoint file of exactly `size` bytes: one valid line, padded with spaces."""
    path = tmp_path / "padded.jsonl"
    path.write_text(line + " " * (size - len(line) - 1) + "\n")
    assert path.stat().st_size == size
    return path


def test_file_of_exactly_ten_mb_is_read(db: Path, tmp_path: Path) -> None:
    assert len(read_checkpoints(padded(tmp_path, head(db), 10 * 1024 * 1024))) == 1


def test_one_byte_over_ten_mb_is_refused(db: Path, tmp_path: Path) -> None:
    with pytest.raises(CheckpointError, match="larger than 10 MB"):
        read_checkpoints(padded(tmp_path, head(db), 10 * 1024 * 1024 + 1))


def test_exactly_the_maximum_number_of_checkpoints(
    db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "MAX_CHECKPOINTS", 2)
    assert len(read_checkpoints(save(tmp_path, head(db), head(db)))) == 2


def test_created_is_at_most_64_characters(db: Path) -> None:
    data = json.loads(head(db))
    Checkpoint.model_validate({**data, "created": "x" * 64})
    with pytest.raises(ValidationError):
        Checkpoint.model_validate({**data, "created": "x" * 65})


def test_models_are_strict_and_frozen(db: Path) -> None:
    with pytest.raises(ValidationError):
        Head.model_validate({"id": "1", "hash": GENESIS_HASH})  # no "1" -> 1
    data = json.loads(head(db))
    with pytest.raises(ValidationError):
        Checkpoint.model_validate({**data, "created": b"2026"})  # no bytes -> str
    checkpoint = Checkpoint.model_validate(data)
    with pytest.raises(ValidationError):
        checkpoint.heads["decisions"].id = 1  # type: ignore[misc]
    with pytest.raises(ValidationError):
        checkpoint.created = "changed"  # type: ignore[misc]
    result = CheckResult(problems=[], skipped=0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.skipped = 1  # type: ignore[misc]


def test_line_has_sorted_keys(db: Path) -> None:
    line = to_line(make_checkpoint(db))
    assert line.startswith('{"created":"') and '},"version":"warden-audit-checkpoint-v1"}' in line
    assert '"decisions":{"hash":"' in line  # nested keys sorted too


def test_exact_skip_count_through_retention(tmp_path: Path) -> None:
    """Empty-log checkpoints (id 0) are checked, never skipped; a checkpoint at exactly
    the retention anchor is checked against it; only older ones are skipped, once each."""
    db = tmp_path / "s.db"
    log = SQLiteAuditLog(db, retention_days=None, clock=lambda: START + timedelta(days=100))
    empty = head(db)  # both tables at id 0
    fill(log, 2)
    older = head(db)  # id 2: deleted by retention below, covered by newer ones
    fill(log, 1)
    at_anchor = head(db)  # id 3: becomes the retention anchor
    fill(log, 1, when=START + timedelta(days=100))
    newest = head(db)  # id 4
    log.purge_older_than(30)
    result = check_checkpoints(
        db, read_checkpoints(save(tmp_path, empty, older, at_anchor, newest))
    )
    assert result == CheckResult(problems=[], skipped=2)  # `older`, in both tables


def test_nothing_skipped_without_retention(db: Path, tmp_path: Path) -> None:
    assert check_checkpoints(db, read_checkpoints(save(tmp_path, head(db)))).skipped == 0


def test_log_emptied_by_hand_names_row_zero(db: Path, tmp_path: Path) -> None:
    saved = save(tmp_path, head(db))
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM decisions")
    problems = check_checkpoints(db, read_checkpoints(saved)).problems
    assert len(problems) == 1
    assert "decisions: the log ends at row id 0, before checkpointed row id 3" in problems[0]


def test_cut_after_retention_names_the_anchor(tmp_path: Path) -> None:
    """Retention deleted rows 1-2 (anchor id 2); then someone deletes the rest by hand.
    The log 'ends' at the anchor, not at row 0."""
    db = tmp_path / "c.db"
    log = SQLiteAuditLog(db, retention_days=None, clock=lambda: START + timedelta(days=100))
    fill(log, 2)
    fill(log, 2, when=START + timedelta(days=100))
    saved = save(tmp_path, head(db))  # id 4
    log.purge_older_than(30)
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM decisions")
    problems = check_checkpoints(db, read_checkpoints(saved)).problems
    assert len(problems) == 1
    assert "decisions: the log ends at row id 2, before checkpointed row id 4" in problems[0]
