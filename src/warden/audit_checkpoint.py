"""Audit checkpoints: anchor the hash chain OUTSIDE this machine.

A hash chain finds an edited, deleted or reordered row. It can't find a rewrite of the
whole log: someone with write access to the database can recompute every hash. The fix
is a copy of the newest hash kept somewhere that person can't reach.

    warden audit head >> checkpoints.jsonl          (e.g. hourly, then copy elsewhere)
    warden audit verify --expect checkpoints.jsonl

`head` prints one JSON line (a checkpoint): for each table, the id and hash of the
newest row. `verify --expect` checks that the log still contains every checkpoint in
the file: the row with that id must still have exactly that hash, and the intact chain
from there to today proves everything in between is unchanged. It fails when:

- a checkpointed row's hash differs (history was rewritten);
- the log ends before a checkpoint (rows were cut from the end, or it's another file);
- the NEWEST checkpoint of a table was deleted by retention and can't be checked any
  more (save checkpoints more often than the retention period). This fails closed on
  purpose: someone rewriting the log could also make it look purged.

Older checkpoints that retention deleted are skipped (and counted): if the newest one
still matches, the chain proves nothing before it changed, and the deleted rows are
gone anyway. Without this, a file appended to every hour would start failing for an
honest log as soon as retention passed its first line.

Not covered: rows written after the newest checkpoint, and deleting the OLDEST rows
dressed up as a retention purge (history before a checkpoint can be removed, not
changed). Keep checkpoints where whoever can edit the database can't.

Read-only. See docs/threat-model.md for what this does and doesn't protect.
"""

import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from warden.audit import GENESIS_HASH, read_snapshot, verify_snapshot
from warden.policy import DuplicateKeyError, no_duplicate_keys

CHECKPOINT_VERSION: Literal["warden-audit-checkpoint-v1"] = "warden-audit-checkpoint-v1"
MAX_CHECKPOINT_FILE_BYTES = 10 * 1024 * 1024
MAX_CHECKPOINTS = 100_000  # mutation-ok: unreachable under the 10 MB limit (defence in depth)

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Table = Literal["decisions", "events"]
TABLES: tuple[Table, ...] = ("decisions", "events")


class Head(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: int = Field(ge=0)  # 0 = the table was empty (hash is the genesis hash)
    hash: Hash


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    version: Literal["warden-audit-checkpoint-v1"]
    created: str = Field(max_length=64)
    heads: dict[Table, Head] = Field(min_length=2)  # both tables, always


class CheckpointError(Exception):
    """The log or the checkpoint file can't be used; the message says why."""


def _anchors(conn: sqlite3.Connection) -> dict[str, tuple[int, str]]:
    rows = conn.execute(
        "SELECT table_name, last_deleted_id, last_deleted_hash FROM audit_anchors"
    ).fetchall()
    try:
        return {str(t): (int(i), str(h)) for t, i, h in rows}
    except ValueError as exc:  # pragma: no cover - verify_chain already refused it
        raise CheckpointError("audit_anchors contains invalid values (edited?)") from exc


def make_checkpoint(path: Path, now: datetime | None = None) -> Checkpoint:
    """The newest id and hash per table. Refuses a log whose chain is already broken:
    saving the head of a tampered log would bless the tampering."""
    heads: dict[Table, Head] = {}
    with read_snapshot(path) as conn:
        report = verify_snapshot(conn)
        if not report.ok:
            raise CheckpointError("the hash chain is broken: " + "; ".join(report.problems))
        anchors = _anchors(conn)
        for table in TABLES:
            head = report.heads[table]
            row = conn.execute(
                f"SELECT id FROM {table} WHERE row_hash = ?",  # noqa: S608 (constant)
                (head,),
            ).fetchone()
            if row is not None:
                row_id = int(row[0])
            elif table in anchors and anchors[table][1] == head:
                row_id = anchors[table][0]  # everything was purged; the anchor is the head
            elif head == GENESIS_HASH:
                row_id = 0
            else:  # pragma: no cover - impossible in one snapshot
                raise CheckpointError("the log changed while reading it; try again")
            heads[table] = Head(id=row_id, hash=head)
    created = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    return Checkpoint(version=CHECKPOINT_VERSION, created=created, heads=heads)


def read_checkpoints(path: Path) -> list[Checkpoint]:
    """Every line of a checkpoint file (blank lines ignored). Strict: one bad line and
    the whole file is refused, so a garbled file can never pass as 'nothing to check'."""
    try:
        if path.stat().st_size > MAX_CHECKPOINT_FILE_BYTES:
            raise CheckpointError(f"{path} is larger than 10 MB")
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckpointError(f"can't read {path}: {type(exc).__name__}") from exc
    checkpoints: list[Checkpoint] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line, object_pairs_hook=no_duplicate_keys)
            checkpoints.append(Checkpoint.model_validate(data))
        except (ValueError, RecursionError, DuplicateKeyError, ValidationError) as exc:
            raise CheckpointError(f"{path} line {number} isn't a valid checkpoint") from exc
        if len(checkpoints) > MAX_CHECKPOINTS:
            raise CheckpointError(f"{path} has more than {MAX_CHECKPOINTS} checkpoints")
    if not checkpoints:
        raise CheckpointError(f"{path} contains no checkpoints")
    return checkpoints


@dataclass(frozen=True)
class CheckResult:
    problems: list[str]  # empty = the log contains every checkable checkpoint
    skipped: int  # older checkpoints whose rows retention has deleted


def check_checkpoints(path: Path, checkpoints: list[Checkpoint]) -> CheckResult:
    """Compare the log with saved checkpoints. Call only after verify_chain(path)
    reported an intact chain."""
    newest = {t: max(c.heads[t].id for c in checkpoints) for t in TABLES}
    problems: list[str] = []
    skipped = 0
    with read_snapshot(path) as conn:
        anchors = _anchors(conn)
        for number, checkpoint in enumerate(checkpoints, start=1):
            for table, head in sorted(checkpoint.heads.items()):
                anchor = anchors.get(table)
                if anchor is not None and 0 < head.id < anchor[0] and head.id < newest[table]:
                    skipped += 1  # deleted by retention; a newer checkpoint covers it
                    continue
                problem = _check_head(conn, table, head, anchor)
                if problem:
                    problems.append(f"checkpoint {number} ({checkpoint.created}), {problem}")
    return CheckResult(problems, skipped)


def _check_head(
    conn: sqlite3.Connection, table: str, head: Head, anchor: tuple[int, str] | None
) -> str | None:
    if head.id == 0:
        return None if head.hash == GENESIS_HASH else f"{table}: invalid empty-table hash"
    row = conn.execute(
        f"SELECT row_hash FROM {table} WHERE id = ?",  # noqa: S608 (constant table)
        (head.id,),
    ).fetchone()
    if row is not None:
        if row[0] == head.hash:
            return None
        return f"{table} row id {head.id}: hash differs (history was rewritten)"
    if anchor is not None and anchor[0] == head.id:
        if anchor[1] == head.hash:
            return None
        return f"{table} row id {head.id}: hash differs (history was rewritten)"
    if anchor is not None and head.id < anchor[0]:  # mutation-ok: == handled above
        return (
            f"{table} row id {head.id}: deleted by retention, and no newer checkpoint "
            f"(save checkpoints more often than the retention period)"
        )
    newest = conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0]  # noqa: S608
    newest = max(int(newest or 0), anchor[0] if anchor else 0)
    return (
        f"{table}: the log ends at row id {newest}, before checkpointed row id {head.id} "
        f"(rows cut from the end, or a different database)"
    )


def to_line(checkpoint: Checkpoint) -> str:
    return json.dumps(checkpoint.model_dump(), separators=(",", ":"), sort_keys=True)


def run_head(path: Path) -> int:
    """`warden audit head`: print one checkpoint line. 0 ok, 1 chain broken, 2 can't read."""
    try:
        if not path.is_file():
            print(f"warden: no audit database at {path}", file=sys.stderr)
            return 2
        checkpoint = make_checkpoint(path)
    except (sqlite3.Error, OSError) as exc:
        print(f"warden: can't read {path}: {type(exc).__name__}", file=sys.stderr)
        return 2
    except CheckpointError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 1
    print(to_line(checkpoint))
    return 0


def run_expect(path: Path, expect: Path) -> int:
    """`warden audit verify --expect FILE`, after the chain itself verified."""
    try:
        checkpoints = read_checkpoints(expect)
        result = check_checkpoints(path, checkpoints)
    except CheckpointError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    except sqlite3.Error as exc:
        print(f"warden: can't read {path}: {type(exc).__name__}", file=sys.stderr)
        return 2
    if result.problems:
        for problem in result.problems:
            print(f"BROKEN: {problem}")
        return 1
    print(f"OK: the hash chain is intact and matches the {len(checkpoints)} checkpoints.")
    if result.skipped:
        print(f"({result.skipped} older table heads were deleted by retention and skipped.)")
    return 0
