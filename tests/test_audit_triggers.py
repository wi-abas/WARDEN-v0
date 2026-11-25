"""A write that did not land is a failed write: nothing is allowed without a record, even
when someone who can edit the database adds triggers, views or odd tables to it."""

import sqlite3
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, shown
from test_audit_chain import Clock, entry, event, filled, sql

import warden.api
from warden import audit, cli
from warden.api import StartupError, create_app
from warden.approvals import ApprovalDB, ApprovalStore
from warden.audit import SQLiteAuditLog, verify_chain
from warden.settings import Settings

ADMIN = {"X-Warden-Admin-Key": ADMIN_KEY}
DROP_ALLOWS = (
    "CREATE TRIGGER z BEFORE INSERT ON decisions WHEN new.decision = 'allow' "
    "BEGIN SELECT RAISE(IGNORE); END"
)

# Ways a trigger can lose or change rows ({t}: the table written to).
TRIGGERS = {
    "ignore insert": "BEFORE INSERT ON {t} BEGIN SELECT RAISE(IGNORE); END",
    "ignore update": "BEFORE UPDATE ON {t} BEGIN SELECT RAISE(IGNORE); END",
    "delete after insert": "AFTER INSERT ON {t} BEGIN DELETE FROM {t} WHERE id = new.id; END",
    "delete after update": "AFTER UPDATE ON {t} BEGIN DELETE FROM {t} WHERE id = new.id; END",
    "rewrite after insert": "AFTER INSERT ON {t} "
    "BEGIN UPDATE {t} SET reason = 'fake' WHERE id = new.id; END",
    "rewrite after update": "AFTER UPDATE OF row_hash ON {t} "
    "BEGIN UPDATE {t} SET reason = 'fake' WHERE id = new.id; END",
    "delete an older row": "AFTER INSERT ON {t} BEGIN DELETE FROM {t} WHERE id = 1; END",
    "change approvals": "AFTER INSERT ON {t} BEGIN UPDATE approvals SET status = 'approved'; END",
}


def dump(path: Path) -> list[str]:
    with sqlite3.connect(path) as conn:
        return list(conn.iterdump())


def write(log: SQLiteAuditLog, table: str) -> None:
    if table == "decisions":
        log.record(entry())
    else:
        log.record_event(event())


def rebuild(path: Path, table: str, reason_type: str) -> None:
    """Replace `table` with one that differs only in the type of its `reason` column."""
    with sqlite3.connect(path) as conn:
        [old] = conn.execute("SELECT sql FROM sqlite_master WHERE name = ?", (table,)).fetchone()
        new = old.replace("reason       TEXT NOT NULL", f"reason {reason_type}")
        assert new != old
        conn.execute(f"DROP TABLE {table}")
        conn.execute(new)


@pytest.mark.parametrize("schema_check", [True, False])
@pytest.mark.parametrize("table", ["decisions", "events"])
@pytest.mark.parametrize("name", TRIGGERS)
def test_a_trigger_on_the_written_table_fails_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, table: str, schema_check: bool
) -> None:
    """Added while the server runs, and caught on the next write. Two independent layers:
    without the schema check, the check of the row itself still catches it."""
    path = tmp_path / "a.db"
    log = filled(path, 2)
    ApprovalDB(path)
    sql(path, "INSERT INTO approvals VALUES ('id', 'a', 't', 'h', 'used', 9e9, 1, 1, 1)")
    sql(path, "CREATE TRIGGER z " + TRIGGERS[name].format(t=table))
    before = dump(path)
    if not schema_check:
        monkeypatch.setattr(audit, "_schema_problems", lambda conn: [])
    with pytest.raises(sqlite3.DatabaseError):
        write(log, table)
    assert dump(path) == before  # rolled back


@pytest.mark.parametrize("table", ["decisions", "events"])
def test_a_table_rebuilt_to_ignore_rows_fails_the_write(tmp_path: Path, table: str) -> None:
    """No trigger needed: ON CONFLICT IGNORE drops a row silently. Only checking the
    stored row catches this one."""
    path = tmp_path / "a.db"
    log = filled(path, 1)
    rebuild(path, table, "TEXT NOT NULL UNIQUE ON CONFLICT IGNORE")
    write(log, table)  # the first one lands
    with pytest.raises(sqlite3.DatabaseError, match="did not land"):
        write(log, table)
    assert verify_chain(path).checked[table] == 1


@pytest.mark.parametrize("table", ["decisions", "events"])
def test_a_table_rebuilt_to_change_values_fails_the_write(tmp_path: Path, table: str) -> None:
    path = tmp_path / "a.db"
    log = filled(path, 1)
    rebuild(path, table, "INTEGER")  # turns the text '1' into the number 1
    with pytest.raises(sqlite3.DatabaseError, match="did not land"):
        if table == "decisions":
            log.record(entry().model_copy(update={"reason": "1"}))
        else:
            log.record_event(event().model_copy(update={"reason": "1"}))


@pytest.mark.parametrize("table", ["decisions", "events", "audit_anchors"])
def test_a_view_in_place_of_a_table_is_refused(tmp_path: Path, table: str) -> None:
    path = tmp_path / "a.db"
    log = filled(path, 2)
    sql(path, f"ALTER TABLE {table} RENAME TO hidden")
    sql(path, f"CREATE VIEW {table} AS SELECT * FROM hidden")  # noqa: S608
    sql(path, f"CREATE TRIGGER z INSTEAD OF INSERT ON {table} BEGIN SELECT 1; END")
    sql(path, f"CREATE TRIGGER y INSTEAD OF UPDATE ON {table} BEGIN SELECT 1; END")
    for kind in ("decisions", "events"):
        with pytest.raises(sqlite3.DatabaseError, match="unexpected"):
            write(log, kind)
    problems = verify_chain(path).problems
    assert any(p.startswith(f"unexpected view '{table}'") for p in problems)
    with pytest.raises(sqlite3.DatabaseError, match="unexpected"):
        SQLiteAuditLog(path)


def test_an_endless_view_cannot_hang_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.db"
    filled(path, 1)
    sql(path, "DROP TABLE decisions")
    sql(
        path,
        "CREATE VIEW Decisions AS WITH RECURSIVE r(id) AS "
        "(SELECT 1 UNION ALL SELECT id + 1 FROM r) SELECT id, 1 AS timestamp, 1 AS agent_id, "
        "1 AS tool, 1 AS decision, 1 AS reason, 1 AS matched_rule, 1 AS action_hash, "
        "1 AS approval_id, NULL AS prev_hash, NULL AS row_hash FROM r",
    )
    assert cli.main(["audit", "verify", "--audit-db", str(path)]) == 1
    assert "BROKEN: unexpected view 'Decisions'" in capsys.readouterr().out


@pytest.mark.parametrize("table", ["decisions", "events", "audit_anchors"])
@pytest.mark.parametrize("operation", ["INSERT", "UPDATE", "DELETE"])
def test_a_trigger_cannot_change_what_retention_does(
    tmp_path: Path, table: str, operation: str
) -> None:
    path = tmp_path / "a.db"
    clock = Clock()
    log = SQLiteAuditLog(path, retention_days=None, clock=clock)
    log.record(entry())
    log.record_event(event())
    clock.now = clock.now.replace(year=2027)
    sql(path, f"CREATE TRIGGER z BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END")
    before = dump(path)
    with pytest.raises(sqlite3.DatabaseError, match="unexpected trigger 'z'"):
        log.purge_older_than(1)
    assert dump(path) == before


@pytest.mark.parametrize(
    "statement",
    [DROP_ALLOWS, "CREATE VIEW z AS SELECT 1", "CREATE VIRTUAL TABLE z USING fts5(a)"],
)
def test_startup_verify_and_head_refuse_unexpected_objects(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], statement: str
) -> None:
    path = tmp_path / "a.db"
    filled(path, 1)
    checkpoints = tmp_path / "c.jsonl"
    assert cli.main(["audit", "head", "--audit-db", str(path)]) == 0
    checkpoints.write_text(capsys.readouterr().out)
    sql(path, statement)
    before = path.read_bytes()
    for extra in ([], ["--expect", str(checkpoints)]):
        assert cli.main(["audit", "verify", "--audit-db", str(path), *extra]) == 1
        out = capsys.readouterr().out
        assert "BROKEN: unexpected" in out
        assert "'z'" in out
        assert "decisions: 1 rows verified" in out  # the chain is still checked
    assert cli.main(["audit", "head", "--audit-db", str(path)]) == 1
    assert "unexpected" in capsys.readouterr().err
    with pytest.raises(sqlite3.DatabaseError, match="unexpected .* 'z'"):
        SQLiteAuditLog(path)
    assert path.read_bytes() == before


def test_ordinary_extra_tables_and_indexes_are_fine(tmp_path: Path) -> None:
    """They can't make a write disappear: that is checked on the row itself."""
    path = tmp_path / "a.db"
    log = filled(path, 1)
    sql(path, "CREATE TABLE z (a UNIQUE)")
    sql(path, "CREATE INDEX i ON decisions (agent_id)")
    sql(path, "CREATE UNIQUE INDEX u ON events (id)")
    sql(path, "ANALYZE")
    write(log, "decisions")
    write(log, "events")
    assert verify_chain(path).ok


def test_a_trigger_listed_as_something_else_is_found(tmp_path: Path) -> None:
    """The schema table can be edited too (PRAGMA writable_schema)."""
    path = tmp_path / "a.db"
    log = filled(path, 1)
    sql(path, DROP_ALLOWS)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA writable_schema = ON")
        conn.execute("UPDATE sqlite_master SET type = 'index' WHERE name = 'z'")
    with pytest.raises(sqlite3.DatabaseError):
        log.record(entry())
    with pytest.raises(sqlite3.DatabaseError):
        SQLiteAuditLog(path)


def test_a_hostile_name_is_shown_escaped_and_short(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    filled(path, 1)
    sql(path, f'CREATE VIEW "\x1b[2J\n‮OK{"x" * 500}" AS SELECT 1')
    [problem] = verify_chain(path).problems
    assert problem.isascii() and problem.isprintable()
    assert len(problem) < 250


def test_a_flood_of_objects_gives_a_short_report(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = filled(path, 1)
    with sqlite3.connect(path) as conn:
        for i in range(50):
            conn.execute(f"CREATE VIEW v{i} AS SELECT 1")
    assert len(verify_chain(path).problems) == 10
    with pytest.raises(sqlite3.DatabaseError, match="unexpected view 'v0'"):
        log.record(entry())


def test_a_database_warden_made_has_no_triggers_or_views(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    filled(path, 1)
    ApprovalDB(path)
    with sqlite3.connect(path) as conn:
        assert {r[0] for r in conn.execute("SELECT type FROM sqlite_master")} == {"table", "index"}
    assert verify_chain(path).ok


# --- Through the API -------------------------------------------------------------------


class Server:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.log = SQLiteAuditLog(path)
        store = ApprovalStore(db=ApprovalDB(path))
        app = create_app(BASIC_POLICY, audit_log=self.log, approvals=store, admin_key=ADMIN_KEY)
        self.client = TestClient(app, raise_server_exceptions=False)

    def ask(self, tool: str, approval_id: str | None = None) -> Any:
        body: dict[str, Any] = {"agent_id": "a", "tool": tool, "arguments": {}}
        if approval_id is not None:
            body["approval_id"] = approval_id
        return self.client.post("/v1/evaluate", json=body)

    def approve(self, approval_id: str) -> int:
        return self.client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=ADMIN,
            json=shown(self.client, approval_id, ADMIN),
        ).status_code


@pytest.fixture
def server(tmp_path: Path) -> Server:
    return Server(tmp_path / "a.db")


def test_an_allow_that_is_not_recorded_is_a_deny(server: Server) -> None:
    assert server.ask("read_file").json()["decision"] == "allow"
    sql(server.path, DROP_ALLOWS)  # while the server runs
    response = server.ask("read_file")
    assert response.status_code == 503
    assert response.json()["decision"] == "deny"
    sql(server.path, "DROP TRIGGER z")
    assert server.ask("read_file").json()["decision"] == "allow"
    assert len(server.log.recent()) == 2
    assert verify_chain(server.path).ok


def test_a_used_approval_is_restored_when_the_allow_is_not_recorded(server: Server) -> None:
    approval_id = server.ask("send_email").json()["approval_id"]
    assert server.approve(approval_id) == 200
    sql(server.path, DROP_ALLOWS)
    assert server.ask("send_email", approval_id).status_code == 503
    sql(server.path, "DROP TRIGGER z")
    assert server.ask("send_email", approval_id).json()["decision"] == "allow"
    assert server.ask("send_email", approval_id).json()["decision"] == "deny"  # single use


def test_a_human_decision_that_is_not_recorded_does_not_happen(server: Server) -> None:
    approval_id = server.ask("send_email").json()["approval_id"]
    sql(
        server.path,
        "CREATE TRIGGER z BEFORE INSERT ON events BEGIN SELECT RAISE(IGNORE); END",
    )
    assert server.approve(approval_id) == 503
    sql(server.path, "DROP TRIGGER z")
    assert server.ask("send_email", approval_id).json()["decision"] != "allow"


@pytest.mark.parametrize(
    "trigger",
    [
        # approve new requests without a human
        "AFTER INSERT ON approvals BEGIN UPDATE approvals SET status = 'approved'; END",
        # make approvals reusable
        "AFTER UPDATE ON approvals WHEN new.status = 'used' "
        "BEGIN UPDATE approvals SET status = 'approved'; END",
    ],
)
def test_a_trigger_on_approvals_never_gives_an_allow(server: Server, trigger: str) -> None:
    approval_id = server.ask("send_email").json()["approval_id"]
    assert server.approve(approval_id) == 200
    sql(server.path, "CREATE TRIGGER z " + trigger)
    assert server.ask("send_email").status_code == 503
    for _ in range(3):
        assert server.ask("send_email", approval_id).json()["decision"] == "deny"


def test_the_server_does_not_start_on_a_database_with_a_trigger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    path = tmp_path / "a.db"
    filled(path, 1)
    sql(path, DROP_ALLOWS)
    with pytest.raises(StartupError, match="unexpected trigger 'z'"):
        warden.api.main(Settings(policy=BASIC_POLICY, audit_db=path))
