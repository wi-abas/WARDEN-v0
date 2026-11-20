"""Audit log: every decision is recorded, arguments never are, failures deny."""

import sqlite3
import threading
from pathlib import Path

from fastapi.testclient import TestClient

from warden import audit
from warden.api import create_app
from warden.audit import AuditEntry, SQLiteAuditLog
from warden.fingerprint import fingerprint
from warden.models import ActionRequest, Decision
from warden.policy import DEFAULT_POLICY_PATH

CANARY = "sk-live-FAKE-123"  # fake secret used to detect leaks


def body(tool: str = "send_email", **arguments: object) -> dict:
    return {"agent_id": "agent-1", "tool": tool, "arguments": arguments or {"to": "a@b.c"}}


def make(tmp_path: Path) -> tuple[TestClient, SQLiteAuditLog]:
    log = SQLiteAuditLog(tmp_path / "audit.db")
    return TestClient(create_app(DEFAULT_POLICY_PATH, audit_log=log)), log


# --- Recording -----------------------------------------------------------------------


def test_every_decision_is_recorded(tmp_path: Path) -> None:
    client, log = make(tmp_path)
    for tool in ["read_file", "send_email", "delete_file", "unknown_tool"]:
        client.post("/v1/evaluate", json=body(tool))
    decisions = [(e.tool, e.decision) for e in reversed(log.recent())]
    assert decisions == [
        ("read_file", Decision.ALLOW),
        ("send_email", Decision.REQUIRE_APPROVAL),
        ("delete_file", Decision.DENY),
        ("unknown_tool", Decision.DENY),
    ]


def test_entry_matches_the_response(tmp_path: Path) -> None:
    client, log = make(tmp_path)
    response = client.post("/v1/evaluate", json=body()).json()
    [entry] = log.recent()
    assert entry.agent_id == "agent-1"
    assert entry.decision == response["decision"]
    assert entry.reason == response["reason"]
    assert entry.matched_rule == response["matched_rule"]
    assert entry.action_hash == response["action_hash"]
    assert entry.timestamp.endswith("+00:00")  # UTC


def test_action_hash_identifies_the_action_without_storing_it(tmp_path: Path) -> None:
    client, log = make(tmp_path)
    request = body(to="boss@example.com")
    client.post("/v1/evaluate", json=request)
    assert log.recent()[0].action_hash == fingerprint(ActionRequest.model_validate(request))


def test_recent_is_newest_first_and_limited(tmp_path: Path) -> None:
    client, log = make(tmp_path)
    for tool in ["read_file", "send_email", "delete_file"]:
        client.post("/v1/evaluate", json=body(tool))
    assert [e.tool for e in log.recent(limit=2)] == ["delete_file", "send_email"]


def test_invalid_requests_are_not_recorded(tmp_path: Path) -> None:
    # There is no valid action to record; the 422 response itself is a deny.
    client, log = make(tmp_path)
    client.post("/v1/evaluate", json={"tool": "Bad Tool!"})
    assert log.recent() == []


def test_log_survives_restart(tmp_path: Path) -> None:
    client, _ = make(tmp_path)
    client.post("/v1/evaluate", json=body())
    assert len(SQLiteAuditLog(tmp_path / "audit.db").recent()) == 1


def test_default_app_writes_to_the_default_path(tmp_path: Path) -> None:
    # conftest.py points DEFAULT_AUDIT_PATH at a temp file.
    TestClient(create_app(DEFAULT_POLICY_PATH)).post("/v1/evaluate", json=body())
    assert len(SQLiteAuditLog(audit.DEFAULT_AUDIT_PATH).recent()) == 1


def test_concurrent_writes_are_all_recorded(tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "audit.db")
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="a",
        tool="t",
        decision=Decision.ALLOW,
        reason="r",
        matched_rule=None,
        action_hash=None,
    )
    threads = [threading.Thread(target=log.record, args=(entry,)) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(log.recent(limit=100)) == 20


# --- Secrets never stored ------------------------------------------------------------


def test_arguments_are_never_stored(tmp_path: Path) -> None:
    client, _ = make(tmp_path)
    client.post("/v1/evaluate", json=body(api_key=CANARY))
    client.post("/v1/evaluate", json=body("read_file", path=CANARY))
    # Look at the raw database file, not just the parsed rows.
    raw = (tmp_path / "audit.db").read_bytes()
    assert CANARY.encode() not in raw


def test_table_has_no_arguments_column(tmp_path: Path) -> None:
    SQLiteAuditLog(tmp_path / "audit.db")
    with sqlite3.connect(tmp_path / "audit.db") as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(decisions)")}
    assert "arguments" not in columns


def test_sql_injection_in_agent_id_is_stored_as_plain_text(tmp_path: Path) -> None:
    # agent_id's pattern already blocks quotes; this checks the placeholder path too.
    client, log = make(tmp_path)
    client.post("/v1/evaluate", json={**body(), "agent_id": "x--DROP.TABLE"})
    assert log.recent()[0].agent_id == "x--DROP.TABLE"


# --- Fail closed ---------------------------------------------------------------------


class BrokenLog:
    def record(self, entry: AuditEntry) -> None:
        raise sqlite3.OperationalError(f"disk full {CANARY}")

    def recent(self, limit: int = 100) -> list[AuditEntry]:
        return []


def test_audit_failure_denies_even_an_allowed_action(caplog) -> None:
    client = TestClient(create_app(DEFAULT_POLICY_PATH, audit_log=BrokenLog()))
    response = client.post("/v1/evaluate", json=body("read_file", path="x"))
    assert response.status_code == 503
    assert response.json()["decision"] == "deny"
    assert response.json()["reason"] == "audit log unavailable"
    assert CANARY not in caplog.text  # only the error type is logged


def test_audit_db_file_deleted_while_running_still_works(tmp_path: Path) -> None:
    client, log = make(tmp_path)
    (tmp_path / "audit.db").unlink()
    # The table is gone, so the write fails, and the answer must be deny.
    response = client.post("/v1/evaluate", json=body("read_file", path="x"))
    assert response.json()["decision"] == "deny"


def test_old_database_is_upgraded_and_keeps_history(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    with sqlite3.connect(path) as conn:  # the table as the first version created it
        conn.execute(
            "CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,"
            " agent_id TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL,"
            " reason TEXT NOT NULL, matched_rule TEXT, action_hash TEXT)"
        )
        conn.execute(
            "INSERT INTO decisions (timestamp, agent_id, tool, decision, reason)"
            " VALUES ('2026-01-01T00:00:00+00:00', 'old', 'read_file', 'allow', 'old row')"
        )
    client = TestClient(create_app(DEFAULT_POLICY_PATH, audit_log=SQLiteAuditLog(path)))
    response = client.post("/v1/evaluate", json=body("read_file", path="x"))
    assert response.json()["decision"] == "allow"
    entries = SQLiteAuditLog(path).recent()
    assert [e.agent_id for e in entries] == ["agent-1", "old"]
    assert entries[1].approval_id is None
