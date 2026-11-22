"""Audit events: human decisions, failed approval attempts and rejected requests."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import MAX_BODY_BYTES, create_app
from warden.approvals import ApprovalStore
from warden.audit import AuditEvent, EventKind, SQLiteAuditLog

KEY = "test-admin-key-0123456789"
ADMIN = {"X-Warden-Admin-Key": KEY}
CANARY = "sk-live-FAKE-123"  # fake secret used to detect leaks


@pytest.fixture
def log(tmp_path: Path) -> SQLiteAuditLog:
    return SQLiteAuditLog(tmp_path / "audit.db")


@pytest.fixture
def client(log: SQLiteAuditLog) -> TestClient:
    app = create_app(BASIC_POLICY, audit_log=log, admin_key=KEY)
    return TestClient(app, raise_server_exceptions=False)


def email(approval_id: str | None = None, to: str = "boss@example.com") -> dict:
    body = {"agent_id": "agent-1", "tool": "send_email", "arguments": {"to": to}}
    if approval_id:
        body["approval_id"] = approval_id
    return body


def pending_id(client: TestClient) -> str:
    return client.post("/v1/evaluate", json=email()).json()["approval_id"]


# --- 1. Human decisions are audited --------------------------------------------------


@pytest.mark.parametrize(
    ("action", "kind"),
    [("approve", EventKind.APPROVAL_APPROVED), ("deny", EventKind.APPROVAL_DENIED)],
)
def test_human_decision_is_recorded(
    client: TestClient, log: SQLiteAuditLog, action: str, kind: EventKind
) -> None:
    approval_id = pending_id(client)
    action_hash = client.post("/v1/evaluate", json=email()).json()["action_hash"]
    client.post(f"/v1/approvals/{approval_id}/{action}", headers=ADMIN)
    [event] = log.recent_events()
    assert event.kind == kind
    assert event.approval_id == approval_id
    assert event.tool == "send_email"
    assert event.agent_id == "agent-1"
    assert event.action_hash == action_hash


class EventsBroken(SQLiteAuditLog):
    """Decisions can be written, events can't."""

    def record_event(self, event: AuditEvent) -> None:
        raise sqlite3.OperationalError("disk full")


def test_unrecorded_approval_does_not_happen(tmp_path: Path) -> None:
    store = ApprovalStore()
    app = create_app(
        BASIC_POLICY,
        audit_log=EventsBroken(tmp_path / "audit.db"),
        approvals=store,
        admin_key=KEY,
    )
    client = TestClient(app)
    approval_id = pending_id(client)

    response = client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN)
    assert response.status_code == 503
    # Still pending, and the agent can't use it.
    assert [a.approval_id for a, _ in store.pending()] == [approval_id]
    retry = client.post("/v1/evaluate", json=email(approval_id))
    assert retry.json()["decision"] == "require_approval"  # still waiting, never allow


@pytest.mark.parametrize(
    ("setup", "status", "reason"),
    [("unknown", 404, "approval not found"), ("decided", 409, "approval already decided")],
)
def test_failed_decision_is_recorded(
    client: TestClient, log: SQLiteAuditLog, setup: str, status: int, reason: str
) -> None:
    approval_id = "x" * 32
    if setup == "decided":
        approval_id = pending_id(client)
        client.post(f"/v1/approvals/{approval_id}/deny", headers=ADMIN)
    client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN)
    event = log.recent_events()[0]
    assert event.kind == EventKind.APPROVAL_DECIDE_FAILED
    assert (event.http_status, event.reason, event.approval_id) == (status, reason, approval_id)


def test_garbage_approval_id_is_not_stored_as_an_id(
    client: TestClient, log: SQLiteAuditLog
) -> None:
    client.post("/v1/approvals/<script>/approve", headers=ADMIN)
    event = log.recent_events()[0]
    assert event.approval_id is None
    assert event.http_status == 404


# --- 2. Failed approval attempts keep the tried approval_id --------------------------


def test_tried_approval_id_is_recorded_on_failure(client: TestClient, log: SQLiteAuditLog) -> None:
    approval_id = pending_id(client)  # never approved
    client.post("/v1/evaluate", json=email(approval_id, to="attacker@example.com"))
    entry = log.recent()[0]
    assert entry.decision == "deny"
    assert entry.approval_id == approval_id


def test_modified_action_attempt_keeps_the_approval_id(
    client: TestClient, log: SQLiteAuditLog
) -> None:
    approval_id = pending_id(client)
    client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN)
    client.post("/v1/evaluate", json=email(approval_id, to="attacker@example.com"))
    entry = log.recent()[0]
    assert (entry.decision, entry.approval_id) == ("deny", approval_id)


# --- 3. Rejected requests are recorded -----------------------------------------------


def test_wrong_admin_key_is_recorded(client: TestClient, log: SQLiteAuditLog) -> None:
    client.get("/v1/approvals", headers={"X-Warden-Admin-Key": "guess"})
    [event] = log.recent_events()
    assert (event.kind, event.http_status, event.method, event.path) == (
        EventKind.REQUEST_REJECTED,
        401,
        "GET",
        "/v1/approvals",
    )


def test_invalid_request_is_recorded_without_its_body(
    client: TestClient, log: SQLiteAuditLog, tmp_path: Path
) -> None:
    client.post("/v1/evaluate", json={"tool": "Bad Tool!", "arguments": {"key": CANARY}})
    [event] = log.recent_events()
    assert (event.http_status, event.reason) == (422, "invalid request")
    assert CANARY.encode() not in (tmp_path / "audit.db").read_bytes()


def test_oversized_request_is_recorded(client: TestClient, log: SQLiteAuditLog) -> None:
    client.post(
        "/v1/evaluate",
        content=b"x" * (MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    [event] = log.recent_events()
    assert (event.http_status, event.reason) == (413, "request too large")


def test_chunked_request_is_recorded(client: TestClient, log: SQLiteAuditLog) -> None:
    def chunks():
        yield b"{}"

    client.post("/v1/evaluate", content=chunks(), headers={"content-type": "application/json"})
    [event] = log.recent_events()
    assert event.http_status == 411


def test_query_string_is_not_stored(client: TestClient, log: SQLiteAuditLog) -> None:
    client.get(f"/v1/approvals?token={CANARY}", headers={"X-Warden-Admin-Key": "guess"})
    assert log.recent_events()[0].path == "/v1/approvals"


def test_long_path_is_cut(client: TestClient, log: SQLiteAuditLog) -> None:
    client.post("/v1/approvals/" + "a" * 5000 + "/approve")
    assert len(log.recent_events()[0].path or "") == 200


def test_events_still_recorded_when_decision_writes_fail(tmp_path: Path) -> None:
    class Exploding(SQLiteAuditLog):
        def record(self, entry: object) -> None:
            raise RuntimeError("boom")

    log = Exploding(tmp_path / "audit.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, admin_key=KEY))
    # A failed decision write is handled (503), so check the event log stayed usable.
    assert client.post("/v1/evaluate", json=email()).status_code == 503
    client.get("/v1/approvals")  # 401
    assert log.recent_events()[0].http_status == 401


def test_rejection_still_denied_when_event_log_is_broken(tmp_path: Path) -> None:
    client = TestClient(
        create_app(BASIC_POLICY, audit_log=EventsBroken(tmp_path / "a.db"), admin_key=KEY)
    )
    response = client.get("/v1/approvals")
    assert response.status_code == 401
    assert response.json()["decision"] == "deny"


def test_successful_requests_create_no_events(client: TestClient, log: SQLiteAuditLog) -> None:
    client.post("/v1/evaluate", json={"agent_id": "a", "tool": "read_file", "arguments": {}})
    client.get("/health")
    assert log.recent_events() == []
