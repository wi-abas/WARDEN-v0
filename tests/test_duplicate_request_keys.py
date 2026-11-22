"""Request bodies that repeat a key are refused: no parser-differential games."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app
from warden.audit import SQLiteAuditLog

KEY = "k" * 32


def client(tmp_path: Path) -> tuple[TestClient, SQLiteAuditLog]:
    log = SQLiteAuditLog(tmp_path / "a.db")
    return TestClient(create_app(BASIC_POLICY, audit_log=log, admin_key=KEY)), log


@pytest.mark.parametrize(
    "body",
    [
        '{"agent_id":"a","tool":"delete_file","tool":"read_file","arguments":{}}',
        '{"agent_id":"a","tool":"read_file","arguments":{"path":"/x","path":"/etc/passwd"}}',
        '{"agent_id":"a","tool":"read_file","arguments":{"o":{"k":1,"k":2}}}',
        '{"agent_id":"a","agent_id":"b","tool":"read_file","arguments":{}}',
    ],
)
def test_duplicate_keys_are_refused(body: str, tmp_path: Path) -> None:
    c, log = client(tmp_path)
    response = c.post("/v1/evaluate", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 422
    assert response.json()["decision"] == "deny"
    assert response.json()["reason"] == "duplicate key in request"
    assert log.recent() == []  # never reached the engine
    assert log.recent_events()[0].reason == "duplicate key in request"


def test_normal_requests_still_work(tmp_path: Path) -> None:
    c, _ = client(tmp_path)
    body = '{"agent_id":"a","tool":"read_file","arguments":{"a":{"k":1},"b":{"k":2}}}'
    response = c.post("/v1/evaluate", content=body, headers={"content-type": "application/json"})
    assert response.json()["decision"] == "allow"


def test_invalid_json_still_reported_as_invalid(tmp_path: Path) -> None:
    c, _ = client(tmp_path)
    response = c.post(
        "/v1/evaluate", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert (response.status_code, response.json()["reason"]) == (422, "invalid request")


def test_admin_posts_without_a_body_still_work(tmp_path: Path) -> None:
    c, _ = client(tmp_path)
    approval_id = c.post(
        "/v1/evaluate", json={"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    ).json()["approval_id"]
    response = c.post(f"/v1/approvals/{approval_id}/approve", headers={"X-Warden-Admin-Key": KEY})
    assert response.status_code == 200
