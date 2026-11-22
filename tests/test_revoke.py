"""A human can revoke an approval before the agent uses it."""

from pathlib import Path

from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app
from warden.audit import EventKind, SQLiteAuditLog

KEY = "k" * 32
ADMIN = {"X-Warden-Admin-Key": KEY}
EMAIL = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x@y.z"}}


def setup(tmp_path: Path) -> tuple[TestClient, SQLiteAuditLog, str]:
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, admin_key=KEY))
    approval_id: str = client.post("/v1/evaluate", json=EMAIL).json()["approval_id"]
    return client, log, approval_id


def test_revoke_before_use(tmp_path: Path) -> None:
    client, log, approval_id = setup(tmp_path)
    assert client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN).status_code == 200
    revoked = client.post(f"/v1/approvals/{approval_id}/deny", headers=ADMIN)
    assert revoked.json()["status"] == "denied"
    retry = client.post("/v1/evaluate", json={**EMAIL, "approval_id": approval_id}).json()
    assert (retry["decision"], retry["reason"]) == ("deny", "denied by a human")
    event = log.recent_events()[0]
    assert (event.kind, event.reason) == (EventKind.APPROVAL_DENIED, "approval revoked by admin")


def test_cannot_revoke_after_use(tmp_path: Path) -> None:
    client, _, approval_id = setup(tmp_path)
    client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN)
    client.post("/v1/evaluate", json={**EMAIL, "approval_id": approval_id})  # used
    assert client.post(f"/v1/approvals/{approval_id}/deny", headers=ADMIN).status_code == 409


def test_cannot_re_approve_or_approve_twice(tmp_path: Path) -> None:
    client, _, approval_id = setup(tmp_path)
    client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN)
    assert client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN).status_code == 409
    client.post(f"/v1/approvals/{approval_id}/deny", headers=ADMIN)
    assert client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN).status_code == 409
    assert client.post(f"/v1/approvals/{approval_id}/deny", headers=ADMIN).status_code == 409
