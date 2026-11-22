"""Only requests addressed to this machine are answered (blocks DNS rebinding)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import _host_name, create_app
from warden.audit import EventKind, SQLiteAuditLog

BODY = {"agent_id": "a", "tool": "read_file", "arguments": {}}


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "127.0.0.1:8000", "localhost:9000", "LOCALHOST", "[::1]:8000"]
)
def test_local_hosts_are_answered(host: str) -> None:
    client = TestClient(create_app(BASIC_POLICY))
    response = client.post("/v1/evaluate", json=BODY, headers={"host": host})
    assert response.json()["decision"] == "allow"


@pytest.mark.parametrize(
    "host", ["evil.example.com", "evil.example.com:8000", "127.0.0.1.evil.com", "", "[::1"]
)
def test_foreign_hosts_are_refused_and_recorded(host: str, tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log))
    response = client.post("/v1/evaluate", json=BODY, headers={"host": host})
    assert response.status_code == 400
    assert response.json() == {
        "decision": "deny",
        "reason": "host not allowed",
        "matched_rule": None,
        "action_hash": None,
        "approval_id": None,
    }
    [event] = log.recent_events()
    assert (event.kind, event.http_status) == (EventKind.REQUEST_REJECTED, 400)
    assert log.recent() == []  # never reached the engine


def test_host_name_parsing() -> None:
    assert _host_name(b"127.0.0.1:8000") == "127.0.0.1"
    assert _host_name(b"[::1]:80") == "::1"
    assert _host_name(b"Example.COM") == "example.com"
