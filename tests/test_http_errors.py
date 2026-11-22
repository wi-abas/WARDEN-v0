"""Unknown URLs and wrong methods also answer with a deny body, and are recorded."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app
from warden.audit import SQLiteAuditLog


@pytest.mark.parametrize(
    ("method", "url", "status", "reason"),
    [
        ("get", "/nope", 404, "not found"),
        ("post", "/v1/evaluat", 404, "not found"),
        ("get", "/v1/evaluate", 405, "method not allowed"),
        ("delete", "/health", 405, "method not allowed"),
    ],
)
def test_http_errors_say_deny(
    method: str, url: str, status: int, reason: str, tmp_path: Path
) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log))
    response = client.request(method, url)
    assert response.status_code == status
    assert response.json()["decision"] == "deny"
    assert response.json()["reason"] == reason
    [event] = log.recent_events()
    assert (event.http_status, event.path) == (status, url)
