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


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("post", "/v1/evaluate/"),
        ("get", "/v1/evaluate/"),
        ("get", "/health/"),
        ("get", "/v1/approvals/"),
        ("post", "/v1/approvals/decide/"),
        ("post", "/v1/approvals/aaaaaaaaaaaaaaaaaaaa/approve/"),
        ("post", "/v1/approvals/aaaaaaaaaaaaaaaaaaaa/deny/"),
        ("post", "/v1/approvals/aaaaaaaaaaaaaaaaaaaa/lift/"),
        ("get", "/docs/"),
        ("get", "/openapi.json/"),
    ],
)
def test_trailing_slash_is_a_plain_404_deny(method: str, url: str, tmp_path: Path) -> None:
    # Not a redirect: a 307 had an empty body (no "decision") and made clients resend
    # the arguments to wherever the Location header said.
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log), follow_redirects=False)
    response = client.request(method, url)
    assert response.status_code == 404
    assert response.json()["decision"] == "deny"
    assert response.json()["reason"] == "not found"
    [event] = log.recent_events()
    assert (event.http_status, event.path) == (404, url)
