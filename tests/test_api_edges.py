"""Exact limits, recorded status codes and small promises of the HTTP API (gaps found
by mutation tests)."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, shown, shown_hashes
from pydantic import ValidationError

import warden.api
from warden.api import GroupDecision, create_app
from warden.approvals import ApprovalStore, Status
from warden.audit import AuditEvent, EventKind, SQLiteAuditLog
from warden.settings import Settings

KEY = "edge-admin-key-0123456789abcdefgh"
ADMIN = {"X-Warden-Admin-Key": KEY}
JSON = {"content-type": "application/json"}


def email(n: int) -> dict[str, Any]:
    return {"agent_id": "a", "tool": "send_email", "arguments": {"to": f"p{n}@example.com"}}


def app_with(log: SQLiteAuditLog, store: ApprovalStore | None = None) -> TestClient:
    return TestClient(
        create_app(BASIC_POLICY, audit_log=log, approvals=store or ApprovalStore(), admin_key=KEY)
    )


def rejections(client: TestClient, log: SQLiteAuditLog) -> list[AuditEvent]:
    client.app.state.warden.flush_events()  # type: ignore[attr-defined]
    return [e for e in log.recent_events(1000) if e.kind is EventKind.REQUEST_REJECTED]


# --- Request body -------------------------------------------------------------------------


def body_of(size: int) -> bytes:
    raw = json.dumps(email(0)).encode()
    return raw + b" " * (size - len(raw))


def test_body_of_exactly_64_kb_is_read(tmp_path: Path) -> None:
    client = app_with(SQLiteAuditLog(tmp_path / "a.db"))
    response = client.post("/v1/evaluate", content=body_of(64 * 1024), headers=JSON)
    assert response.status_code == 200 and response.json()["decision"] == "require_approval"


def test_one_byte_over_64_kb_is_refused(tmp_path: Path) -> None:
    client = app_with(SQLiteAuditLog(tmp_path / "a.db"))
    assert (
        client.post("/v1/evaluate", content=body_of(64 * 1024 + 1), headers=JSON).status_code == 413
    )


def test_duplicate_key_rejection_is_recorded_as_422(tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = app_with(log)
    response = client.post("/v1/evaluate", content=b'{"agent_id":"a","agent_id":"b"}')
    assert response.status_code == 422
    [event] = rejections(client, log)
    assert (event.http_status, event.reason) == (422, "duplicate key in request")


def test_only_bodies_of_writes_are_checked_for_duplicate_keys(tmp_path: Path) -> None:
    client = app_with(SQLiteAuditLog(tmp_path / "a.db"))
    response = client.request("GET", "/health", content=b'{"a":1,"a":2}')
    assert response.status_code == 200


def test_sixty_rejections_per_minute_are_recorded_by_default(tmp_path: Path) -> None:
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = app_with(log)
    client.app.state.warden.clock = lambda: 1000.0  # type: ignore[attr-defined]
    for _ in range(61):
        assert client.post("/v1/evaluate", json={"tool": 1}).status_code == 422
    assert len(rejections(client, log)) == 60


# --- Rate limit header ----------------------------------------------------------------------


class _AlmostReady:
    def acquire(self, agent_id: str) -> float:
        return 0.2  # seconds until the next request is allowed


def test_retry_after_is_at_least_one_second(tmp_path: Path) -> None:
    client = app_with(SQLiteAuditLog(tmp_path / "a.db"))
    client.app.state.warden.limiter = _AlmostReady()  # type: ignore[attr-defined]
    response = client.post("/v1/evaluate", json=email(0))
    assert response.status_code == 429 and response.headers["Retry-After"] == "1"


# --- Human decisions: the audit trail matches what happened ----------------------------------


class FailsOnce(SQLiteAuditLog):
    """The first write of events fails (the decision's own audit); later ones work."""

    failed = False

    def record_events(self, events: Any) -> None:
        if not self.failed:
            self.failed = True
            raise OSError("disk full")
        super().record_events(events)


def not_applied(log: SQLiteAuditLog) -> list[AuditEvent]:
    return [e for e in log.recent_events() if e.kind is EventKind.APPROVAL_DECIDE_FAILED]


@pytest.mark.parametrize("group", [False, True])
def test_failed_audit_is_not_reported_as_not_applied(tmp_path: Path, group: bool) -> None:
    """The decision's audit write failed, so nothing was claimed: no 'NOT applied'
    follow-up event (that one is only for 'audited, then saving failed')."""
    log = FailsOnce(tmp_path / "a.db")
    store = ApprovalStore()
    client = app_with(log, store)
    approval_id = client.post("/v1/evaluate", json=email(0)).json()["approval_id"]
    if group:
        body = {"ids": [approval_id], "action_hashes": shown_hashes(store, [approval_id])}
        response = client.post(
            "/v1/approvals/decide", json={**body, "approve": True}, headers=ADMIN
        )
    else:
        response = client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=ADMIN,
            json=shown(client, approval_id, ADMIN),
        )
    assert response.status_code == 503
    assert store._items[approval_id].status is Status.PENDING
    assert not_applied(log) == []


@pytest.mark.parametrize("group", [False, True])
def test_not_applied_event_records_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, group: bool
) -> None:
    from warden.approvals import ApprovalDB

    log = SQLiteAuditLog(tmp_path / "a.db")
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db)
    client = app_with(log, store)
    approval_id = client.post("/v1/evaluate", json=email(0)).json()["approval_id"]

    def locked(approvals: object) -> None:
        raise OSError("locked")

    monkeypatch.setattr(db, "save_many", locked)
    if group:
        body = {"ids": [approval_id], "action_hashes": shown_hashes(store, [approval_id])}
        client.post("/v1/approvals/decide", json={**body, "approve": True}, headers=ADMIN)
    else:
        client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=ADMIN,
            json=shown(client, approval_id, ADMIN),
        )
    [event] = not_applied(log)
    assert event.http_status == 503


def test_group_decision_is_strict_and_frozen(tmp_path: Path) -> None:
    client = app_with(SQLiteAuditLog(tmp_path / "a.db"))
    # With hashes, only strictness can refuse these (lax: -> False).
    for approve in ("false", "no", 0):
        body = {"ids": ["a" * 32], "action_hashes": ["0" * 64], "approve": approve}
        assert client.post("/v1/approvals/decide", json=body, headers=ADMIN).status_code == 422
    decision = GroupDecision(ids=["a" * 32], approve=False)
    with pytest.raises(ValidationError):
        decision.approve = True  # type: ignore[misc]


# --- Startup --------------------------------------------------------------------------------


def test_generated_admin_key_is_256_bits(capsys: pytest.CaptureFixture[str]) -> None:
    create_app(BASIC_POLICY, audit_log=None)
    err = capsys.readouterr().err
    [key] = re.findall(r"needed to approve actions\): (\S+)", err)
    assert len(key) == 43  # token_urlsafe(32): 32 random bytes


def test_startup_says_where_the_admin_key_came_from(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    settings = Settings(
        policy=BASIC_POLICY, audit_db=tmp_path / "a.db", admin_key=None, no_auth=True
    )
    warden.api.main(settings)
    err = capsys.readouterr().err
    assert "using WARDEN_ADMIN_KEY" not in err and "needed to approve actions" in err
