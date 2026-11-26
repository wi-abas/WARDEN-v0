"""A flood of bad requests is answered (deny) but only partly recorded, with a summary."""

from pathlib import Path

from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, Clock

from warden.api import create_app
from warden.audit import SQLiteAuditLog


def setup(tmp_path: Path) -> tuple[TestClient, SQLiteAuditLog, Clock[float]]:
    log = SQLiteAuditLog(tmp_path / "a.db")
    app = create_app(BASIC_POLICY, audit_log=log, admin_key="k" * 32)
    clock = Clock(1000.0)
    app.state.warden.clock = clock
    app.state.warden.rejections_per_minute = 5
    return TestClient(app), log, clock


def test_flood_is_capped_then_summarised(tmp_path: Path) -> None:
    client, log, clock = setup(tmp_path)
    for _ in range(12):
        response = client.get("/v1/approvals")  # wrong key: 401
        assert response.json()["decision"] == "deny"  # every one is still refused
    assert len(log.recent_events(limit=100)) == 5  # only 5 recorded this minute

    clock.now += 61  # next minute: the next rejection writes a summary first
    client.get("/v1/approvals")
    events = log.recent_events(limit=100)
    assert events[1].reason == "7 more rejected requests not recorded (rate limit)"
    assert events[0].http_status == 401
    assert len(events) == 7


def test_normal_traffic_is_not_limited(tmp_path: Path) -> None:
    client, log, _ = setup(tmp_path)
    for _ in range(20):
        client.post("/v1/evaluate", json={"agent_id": "a", "tool": "read_file", "arguments": {}})
    assert len(log.recent(limit=100)) == 20  # decisions are never rate limited
    assert log.recent_events() == []


def test_a_new_window_starts_at_exactly_sixty_seconds(tmp_path: Path) -> None:
    client, log, clock = setup(tmp_path)
    for _ in range(6):
        client.get("/v1/approvals")
    clock.now += 60  # exactly one minute later: new window
    client.get("/v1/approvals")
    assert log.recent_events()[1].reason == "1 more rejected requests not recorded (rate limit)"
