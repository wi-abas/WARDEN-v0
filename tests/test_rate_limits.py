"""Per-agent rate limits and pending-approval quotas: deterministic and race-free."""

import json
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY
from pydantic import ValidationError

from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.approvals import ApprovalStore, PendingQuotaExceeded
from warden.audit import SQLiteAuditLog
from warden.limits import (
    DEFAULT_MAX_PENDING_APPROVALS,
    DEFAULT_REQUESTS_PER_MINUTE,
    Limits,
    RateLimiter,
)
from warden.models import ActionRequest
from warden.policy import Policy


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def limits(**data: Any) -> Limits:
    return Limits.model_validate(data)


# --- Resolving limits -----------------------------------------------------------------


def test_agent_value_then_default_then_builtin() -> None:
    lim = limits(
        default={"requests_per_minute": 100},
        agents={"slow": {"requests_per_minute": 5, "max_pending_approvals": 0}},
    )
    assert lim.requests_per_minute("slow") == 5
    assert lim.requests_per_minute("other") == 100
    assert lim.max_pending_approvals("slow") == 0  # 0 is a real value, not "unset"
    assert lim.max_pending_approvals("other") == DEFAULT_MAX_PENDING_APPROVALS
    assert Limits().requests_per_minute("x") == DEFAULT_REQUESTS_PER_MINUTE
    assert limits(default={"max_pending_approvals": 3}).max_pending_approvals("x") == 3


@pytest.mark.parametrize(
    "bad",
    [
        {"default": {"requests_per_minute": 0}},
        {"default": {"requests_per_minute": "10"}},
        {"default": {"max_pending_approvals": -1}},
        {"default": {"rpm": 10}},
        {"agents": {"bad id": {}}},
        {"extra": 1},
    ],
)
def test_invalid_limits_fail_to_load(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate_json(json.dumps({"rules": [], "limits": bad}))


# --- Token bucket ---------------------------------------------------------------------


def test_bucket_allows_a_burst_then_refills() -> None:
    clock = Clock()
    limiter = RateLimiter(limits(default={"requests_per_minute": 3}), clock=clock)
    assert [limiter.acquire("a") for _ in range(3)] == [0, 0, 0]
    assert limiter.acquire("a") == pytest.approx(20.0)  # one token every 20 s
    clock.now += 10
    assert limiter.acquire("a") == pytest.approx(10.0)
    clock.now += 10
    assert limiter.acquire("a") == 0
    assert limiter.acquire("b") == 0  # other agents have their own bucket


def test_bucket_never_exceeds_capacity_and_ignores_clock_going_back() -> None:
    clock = Clock()
    limiter = RateLimiter(limits(default={"requests_per_minute": 2}), clock=clock)
    clock.now += 10_000  # a long idle time doesn't bank more than the capacity
    assert [limiter.acquire("a") for _ in range(3)][2] > 0
    clock.now -= 50  # a clock that goes backwards gives nothing extra
    assert limiter.acquire("a") > 0


def test_too_many_agents_drops_idle_ones_then_fails_closed() -> None:
    clock = Clock()
    limiter = RateLimiter(limits(default={"requests_per_minute": 1}), clock=clock, max_agents=2)
    assert limiter.acquire("a") == 0 and limiter.acquire("b") == 0
    assert limiter.acquire("c") == 60.0  # both still active: refuse a third
    clock.now += 60  # a and b refilled: they're idle and can be forgotten
    assert limiter.acquire("c") == 0


def test_concurrent_requests_never_exceed_the_limit() -> None:
    limiter = RateLimiter(limits(default={"requests_per_minute": 50}), clock=lambda: 0.0)
    allowed: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(20):
            if limiter.acquire("a") == 0:
                with lock:
                    allowed.append(1)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == 50


# --- Pending approval quota -----------------------------------------------------------


def action(agent: str, n: int) -> ActionRequest:
    return ActionRequest(agent_id=agent, tool="send", arguments={"n": n})


def test_quota_counts_pending_per_agent_only() -> None:
    store = ApprovalStore()
    for n in range(2):
        assert store.request(action("a", n), f"{n:064x}", agent_limit=2)
    # Asking again for the SAME action reuses its approval: not a new one.
    assert store.request(action("a", 0), f"{0:064x}", agent_limit=2)
    with pytest.raises(PendingQuotaExceeded):
        store.request(action("a", 9), f"{9:064x}", agent_limit=2)
    assert store.request(action("b", 9), f"{99:064x}", agent_limit=2)


def test_quota_holds_under_a_race() -> None:
    store = ApprovalStore()
    created: list[str] = []
    refused: list[int] = []
    lock = threading.Lock()

    def worker(start: int) -> None:
        for n in range(start, start + 20):
            try:
                approval = store.request(action("a", n), f"{n:064x}", agent_limit=7)
            except PendingQuotaExceeded:
                with lock:
                    refused.append(n)
                continue
            assert approval is not None
            with lock:
                created.append(approval)

    threads = [threading.Thread(target=worker, args=(i * 100,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(created) == 7 and len(refused) == 160 - 7
    assert len(store.pending()) == 7


# --- Through the API ------------------------------------------------------------------


def make_client(tmp_path: Path, limits_section: dict[str, Any], **kwargs: Any) -> TestClient:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [
                    {"id": "read", "tool": "read_file", "effect": "allow"},
                    {"id": "send", "tool": "send_email", "effect": "require_approval"},
                ],
                "limits": limits_section,
            }
        )
    )
    app = create_app(
        policy, audit_log=SQLiteAuditLog(tmp_path / "audit.db"), admin_key=ADMIN_KEY, **kwargs
    )
    return TestClient(app)


def read(agent: str) -> dict[str, Any]:
    return {"agent_id": agent, "tool": "read_file", "arguments": {"path": "/a"}}


def test_over_the_limit_is_429_deny(tmp_path: Path) -> None:
    client = make_client(tmp_path, {"agents": {"noisy": {"requests_per_minute": 2}}})
    assert [client.post("/v1/evaluate", json=read("noisy")).status_code for _ in range(2)] == [
        200,
        200,
    ]
    response = client.post("/v1/evaluate", json=read("noisy"))
    assert response.status_code == 429
    assert response.json() == {
        "decision": "deny",
        "reason": "rate limit exceeded",
        "matched_rule": None,
        "action_hash": None,
        "approval_id": None,
    }
    assert response.headers["Retry-After"] == "30"
    assert client.post("/v1/evaluate", json=read("quiet")).status_code == 200
    warden = client.app.state.warden  # type: ignore[attr-defined]
    assert warden.audit_log.recent_events()[0].http_status == 429


def test_with_tokens_the_limit_follows_the_token(tmp_path: Path) -> None:
    token = add_agent(tmp_path / "agents.json", "noisy")
    client = make_client(
        tmp_path,
        {"agents": {"noisy": {"requests_per_minute": 1}}},
        agents=load_agents(tmp_path / "agents.json"),
    )
    headers = {"Authorization": f"Bearer {token}"}
    body = {"tool": "read_file", "arguments": {"path": "/a"}}
    assert client.post("/v1/evaluate", json=body, headers=headers).status_code == 200
    # Claiming another agent_id doesn't give a fresh bucket: it's refused outright.
    dodge = client.post("/v1/evaluate", json={**body, "agent_id": "other"}, headers=headers)
    assert dodge.status_code == 403
    assert client.post("/v1/evaluate", json=body, headers=headers).status_code == 429


def test_pending_quota_through_the_api(tmp_path: Path) -> None:
    client = make_client(
        tmp_path,
        {
            "default": {"max_pending_approvals": 1},
            "agents": {"never": {"max_pending_approvals": 0}},
        },
    )

    def send(agent: str, to: str) -> dict[str, Any]:
        body = {"agent_id": agent, "tool": "send_email", "arguments": {"to": to}}
        answer: dict[str, Any] = client.post("/v1/evaluate", json=body).json()
        return answer

    assert send("a", "x")["decision"] == "require_approval"
    assert send("a", "x")["decision"] == "require_approval"  # same action: reused
    second = send("a", "y")
    assert second["decision"] == "deny"
    assert second["reason"] == "too many pending approvals for this agent"
    assert send("b", "y")["decision"] == "require_approval"
    assert send("never", "x")["reason"] == "too many pending approvals for this agent"
