"""Behaviours that a planted bug could break without any test noticing (found by
scripts/mutation.py during the build-session re-audit)."""

import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY
from pydantic import ValidationError

from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore, apply_approval
from warden.audit import SQLiteAuditLog
from warden.client import Answer
from warden.engine import _is_clean_url, evaluate
from warden.models import ActionRequest, Decision, EvaluationResult
from warden.policy import Policy, parse_policy
from warden.sdk import ApprovalPending, WardenClient, run_guarded

ACTION = ActionRequest(agent_id="a", tool="t", arguments={})


@pytest.mark.parametrize("decision", [Decision.DENY, Decision.ALLOW])
def test_approvals_never_touch_allow_or_deny(decision: Decision) -> None:
    store = ApprovalStore()
    result = EvaluationResult(decision=decision, reason="r", action_hash="f" * 64)
    assert apply_approval(ACTION, result, store) is result
    assert store.pending() == []  # no approval was created for it


@pytest.mark.parametrize(
    ("url", "blocked"),
    [
        ("https://evil.net/", True),  # ".evil.net" covers the bare domain too
        ("https://a.b.evil.net/x", True),
        ("https://notevil.net/", False),
        ("https://evil.net.example.com/", False),
    ],
)
def test_host_in_dot_entry_covers_the_domain_and_subdomains(url: str, blocked: bool) -> None:
    rules = parse_policy(
        json.dumps(
            {
                "rules": [
                    {"id": "ok", "tool": "fetch", "effect": "allow"},
                    {
                        "id": "no-evil",
                        "tool": "fetch",
                        "effect": "deny",
                        "when": [{"arg": "url", "op": "host_in", "value": [".evil.net"]}],
                    },
                ]
            }
        )
    ).rules
    request = ActionRequest(agent_id="a", tool="fetch", arguments={"url": url})
    assert (evaluate(request, rules).decision is Decision.DENY) is blocked


@pytest.mark.parametrize(
    ("url", "clean"),
    [
        ("http://[::1]:80/a", True),
        ("http://[::1]/a", True),
        ("http://[::1]x/a", False),
        ("http://[::1]:/a", False),
        ("http://[]/a", False),
        ("http://[::1/a", False),
    ],
)
def test_ipv6_hosts(url: str, clean: bool) -> None:
    assert _is_clean_url(url) is clean


def test_persisted_store_uses_the_wall_clock(tmp_path: Path) -> None:
    store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=100)
    store.request(ACTION, "e" * 64)
    [(approval, _)] = store.pending()
    assert abs(approval.expires_at - (time.time() + 100)) < 5
    assert ApprovalStore()._clock is time.monotonic


def test_already_decided_message(tmp_path: Path) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    client = TestClient(app)
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    approval_id = client.post("/v1/evaluate", json=body).json()["approval_id"]
    headers = {"X-Warden-Admin-Key": ADMIN_KEY}
    client.post(f"/v1/approvals/{approval_id}/deny", headers=headers)
    again = client.post(f"/v1/approvals/{approval_id}/approve", headers=headers)
    assert again.status_code == 409 and again.json() == {"error": "approval already decided"}


class Pending(WardenClient):
    def __init__(self) -> None:
        super().__init__()
        self.asked = 0

    def evaluate(self, tool: str, arguments: Any, approval_id: str | None = None) -> Answer:
        self.asked += 1
        return Answer(Decision.REQUIRE_APPROVAL, "wait", "appr-0123456789abcdef", "a" * 64)


def test_run_guarded_does_not_wait_by_default() -> None:
    client = Pending()
    started = time.monotonic()
    with pytest.raises(ApprovalPending):
        run_guarded("t", {}, lambda: None, client=client)
    assert client.asked == 2 and time.monotonic() - started < 1


@pytest.mark.parametrize(
    ("limits", "ok"),
    [
        ({"default": {"requests_per_minute": 100_000}}, True),
        ({"default": {"requests_per_minute": 100_001}}, False),
        ({"default": {"max_pending_approvals": 1000}}, True),
        ({"default": {"max_pending_approvals": 1001}}, False),
        ({"agents": {f"a{i}": {} for i in range(1000)}}, True),
        ({"agents": {f"a{i}": {} for i in range(1001)}}, False),
    ],
)
def test_limit_bounds(limits: dict[str, Any], ok: bool) -> None:
    raw = json.dumps({"rules": [], "limits": limits})
    if ok:
        Policy.model_validate_json(raw)
    else:
        with pytest.raises(ValidationError):
            Policy.model_validate_json(raw)
