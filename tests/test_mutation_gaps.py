"""Behaviours that a planted bug could break without any test noticing (found by
scripts/mutation.py during the build-session re-audit)."""

import dataclasses
import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, shown
from pydantic import ValidationError

from warden import client as client_module
from warden import limits as limits_module
from warden.agents import MAX_AGENTS, AgentEntry, AgentsFile
from warden.api import _display_safe, create_app
from warden.approvals import (
    ApprovalDB,
    ApprovalStore,
    GroupDecideError,
    Status,
    apply_approval,
)
from warden.approvals_cli import _ago
from warden.audit import SQLiteAuditLog
from warden.client import MAX_RESPONSE_BYTES, Answer, _retry_after, parse_answer
from warden.engine import _is_clean_url, evaluate
from warden.limits import Limits, LimitSpec
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
    client.post(
        f"/v1/approvals/{approval_id}/deny",
        headers=headers,
        json=shown(client, approval_id, headers),
    )
    again = client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers=headers,
        json=shown(client, approval_id, headers),
    )
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


# --- Models, defaults and bounds --------------------------------------------------------


def test_limits_and_agents_models_are_strict_and_frozen() -> None:
    entry = AgentEntry(id="a", token_sha256="0" * 64)
    for model, field in (
        (LimitSpec(), "requests_per_minute"),
        (Limits(), "default"),
        (entry, "id"),
        (AgentsFile(agents=(entry,)), "agents"),
    ):
        with pytest.raises(ValidationError, match="frozen"):
            setattr(model, field, None)
    with pytest.raises(ValidationError):
        LimitSpec(requests_per_minute="5")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Limits.model_validate({"default": {}, "agents": [("a", {})]})
    with pytest.raises(ValidationError):
        AgentEntry.model_validate({"id": b"a", "token_sha256": "0" * 64})
    with pytest.raises(ValidationError):
        AgentsFile.model_validate({"agents": [entry]})  # a list is not a tuple


def test_default_numbers() -> None:
    assert limits_module.DEFAULT_REQUESTS_PER_MINUTE == 1200
    assert limits_module.DEFAULT_MAX_PENDING_APPROVALS == 100
    assert limits_module.MAX_TRACKED_AGENTS == 10_000
    assert MAX_AGENTS == 1000
    assert MAX_RESPONSE_BYTES == 65_536


def test_answer_is_frozen_and_its_reason_is_cut() -> None:
    answer = parse_answer({"decision": "deny", "reason": "x" * 300})
    assert answer.reason == "x" * 200
    with pytest.raises(dataclasses.FrozenInstanceError):
        answer.decision = Decision.ALLOW  # type: ignore[misc]


def test_client_never_sends_nan() -> None:
    sent: list[object] = []
    original = client_module.open_local
    client_module.open_local = lambda *args, **kwargs: sent.append(args)
    try:
        answer = WardenClient().evaluate("t", {"x": float("nan")})
    finally:
        client_module.open_local = original
    assert answer.decision is Decision.DENY
    assert sent == []


@pytest.mark.parametrize(("header", "seconds"), [("00007", 7.0), ("000007", 1.0)])
def test_retry_after_length_limit(header: str, seconds: float) -> None:
    class Error:
        headers = {"Retry-After": header}  # noqa: RUF012

    assert _retry_after(Error()) == seconds  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("age", "text"), [(59, "59s ago"), (60, "1 min ago"), (119, "1 min ago"), (120, "2 min ago")]
)
def test_age_text(age: int, text: str) -> None:
    assert _ago(age) == text


def test_highest_bmp_character_and_the_next_one_display() -> None:
    # U+FFF8 and U+E0001 are hidden: 4 hex digits below U+10000, 8 above.
    assert _display_safe("\ufff8\U000e0001", []) == "\\ufff8\\U000e0001"


# --- Approvals --------------------------------------------------------------------------


def used_approval(store: ApprovalStore) -> str:
    approval_id = store.request(ACTION, "d" * 64)
    assert approval_id is not None
    store.decide(approval_id, approve=True)
    assert store.use(approval_id, "d" * 64) is Status.APPROVED
    return approval_id


def test_group_approve_of_a_used_approval_does_not_block_its_restore() -> None:
    store = ApprovalStore()
    approval_id = used_approval(store)
    with pytest.raises(GroupDecideError):
        store.decide_group([approval_id], approve=True)
    store.restore(approval_id)
    assert store.use(approval_id, "d" * 64) is Status.APPROVED


def test_a_rejection_at_the_same_instant_beats_a_restore() -> None:
    store = ApprovalStore(clock=lambda: 1000.0)
    first = used_approval(store)
    second = store.request(ACTION, "d" * 64)
    assert second is not None and second != first
    store.decide(second, approve=False)
    store.restore(first)
    assert store.use(first, "d" * 64) is Status.USED


def test_approval_database_is_created_private(tmp_path: Path) -> None:
    ApprovalDB(tmp_path / "new.db")
    assert (tmp_path / "new.db").stat().st_mode & 0o777 == 0o600
