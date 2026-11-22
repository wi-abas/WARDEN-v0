"""Approval workflow: the happy path, and every way to abuse it."""

import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app
from warden.approvals import ApprovalStore
from warden.audit import SQLiteAuditLog

KEY = "test-admin-key-0123456789"
ADMIN = {"X-Warden-Admin-Key": KEY}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900, max_pending=5, clock=clock)


@pytest.fixture
def client(store: ApprovalStore, tmp_path: Path) -> TestClient:
    app = create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "audit.db"),
        approvals=store,
        admin_key=KEY,
    )
    return TestClient(app)


def email(to: str = "boss@example.com", approval_id: str | None = None) -> dict:
    body = {"agent_id": "agent-1", "tool": "send_email", "arguments": {"to": to}}
    if approval_id:
        body["approval_id"] = approval_id
    return body


def ask(client: TestClient, body: dict) -> dict:
    return client.post("/v1/evaluate", json=body).json()


def approve(client: TestClient, approval_id: str, action: str = "approve") -> int:
    return client.post(f"/v1/approvals/{approval_id}/{action}", headers=ADMIN).status_code


def get_approved(client: TestClient, body: dict | None = None) -> str:
    approval_id = ask(client, body or email())["approval_id"]
    assert approve(client, approval_id) == 200
    return approval_id


# --- Happy path ----------------------------------------------------------------------


def test_full_flow(client: TestClient) -> None:
    first = ask(client, email())
    assert first["decision"] == "require_approval"
    approval_id = first["approval_id"]

    pending = client.get("/v1/approvals", headers=ADMIN).json()
    assert [p["approval_id"] for p in pending] == [approval_id]
    assert pending[0]["arguments"] == {"to": "boss@example.com"}  # human sees the action
    assert pending[0]["expires_in_seconds"] == 900

    assert approve(client, approval_id) == 200
    second = ask(client, email(approval_id=approval_id))
    assert second["decision"] == "allow"
    assert second["approval_id"] == approval_id
    assert second["action_hash"] == first["action_hash"]


def test_asking_twice_reuses_the_pending_approval(client: TestClient) -> None:
    assert ask(client, email())["approval_id"] == ask(client, email())["approval_id"]


def test_human_can_deny(client: TestClient) -> None:
    approval_id = ask(client, email())["approval_id"]
    assert approve(client, approval_id, "deny") == 200
    assert ask(client, email(approval_id=approval_id))["decision"] == "deny"


def test_approved_items_leave_the_pending_list(client: TestClient) -> None:
    get_approved(client)
    assert client.get("/v1/approvals", headers=ADMIN).json() == []


def test_decisions_are_audited_with_the_approval_id(client: TestClient, tmp_path: Path) -> None:
    approval_id = get_approved(client)
    ask(client, email(approval_id=approval_id))
    entries = SQLiteAuditLog(tmp_path / "audit.db").recent()
    assert [(e.decision, e.approval_id) for e in reversed(entries)] == [
        ("require_approval", approval_id),
        ("allow", approval_id),
    ]


# --- Attacks -------------------------------------------------------------------------


def test_replay_an_approval_is_denied(client: TestClient) -> None:
    approval_id = get_approved(client)
    assert ask(client, email(approval_id=approval_id))["decision"] == "allow"
    replay = ask(client, email(approval_id=approval_id))
    assert replay["decision"] == "deny"
    assert replay["reason"] == "approval already used"


@pytest.mark.parametrize(
    "modified",
    [
        email(to="attacker@example.com"),  # different argument
        {"agent_id": "agent-2", "tool": "send_email", "arguments": {"to": "boss@example.com"}},
        {
            "agent_id": "agent-1",
            "tool": "send_email",
            "arguments": {"to": "boss@example.com", "bcc": "x@y.z"},
        },
    ],
)
def test_modified_action_after_approval_is_denied(client: TestClient, modified: dict) -> None:
    approval_id = get_approved(client)
    assert ask(client, {**modified, "approval_id": approval_id})["decision"] == "deny"
    # The failed attempt did not burn the approval: the real action still works.
    assert ask(client, email(approval_id=approval_id))["decision"] == "allow"


def test_approval_cannot_be_used_for_a_different_tool(client: TestClient) -> None:
    approval_id = get_approved(client)
    body = {"agent_id": "agent-1", "tool": "delete_file", "arguments": {"to": "boss@example.com"}}
    assert ask(client, {**body, "approval_id": approval_id})["decision"] == "deny"


def test_expired_approval_is_denied(client: TestClient, clock: FakeClock) -> None:
    approval_id = get_approved(client)
    clock.now += 901
    assert ask(client, email(approval_id=approval_id))["decision"] == "deny"


def test_expired_pending_cannot_be_approved(client: TestClient, clock: FakeClock) -> None:
    approval_id = ask(client, email())["approval_id"]
    clock.now += 901
    assert approve(client, approval_id) == 404


def test_pending_approval_means_keep_waiting_not_allow(client: TestClient) -> None:
    approval_id = ask(client, email())["approval_id"]  # pending, nobody approved
    retry = ask(client, email(approval_id=approval_id))
    assert retry["decision"] == "require_approval"
    assert retry["reason"] == "waiting for a human to approve"
    assert retry["approval_id"] == approval_id


def test_pending_approval_for_a_different_action_is_denied(client: TestClient) -> None:
    approval_id = ask(client, email())["approval_id"]
    other = ask(client, email(to="attacker@example.com", approval_id=approval_id))
    assert (other["decision"], other["reason"]) == ("deny", "approval not valid")


def test_human_no_says_so(client: TestClient) -> None:
    approval_id = ask(client, email())["approval_id"]
    approve(client, approval_id, "deny")
    retry = ask(client, email(approval_id=approval_id))
    assert (retry["decision"], retry["reason"]) == ("deny", "denied by a human")


def test_made_up_approval_id_is_denied(client: TestClient) -> None:
    assert ask(client, email(approval_id="x" * 32))["decision"] == "deny"


def test_no_double_decision(client: TestClient) -> None:
    approval_id = ask(client, email())["approval_id"]
    assert approve(client, approval_id, "deny") == 200
    assert approve(client, approval_id) == 409  # can't flip a deny into approve
    assert approve(client, approval_id, "deny") == 409


def test_approval_never_turns_deny_into_allow(client: TestClient) -> None:
    approval_id = get_approved(client)
    body = {"agent_id": "agent-1", "tool": "delete_file", "arguments": {"to": "boss@example.com"}}
    assert ask(client, {**body, "approval_id": approval_id})["decision"] == "deny"


def test_race_two_retries_only_one_wins(store: ApprovalStore, client: TestClient) -> None:
    approval_id = get_approved(client)
    action_hash = ask(client, email())["action_hash"]
    results: list[bool] = []
    barrier = threading.Barrier(20)

    def attempt() -> None:
        barrier.wait()
        results.append(store.consume(approval_id, action_hash))

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_pending_flood_is_capped(client: TestClient) -> None:
    for i in range(5):
        assert ask(client, email(to=f"u{i}@x.y"))["decision"] == "require_approval"
    flooded = ask(client, email(to="one-too-many@x.y"))
    assert flooded["decision"] == "deny"
    assert flooded["reason"] == "too many pending approvals"


# --- Admin key -----------------------------------------------------------------------


@pytest.mark.parametrize("headers", [{}, {"X-Warden-Admin-Key": "wrong"}])
def test_admin_endpoints_need_the_key(client: TestClient, headers: dict) -> None:
    approval_id = ask(client, email())["approval_id"]
    for method, url in [
        ("get", "/v1/approvals"),
        ("post", f"/v1/approvals/{approval_id}/approve"),
        ("post", f"/v1/approvals/{approval_id}/deny"),
    ]:
        response = client.request(method, url, headers=headers)
        assert response.status_code == 401
        assert response.json()["decision"] == "deny"
    # Still pending: nothing was approved without the key.
    assert ask(client, email(approval_id=approval_id))["decision"] == "require_approval"
    assert len(client.get("/v1/approvals", headers=ADMIN).json()) == 1


def test_agent_never_receives_the_admin_key(client: TestClient) -> None:
    response = client.post("/v1/evaluate", json=email())
    assert KEY not in response.text


def test_generated_admin_key_is_printed_not_logged(capsys, caplog, tmp_path: Path) -> None:
    create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"))
    printed = capsys.readouterr().err
    key = printed.split("approve actions): ")[1].strip()
    assert len(key) >= 32
    assert key not in caplog.text
