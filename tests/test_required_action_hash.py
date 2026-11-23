"""v0.4 (breaking): approving, rejecting a PENDING approval, and group rejects need the
action_hash the human was shown. Revoking an approved one still works without a body.
See docs/design/approval-hygiene.md."""

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import HASH_REQUIRED, HASHES_REQUIRED, create_app
from warden.approvals import ApprovalDB, ApprovalStore, DecideError, Status
from warden.audit import SQLiteAuditLog
from warden.models import ActionRequest

KEY = "hash-admin-key-0123456789abcdef"
ADMIN = {"X-Warden-Admin-Key": KEY}
MARKER = "HASHMARKER-42"  # must never be echoed back


@pytest.fixture
def store() -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900)


@pytest.fixture
def log(tmp_path: Path) -> SQLiteAuditLog:
    return SQLiteAuditLog(tmp_path / "a.db")


@pytest.fixture
def client(store: ApprovalStore, log: SQLiteAuditLog) -> TestClient:
    return TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))


def ask(client: TestClient, n: int = 0) -> tuple[str, str]:
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": f"p{n}@example.com"}}
    answer = client.post("/v1/evaluate", json=body).json()
    return answer["approval_id"], answer["action_hash"]


def post(client: TestClient, path: str, body: Any = None) -> Any:
    if body is None:
        return client.post(path, headers=ADMIN)
    return client.post(path, headers=ADMIN, json=body)


@pytest.mark.parametrize("verb", ["approve", "deny"])
@pytest.mark.parametrize("body", [None, {}])
def test_deciding_a_pending_approval_needs_the_hash(
    client: TestClient, store: ApprovalStore, log: SQLiteAuditLog, verb: str, body: Any
) -> None:
    approval_id, _ = ask(client)
    r = post(client, f"/v1/approvals/{approval_id}/{verb}", body)
    assert r.status_code == 422
    assert r.json() == {"error": HASH_REQUIRED}
    assert store._items[approval_id].status is Status.PENDING  # nothing changed
    conn = sqlite3.connect(log.path)
    reasons = [row[0] for row in conn.execute("SELECT reason FROM events")]
    assert HASH_REQUIRED in reasons  # the refused decision is audited


@pytest.mark.parametrize(
    ("verb", "status"), [("approve", Status.APPROVED), ("deny", Status.DENIED)]
)
def test_deciding_with_the_shown_hash_works(
    client: TestClient, store: ApprovalStore, verb: str, status: Status
) -> None:
    approval_id, action_hash = ask(client)
    r = post(client, f"/v1/approvals/{approval_id}/{verb}", {"action_hash": action_hash})
    assert r.status_code == 200
    assert store._items[approval_id].status is status


@pytest.mark.parametrize("verb", ["approve", "deny"])
def test_wrong_hash_is_refused(client: TestClient, store: ApprovalStore, verb: str) -> None:
    approval_id, _ = ask(client)
    r = post(client, f"/v1/approvals/{approval_id}/{verb}", {"action_hash": "0" * 64})
    assert r.status_code == 409
    assert store._items[approval_id].status is Status.PENDING


@pytest.mark.parametrize("body", [None, {}])
def test_revoking_an_approved_approval_needs_no_body(
    client: TestClient, store: ApprovalStore, body: Any
) -> None:
    approval_id, action_hash = ask(client)
    assert post(client, f"/v1/approvals/{approval_id}/approve", {"action_hash": action_hash})
    r = post(client, f"/v1/approvals/{approval_id}/deny", body)
    assert r.status_code == 200 and r.json()["status"] == "denied"
    assert store._items[approval_id].status is Status.DENIED


def test_revoke_checks_the_hash_when_sent(client: TestClient, store: ApprovalStore) -> None:
    approval_id, action_hash = ask(client)
    post(client, f"/v1/approvals/{approval_id}/approve", {"action_hash": action_hash})
    r = post(client, f"/v1/approvals/{approval_id}/deny", {"action_hash": "0" * 64})
    assert r.status_code == 409
    assert store._items[approval_id].status is Status.APPROVED
    r = post(client, f"/v1/approvals/{approval_id}/deny", {"action_hash": action_hash})
    assert r.status_code == 200


def test_unknown_id_without_hash_is_not_found(client: TestClient) -> None:
    r = post(client, "/v1/approvals/" + "a" * 32 + "/approve")
    assert r.status_code == 404


def test_refusals_never_echo_input(client: TestClient) -> None:
    approval_id, _ = ask(client)
    for body in [{"action_hash": MARKER}, {"other": MARKER}, {"action_hash": None}]:
        r = post(client, f"/v1/approvals/{approval_id}/approve", body)
        assert r.status_code == 422 and MARKER not in r.text
    r = post(client, "/v1/approvals/decide", {"ids": [approval_id], "approve": False})
    assert MARKER not in r.text and approval_id not in r.text


def test_group_reject_needs_hashes(client: TestClient, store: ApprovalStore) -> None:
    ids, hashes = zip(*(ask(client, n) for n in range(3)), strict=True)
    r = post(client, "/v1/approvals/decide", {"ids": list(ids), "approve": False})
    assert r.status_code == 422
    assert HASHES_REQUIRED in r.text
    assert all(store._items[i].status is Status.PENDING for i in ids)
    body = {"ids": list(ids), "action_hashes": list(hashes), "approve": False}
    r = post(client, "/v1/approvals/decide", body)
    assert r.status_code == 200
    assert all(store._items[i].status is Status.DENIED for i in ids)


def test_group_approve_still_needs_hashes(client: TestClient, store: ApprovalStore) -> None:
    approval_id, _ = ask(client)
    r = post(client, "/v1/approvals/decide", {"ids": [approval_id], "approve": True})
    assert r.status_code == 422 and HASHES_REQUIRED in r.text
    assert store._items[approval_id].status is Status.PENDING


def test_restarted_approval_can_be_rejected_with_its_stored_hash(tmp_path: Path) -> None:
    db = ApprovalDB(tmp_path / "approvals.db")
    first = ApprovalStore(ttl_seconds=900, db=db)
    action = ActionRequest(agent_id="a", tool="send_email", arguments={"to": "x@example.com"})
    approval_id = first.request(action, "c" * 64)
    assert approval_id is not None
    restarted = ApprovalStore(ttl_seconds=900, db=db)  # arguments are gone, the hash isn't
    client = TestClient(
        create_app(
            BASIC_POLICY,
            audit_log=SQLiteAuditLog(tmp_path / "a.db"),
            approvals=restarted,
            admin_key=KEY,
        )
    )
    assert post(client, f"/v1/approvals/{approval_id}/deny").status_code == 422
    listed = client.get("/v1/approvals", headers=ADMIN).json()
    assert listed[0]["action_hash"] == "c" * 64
    r = post(client, f"/v1/approvals/{approval_id}/deny", {"action_hash": "c" * 64})
    assert r.status_code == 200


# --- The store ---------------------------------------------------------------------------


def test_store_require_hash() -> None:
    store = ApprovalStore(ttl_seconds=900)
    action = ActionRequest(agent_id="a", tool="t", arguments={})
    approval_id = store.request(action, "d" * 64)
    assert approval_id is not None
    for approve in (True, False):
        with pytest.raises(DecideError) as caught:
            store.decide(approval_id, approve, require_hash=True)
        assert caught.value.hash_required and not caught.value.hash_mismatch
        assert str(caught.value) == "action_hash required"
    assert store._items[approval_id].status is Status.PENDING
    store.decide(approval_id, True, expected_hash="d" * 64, require_hash=True)
    # Revoking an approved approval: no hash needed.
    assert store.decide(approval_id, False, require_hash=True) is Status.DENIED
