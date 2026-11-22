"""Approving needs proof the human looked: the action_hash they were shown.

Required for group approvals; optional (but checked when sent) for single ones, which
keep working without it for existing clients."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server, shown_hashes

from warden import approvals_cli
from warden.api import create_app
from warden.approvals import ApprovalStore, DecideError, GroupDecideError, GroupReason, Status
from warden.audit import EventKind, SQLiteAuditLog
from warden.cli import main
from warden.models import ActionRequest

KEY = "seen-admin-key-0123456789abcdefgh"
ADMIN = {"X-Warden-Admin-Key": KEY}
MISMATCH = "action_hash doesn't match this approval (list the approvals again)"


@pytest.fixture
def store() -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900)


@pytest.fixture
def log(tmp_path: Path) -> SQLiteAuditLog:
    return SQLiteAuditLog(tmp_path / "a.db")


@pytest.fixture
def client(store: ApprovalStore, log: SQLiteAuditLog) -> TestClient:
    return TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))


def queue(client: TestClient, n: int) -> list[str]:
    return [
        client.post(
            "/v1/evaluate",
            json={"agent_id": "a", "tool": "send_email", "arguments": {"to": f"p{i}@x.com"}},
        ).json()["approval_id"]
        for i in range(n)
    ]


def pending(store: ApprovalStore, ids: list[str]) -> bool:
    return all(store._items[i].status is Status.PENDING for i in ids)


# --- Group ----------------------------------------------------------------------------


def test_group_approve_needs_hashes(client: TestClient, store: ApprovalStore) -> None:
    ids = queue(client, 2)
    response = client.post(
        "/v1/approvals/decide", json={"ids": ids, "approve": True}, headers=ADMIN
    )
    assert response.status_code == 422 and pending(store, ids)


def test_group_reject_without_hashes_works(client: TestClient, store: ApprovalStore) -> None:
    ids = queue(client, 2)
    response = client.post(
        "/v1/approvals/decide", json={"ids": ids, "approve": False}, headers=ADMIN
    )
    assert response.status_code == 200
    assert all(store._items[i].status is Status.DENIED for i in ids)


def test_swapped_hashes_change_nothing(
    client: TestClient, store: ApprovalStore, log: SQLiteAuditLog
) -> None:
    """The human looked at a different list (or someone pasted ids with the wrong
    hashes): every id must come with ITS hash."""
    ids = queue(client, 3)
    hashes = shown_hashes(store, ids)
    swapped = [hashes[1], hashes[0], hashes[2]]
    response = client.post(
        "/v1/approvals/decide",
        json={"ids": ids, "action_hashes": swapped, "approve": True},
        headers=ADMIN,
    )
    assert response.status_code == 409
    assert response.json()["failed"] == [
        {"id": ids[0], "reason": MISMATCH},
        {"id": ids[1], "reason": MISMATCH},
    ]
    assert pending(store, ids)
    assert not [e for e in log.recent_events() if e.kind is EventKind.APPROVAL_APPROVED]


def test_wrong_hash_on_reject_also_refused(client: TestClient, store: ApprovalStore) -> None:
    ids = queue(client, 1)
    response = client.post(
        "/v1/approvals/decide",
        json={"ids": ids, "action_hashes": ["0" * 64], "approve": False},
        headers=ADMIN,
    )
    assert response.status_code == 409 and pending(store, ids)


@pytest.mark.parametrize(
    "hashes",
    [
        [],  # fewer than ids
        ["0" * 64, "0" * 64, "0" * 64],  # more than ids
        ["0" * 63, "0" * 64],
        ["A" * 64, "0" * 64],  # upper case: not how Warden writes them
        ["0" * 63 + "٠", "0" * 64],  # Arabic-Indic digit zero
        "0" * 64,
        None,
    ],
)
def test_malformed_hashes(client: TestClient, store: ApprovalStore, hashes: Any) -> None:
    ids = queue(client, 2)
    response = client.post(
        "/v1/approvals/decide",
        json={"ids": ids, "action_hashes": hashes, "approve": True},
        headers=ADMIN,
    )
    assert response.status_code == 422 and pending(store, ids)
    assert "0" * 63 not in response.text


def test_store_compares_hashes_safely() -> None:
    store = ApprovalStore(ttl_seconds=900)
    action = ActionRequest(agent_id="a", tool="t", arguments={})
    approval_id = store.request(action, "e" * 64)
    assert approval_id is not None
    with pytest.raises(ValueError, match="one action_hash per id"):
        store.decide_group([approval_id], True, expected_hashes=[])
    with pytest.raises(GroupDecideError) as caught:  # non-ASCII: a "no", not a TypeError
        store.decide_group([approval_id], True, expected_hashes=["é" * 64])
    assert caught.value.failed == [(approval_id, GroupReason.HASH_MISMATCH)]
    with pytest.raises(DecideError) as single:
        store.decide(approval_id, True, expected_hash="é" * 64)
    assert single.value.hash_mismatch
    assert store.decide(approval_id, True, expected_hash="e" * 64) is Status.APPROVED


# --- Single ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_single_with_the_right_hash(client: TestClient, store: ApprovalStore, action: str) -> None:
    [approval_id] = queue(client, 1)
    body = {"action_hash": store._items[approval_id].action_hash}
    response = client.post(f"/v1/approvals/{approval_id}/{action}", json=body, headers=ADMIN)
    assert response.status_code == 200


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_single_with_a_wrong_hash(
    client: TestClient, store: ApprovalStore, log: SQLiteAuditLog, action: str
) -> None:
    [approval_id] = queue(client, 1)
    response = client.post(
        f"/v1/approvals/{approval_id}/{action}", json={"action_hash": "0" * 64}, headers=ADMIN
    )
    assert response.status_code == 409 and response.json() == {"error": MISMATCH}
    assert pending(store, [approval_id])
    [failed] = [e for e in log.recent_events() if e.kind is EventKind.APPROVAL_DECIDE_FAILED]
    assert failed.reason == MISMATCH and failed.approval_id == approval_id


def test_single_without_a_body_still_works(client: TestClient, store: ApprovalStore) -> None:
    [approval_id] = queue(client, 1)
    assert client.post(f"/v1/approvals/{approval_id}/approve", headers=ADMIN).status_code == 200


@pytest.mark.parametrize(
    "body",
    [{"action_hash": "0" * 64, "force": True}, {"action_hash": 1}, {"hash": "0" * 64}, []],
)
def test_single_malformed_body(client: TestClient, store: ApprovalStore, body: Any) -> None:
    [approval_id] = queue(client, 1)
    response = client.post(f"/v1/approvals/{approval_id}/approve", json=body, headers=ADMIN)
    assert response.status_code == 422 and pending(store, [approval_id])


# --- CLI ------------------------------------------------------------------------------


def test_cli_sends_the_hashes_it_showed(
    client: TestClient,
    store: ApprovalStore,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """If what the CLI was shown doesn't match the approvals (here: a tampered list),
    Warden refuses the decision."""
    ids = queue(client, 2)
    real_call = approvals_cli._call

    def tampered(url: str, key: str, method: str, path: str, body: Any = None) -> Any:
        status, data = real_call(url, key, method, path, body)
        if method == "GET":
            data[0]["action_hash"] = "f" * 64
        return status, data

    monkeypatch.setattr(approvals_cli, "_call", tampered)
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    with live_server(client.app) as url:  # type: ignore[arg-type]
        assert main(["approvals", "approve", *ids, "--yes", "--warden-url", url]) == 1
    assert MISMATCH in capsys.readouterr().err
    assert pending(store, ids)
